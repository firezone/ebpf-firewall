#![cfg(any(feature = "tokio", feature = "async_std"))]

use crate::{Error, Result};
use num_traits::FromPrimitive;
use serde::Serialize;
use std::{convert::TryFrom, net::IpAddr};

// This module could be expanded to be used with `PerfEventArray`
// That way we wouldn't depend on having a tokio or async_std runtime
// to log the events and that could expand our supported platforms.
use aya::{
    maps::{
        perf::{AsyncPerfEventArray, AsyncPerfEventArrayBuffer},
        MapData,
    },
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use firewall_common::{Action, PacketLog};

#[cfg(feature = "tokio")]
use tokio::spawn;

#[cfg(feature = "async-std")]
use async_std::task::spawn;

use uuid::Uuid;

use crate::EVENT_ARRAY;

pub struct Logger {
    map_name: String,
}

impl Logger {
    fn new_with_name(map_name: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            map_name: map_name.as_ref().to_string(),
        })
    }

    pub fn new() -> Result<Self> {
        Self::new_with_name(EVENT_ARRAY)
    }

    pub fn init(&mut self, bpf: &mut Bpf) -> Result<()> {
        let map = bpf.take_map(&self.map_name).ok_or(Error::MapNotFound)?;
        let mut event_array = AsyncPerfEventArray::try_from(map)?;
        for cpu_id in online_cpus()? {
            let buf = event_array.open(cpu_id, None)?;
            spawn(log_events(buf));
        }

        Ok(())
    }
}

pub async fn log_events<T: AsMut<MapData> + AsRef<MapData>>(mut buf: AsyncPerfEventArrayBuffer<T>) {
    let mut buffers = (0..10)
        .map(|_| BytesMut::with_capacity(1024))
        .collect::<Vec<_>>();
    loop {
        // TODO: If events are lost(Events produced by ebpf overflow the internal ring)
        let events = buf.read_events(&mut buffers).await.unwrap();
        buffers[0..events.read]
            .iter_mut()
            // SAFETY: read_event makes sure buf is initialized to a Packetlog
            // Also Packetlog is Copy
            .map(|buf| unsafe { buf_to_packet(buf) })
            .for_each(|data| {
                let Ok(packet) = PacketFormatted::try_from(data) else {return;};
                let Ok(packet) = serde_json::to_string(&packet) else {return;};
                tracing::info!(target: "packet_log", "{packet}");
            });
    }
}

#[derive(Debug, Clone, Serialize)]
struct PacketFormatted {
    source_ip: IpAddr,
    destination_ip: IpAddr,
    destination_port: Option<u16>,
    source_port: Option<u16>,
    action: Action,
    protocol: u8,
    uuid: Option<uuid::Uuid>,
    timestamp: String,
}

impl TryFrom<PacketLog> for PacketFormatted {
    type Error = Error;

    fn try_from(value: PacketLog) -> Result<Self> {
        let destination_port = match value.dest_port {
            0 => None,
            x => Some(x),
        };

        let source_port = match value.src_port {
            0 => None,
            x => Some(x),
        };
        let action = Action::from_i32(value.action).ok_or(Error::LogFormatError)?;
        let timestamp =
            chrono::offset::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let uuid = if value.class == [0; 16] {
            None
        } else {
            Some(Uuid::from_u128(u128::from_le_bytes(value.class)))
        };

        let (source_ip, destination_ip) = match value.version {
            6 => (IpAddr::from(value.source), IpAddr::from(value.dest)),
            4 => (to_ip(value.source), to_ip(value.dest)),
            _ => return Err(Error::LogFormatError),
        };
        Ok(Self {
            source_ip,
            destination_ip,
            destination_port,
            source_port,
            action,
            protocol: value.proto,
            uuid,
            timestamp,
        })
    }
}

fn to_ip(ip: [u8; 16]) -> IpAddr {
    IpAddr::from([ip[0], ip[1], ip[2], ip[3]])
}

unsafe fn buf_to_packet(buf: &mut BytesMut) -> PacketLog {
    let ptr = buf.as_ptr() as *const PacketLog;
    ptr.read_unaligned()
}
