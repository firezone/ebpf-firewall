#![cfg(any(feature = "tokio", feature = "async_std"))]

use crate::{Error, Result};
use num_traits::FromPrimitive;
use serde::Serialize;
use std::{convert::TryFrom, net::IpAddr, ops::DerefMut};

// This module could be expanded to be used with `PerfEventArray`
// That way we wouldn't depend on having a tokio or async_std runtime
// to log the events and that could expand our supported platforms.
use aya::{
    maps::{
        perf::{AsyncPerfEventArray, AsyncPerfEventArrayBuffer},
        Map, MapRefMut,
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
    event_array: AsyncPerfEventArray<MapRefMut>,
}

impl Logger {
    fn new_with_name(bpf: &Bpf, map_name: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            event_array: AsyncPerfEventArray::try_from(bpf.map_mut(map_name.as_ref())?)?,
        })
    }

    pub fn new(bpf: &Bpf) -> Result<Self> {
        Self::new_with_name(bpf, EVENT_ARRAY)
    }

    pub fn init(&mut self) -> Result<()> {
        for cpu_id in online_cpus()? {
            let buf = self.event_array.open(cpu_id, None)?;
            spawn(log_events(buf));
        }

        Ok(())
    }
}

pub async fn log_events<T: DerefMut<Target = Map>>(mut buf: AsyncPerfEventArrayBuffer<T>) {
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
#[allow(dead_code)]
struct PacketFormatted {
    source_ip: IpAddr,
    destination_ip: IpAddr,
    destination_port: u16,
    source_port: u16,
    action: Action,
    protocol: u8,
    uuid: Option<uuid::Uuid>,
    timestamp: String,
}

impl TryFrom<PacketLog> for PacketFormatted {
    type Error = Error;

    fn try_from(value: PacketLog) -> Result<Self> {
        let timestamp =
            chrono::offset::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let uuid = if value.class == [0; 16] {
            None
        } else {
            Some(Uuid::from_u128(u128::from_le_bytes(value.class)))
        };
        match value.version {
            6 => Ok(Self {
                source_ip: IpAddr::from(value.source),
                destination_ip: IpAddr::from(value.dest),
                destination_port: value.dest_port,
                source_port: value.src_port,
                action: Action::from_i32(value.action).ok_or(Error::LogFormatError)?,
                protocol: value.proto,
                uuid,
                timestamp,
            }),
            4 => Ok(Self {
                source_ip: IpAddr::from([
                    value.source[0],
                    value.source[1],
                    value.source[2],
                    value.source[3],
                ]),
                destination_ip: IpAddr::from([
                    value.dest[0],
                    value.dest[1],
                    value.dest[2],
                    value.dest[3],
                ]),
                destination_port: value.dest_port,
                source_port: value.src_port,
                action: Action::from_i32(value.action).ok_or(Error::LogFormatError)?,
                protocol: value.proto,
                uuid,
                timestamp,
            }),
            _ => Err(Error::LogFormatError),
        }
    }
}

unsafe fn buf_to_packet(buf: &mut BytesMut) -> PacketLog {
    let ptr = buf.as_ptr() as *const PacketLog;
    ptr.read_unaligned()
}
