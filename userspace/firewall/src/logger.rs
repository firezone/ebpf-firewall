#![cfg(any(feature = "tokio", feature = "async_std"))]

use crate::Result;
use std::ops::DerefMut;

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
use firewall_common::PacketLog;

#[cfg(feature = "tokio")]
use tokio::spawn;

#[cfg(feature = "async-std")]
use async_std::task::spawn;

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
            .for_each(|data| tracing::info!("Ingress Packet: {data}"));
    }
}

unsafe fn buf_to_packet(buf: &mut BytesMut) -> PacketLog {
    let ptr = buf.as_ptr() as *const PacketLog;
    ptr.read_unaligned()
}