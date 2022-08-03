#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_bpf::{
    bindings::TC_ACT_OK,
    bindings::TC_ACT_SHOT,
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::SkBuffContext,
};

mod bindings;
use bindings::{ethhdr, iphdr};
use core::mem;
use ebpf_firewall_common::PacketLog;
use memoffset::offset_of;

#[map(name = "EVENTS")] //
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

#[classifier(name = "ebpf_firewall")]
pub fn ebpf_firewall(ctx: SkBuffContext) -> i32 {
    match unsafe { try_ebpf_firewall(ctx) } {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

unsafe fn try_ebpf_firewall(ctx: SkBuffContext) -> Result<i32, i64> {
    let source = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, saddr))?);

    let log_entry = PacketLog {
        ipv4_address: source,
        action: TC_ACT_OK,
    };
    EVENTS.output(&ctx, &log_entry, 0);
    Ok(TC_ACT_OK)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
