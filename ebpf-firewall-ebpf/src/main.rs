#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_bpf::{
    bindings::BPF_F_NO_PREALLOC,
    bindings::TC_ACT_OK,
    bindings::TC_ACT_SHOT,
    macros::{classifier, map},
    maps::{
        lpm_trie::{Key, LpmTrie},
        PerfEventArray,
    },
    programs::SkBuffContext,
};

use aya_log_ebpf::info;

mod bindings;
use bindings::{ethhdr, iphdr};

use core::mem;
use ebpf_firewall_common::PacketLog;
use memoffset::offset_of;

#[map(name = "EVENTS")] //
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

#[map(name = "BLOCKLIST")]
static mut BLOCKLIST: LpmTrie<[u8; 4], i32> =
    LpmTrie::<[u8; 4], i32>::with_max_entries(1024, BPF_F_NO_PREALLOC);

#[classifier(name = "ebpf_firewall")]
pub fn ebpf_firewall(ctx: SkBuffContext) -> i32 {
    match unsafe { try_ebpf_firewall(ctx) } {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

unsafe fn try_ebpf_firewall(ctx: SkBuffContext) -> Result<i32, i64> {
    let source = ctx.load(ETH_HDR_LEN + offset_of!(iphdr, saddr))?;
    //info!(&ctx, "packet recieved");

    let action = if block_ip(source) {
        TC_ACT_SHOT
    } else {
        TC_ACT_OK
    };

    let log_entry = PacketLog {
        ipv4_address: source,
        action,
    };

    EVENTS.output(&ctx, &log_entry, 0);
    //info!(&ctx, "Packet recieved!");
    Ok(action)
}

fn block_ip(address: [u8; 4]) -> bool {
    unsafe { BLOCKLIST.get(&Key::new(32, address)).is_some() }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
