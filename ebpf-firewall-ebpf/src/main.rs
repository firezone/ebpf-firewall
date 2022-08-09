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
        HashMap, PerfEventArray,
    },
    programs::SkBuffContext,
};

// We need to include this otherwise ebpf complies that
// `AYA_LOG` doesn't exists. Need to debug this.
use aya_log_ebpf::info;

mod bindings;
use bindings::{ethhdr, iphdr};

use core::mem;
use ebpf_firewall_common::PacketLog;
use memoffset::offset_of;

#[map(name = "EVENTS")] //
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

// Let's support single classification for now #[map(name = "SOURCE_CLASSIFIER")]
#[map(name = "CLASSIFIER")]
static mut SOURCE_CLASSIFIER: HashMap<[u8; 4], u32> =
    HashMap::<[u8; 4], u32>::with_max_entries(1024, 0);

#[map(name = "BLOCKLIST")]
static mut BLOCKLIST: LpmTrie<[u8; 8], i32> =
    LpmTrie::<[u8; 8], i32>::with_max_entries(1024, BPF_F_NO_PREALLOC);

#[classifier(name = "ebpf_firewall")]
pub fn ebpf_firewall(ctx: SkBuffContext) -> i32 {
    match unsafe { try_ebpf_firewall(ctx) } {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

unsafe fn try_ebpf_firewall(ctx: SkBuffContext) -> Result<i32, i64> {
    let source = ctx.load(ETH_HDR_LEN + offset_of!(iphdr, saddr))?;
    let dest = ctx.load(ETH_HDR_LEN + offset_of!(iphdr, daddr))?;

    let class = source_class(source);
    let action = if block_ip(class, dest) {
        TC_ACT_SHOT
    } else {
        TC_ACT_OK
    };

    let log_entry = PacketLog {
        source,
        dest,
        action,
    };

    EVENTS.output(&ctx, &log_entry, 0);
    Ok(action)
}

fn source_class(address: [u8; 4]) -> Option<[u8; 4]> {
    // Race condition if ip changes group?
    unsafe {
        SOURCE_CLASSIFIER
            .get(&address)
            .map(|x| u32::to_be_bytes(*x))
    }
}

fn block_ip(group: Option<[u8; 4]>, address: [u8; 4]) -> bool {
    // For now let's assume things are correctly initialzed
    unsafe {
        BLOCKLIST
            .get(&Key::new(64, get_key(group, address)))
            .is_some()
    }
}

fn get_key(group: Option<[u8; 4]>, address: [u8; 4]) -> [u8; 8] {
    // TODO: MaybeUninit would make this easy
    let group = group.unwrap_or_default();
    let mut res = [0; 8];
    let (res_group, res_address) = res.split_at_mut(4);
    res_group.copy_from_slice(&group);
    res_address.copy_from_slice(&address);
    res
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
