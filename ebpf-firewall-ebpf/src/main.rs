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

// Just using it to initialize log statics
use aya_log_ebpf as _;

mod bindings;
use bindings::iphdr;

use core::mem;
//use ebpf_firewall_common::{ActionStore, PacketLog};
use ebpf_firewall_common::{ActionStore, PacketLog};
use memoffset::offset_of;

use crate::bindings::{tcphdr, udphdr};

#[map(name = "EVENTS")] //
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

// Let's support single classification for now #[map(name = "SOURCE_CLASSIFIER")]
#[map(name = "CLASSIFIER")]
static mut SOURCE_CLASSIFIER: HashMap<[u8; 4], u32> =
    HashMap::<[u8; 4], u32>::with_max_entries(1024, 0);

#[map(name = "BLOCKLIST")]
static mut BLOCKLIST: LpmTrie<[u8; 8], ActionStore> =
    LpmTrie::<[u8; 8], ActionStore>::with_max_entries(100_000, BPF_F_NO_PREALLOC);

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
    let proto = ctx.load(ETH_HDR_LEN + offset_of!(iphdr, protocol))?;

    let port = match proto {
        TCP => u16::from_be(ctx.load(ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest))?),
        UDP => u16::from_be(ctx.load(ETH_HDR_LEN + IP_HDR_LEN + offset_of!(udphdr, dest))?),
        // MORE TODOS!
        _ => 0,
    };

    let class = source_class(source);
    let action = get_action(class, dest, port);

    let log_entry = PacketLog {
        source,
        dest,
        action,
        port: port as u32,
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

// Okay yeah, this is ugly, will refacto exactly how this works later
fn get_action(group: Option<[u8; 4]>, address: [u8; 4], port: u16) -> i32 {
    // For now let's assume things are correctly initialzed
    let action_store = unsafe { BLOCKLIST.get(&Key::new(64, get_key(group, address))) };
    if let Some(action_store) = action_store {
        if let Some(action) = action_store.lookup(port) {
            if action {
                TC_ACT_OK
            } else {
                TC_ACT_SHOT
            }
        } else {
            DEFAULT_ACTION
        }
    } else {
        DEFAULT_ACTION
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
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const TCP: u8 = 0x06;
const UDP: u8 = 0x11;
const DEFAULT_ACTION: i32 = TC_ACT_OK;

#[cfg(not(feature = "wireguard"))]
const ETH_HDR_LEN: usize = mem::size_of::<bindings::ethhdr>();

#[cfg(feature = "wireguard")]
const ETH_HDR_LEN: usize = 0;
