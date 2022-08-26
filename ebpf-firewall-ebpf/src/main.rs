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

mod bindings;
use bindings::{__BindgenBitfieldUnit, iphdr};

use core::mem;
use ebpf_firewall_common::{ActionStore, PacketLog};
use memoffset::offset_of;

use crate::bindings::{ipv6hdr, tcphdr, udphdr};

// Note: I wish we could use const values as map names
// but alas! this is not supported yet https://github.com/rust-lang/rust/issues/52393
// As soon as it is: move map names to const in common crate and use that instead of hardcoding

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

#[map(name = "SOURCE_ID_IPV4")]
static mut SOURCE_ID_IPV4: HashMap<[u8; 4], u32> =
    HashMap::<[u8; 4], u32>::with_max_entries(1024, 0);

#[map(name = "ACTION_MAP_IPV4")]
static mut ACTION_MAP_IPV4: LpmTrie<[u8; 8], ActionStore> =
    LpmTrie::<[u8; 8], ActionStore>::with_max_entries(100_000, BPF_F_NO_PREALLOC);

#[map(name = "SOURCE_ID_IPV6")]
static mut SOURCE_ID_IPV6: HashMap<[u8; 16], u32> =
    HashMap::<[u8; 16], u32>::with_max_entries(1024, 0);

#[map(name = "ACTION_MAP_IPV6")]
static mut ACTION_MAP_IPV6: LpmTrie<[u8; 20], ActionStore> =
    LpmTrie::<[u8; 20], ActionStore>::with_max_entries(100_000, BPF_F_NO_PREALLOC);

#[classifier(name = "ebpf_firewall")]
pub fn ebpf_firewall(ctx: SkBuffContext) -> i32 {
    match unsafe { try_ebpf_firewall(ctx) } {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn version(hd: u8) -> u8 {
    (hd & 0xf0) >> 4
}

unsafe fn try_ebpf_firewall(ctx: SkBuffContext) -> Result<i32, i64> {
    // Endianess??
    let version = version(ctx.load(ETH_HDR_LEN)?);
    match version {
        4 => process_v4(ctx, version),
        6 => process_v6(ctx, version),
        _ => Err(-1),
    }
}

unsafe fn process_v6(ctx: SkBuffContext, version: u8) -> Result<i32, i64> {
    let source = ctx.load(ETH_HDR_LEN + offset_of!(ipv6hdr, saddr))?;
    let dest = ctx.load(ETH_HDR_LEN + offset_of!(ipv6hdr, daddr))?;
    let next_header = ctx.load(ETH_HDR_LEN + offset_of!(ipv6hdr, nexthdr))?;
    let port = match next_header {
        TCP => u16::from_be(ctx.load(ETH_HDR_LEN + IPV6_HDR_LEN + offset_of!(tcphdr, dest))?),
        UDP => u16::from_be(ctx.load(ETH_HDR_LEN + IPV6_HDR_LEN + offset_of!(udphdr, dest))?),
        // MORE TODOS!
        _ => 0,
    };
    let class = source_class_v6(source);
    let action = get_action_v6(class, dest, port, next_header);

    let log_entry = PacketLog {
        source,
        dest,
        action,
        port,
        proto: next_header,
        version,
    };

    EVENTS.output(&ctx, &log_entry, 0);
    Ok(action)
}

unsafe fn process_v4(ctx: SkBuffContext, version: u8) -> Result<i32, i64> {
    let source = ctx.load(ETH_HDR_LEN + offset_of!(iphdr, saddr))?;
    let dest = ctx.load(ETH_HDR_LEN + offset_of!(iphdr, daddr))?;
    let proto = ctx.load(ETH_HDR_LEN + offset_of!(iphdr, protocol))?;
    // TODO: Would endianness always work?

    let port = match proto {
        TCP => u16::from_be(ctx.load(ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest))?),
        UDP => u16::from_be(ctx.load(ETH_HDR_LEN + IP_HDR_LEN + offset_of!(udphdr, dest))?),
        // MORE TODOS!
        _ => 0,
    };

    let class = source_class(source);
    let action = get_action(class, dest, port, proto);

    let mut s = [0u8; 16];
    let (s_ip, _) = s.split_at_mut(4);
    s_ip.copy_from_slice(&source);

    let mut d = [0u8; 16];
    let (d_ip, _) = d.split_at_mut(4);
    d_ip.copy_from_slice(&dest);
    let log_entry = PacketLog {
        source: s,
        dest: d,
        action,
        port,
        proto,
        version,
    };

    EVENTS.output(&ctx, &log_entry, 0);
    Ok(action)
}

fn source_class_v6(address: [u8; 16]) -> Option<[u8; 4]> {
    // Race condition if ip changes group?
    unsafe { SOURCE_ID_IPV6.get(&address).map(|x| u32::to_be_bytes(*x)) }
}

fn source_class(address: [u8; 4]) -> Option<[u8; 4]> {
    // Race condition if ip changes group?
    unsafe { SOURCE_ID_IPV4.get(&address).map(|x| u32::to_be_bytes(*x)) }
}

fn get_action_v6(group: Option<[u8; 4]>, address: [u8; 16], port: u16, proto: u8) -> i32 {
    // SAFETY?
    let block_list = unsafe { &ACTION_MAP_IPV6 };
    // TODO: here we allocate `action_store` in the stack.
    // below we do the same. Even if we make this `mut`.
    // This limits us in the number of rules we can store for a single entry.
    // Maybe we can do something similar to what the main function does with offset_of
    let action_store = block_list.get(&Key::new(160, get_key_v6(group, address)));
    if let Some(action) = get_store_action(&action_store, port, proto) {
        match action {
            true => return TC_ACT_OK,
            false => return TC_ACT_SHOT,
        }
    }

    if group.is_some() {
        let action_store = block_list.get(&Key::new(160, get_key_v6(None, address)));
        if let Some(action) = get_store_action(&action_store, port, proto) {
            match action {
                true => return TC_ACT_OK,
                false => return TC_ACT_SHOT,
            }
        }
    }

    DEFAULT_ACTION
}

fn get_action(group: Option<[u8; 4]>, address: [u8; 4], port: u16, proto: u8) -> i32 {
    // SAFETY?
    let block_list = unsafe { &ACTION_MAP_IPV4 };
    let action_store = block_list.get(&Key::new(64, get_key(group, address)));
    if let Some(action) = get_store_action(&action_store, port, proto) {
        match action {
            true => return TC_ACT_OK,
            false => return TC_ACT_SHOT,
        }
    }

    if group.is_some() {
        let action_store = block_list.get(&Key::new(64, get_key(None, address)));
        if let Some(action) = get_store_action(&action_store, port, proto) {
            match action {
                true => return TC_ACT_OK,
                false => return TC_ACT_SHOT,
            }
        }
    }

    DEFAULT_ACTION
}

fn get_store_action(action_store: &Option<&ActionStore>, port: u16, proto: u8) -> Option<bool> {
    action_store
        .map(|store| store.lookup(port, proto))
        .flatten()
}

fn get_key_v6(group: Option<[u8; 4]>, address: [u8; 16]) -> [u8; 20] {
    // TODO: MaybeUninit would make this easy
    let group = group.unwrap_or_default();
    let mut res = [0; 20];
    let (res_group, res_address) = res.split_at_mut(4);
    res_group.copy_from_slice(&group);
    res_address.copy_from_slice(&address);
    res
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
const IPV6_HDR_LEN: usize = mem::size_of::<ipv6hdr>();
const TCP: u8 = 0x06;
const UDP: u8 = 0x11;
const DEFAULT_ACTION: i32 = TC_ACT_OK;

#[cfg(not(feature = "wireguard"))]
const ETH_HDR_LEN: usize = mem::size_of::<bindings::ethhdr>();

#[cfg(feature = "wireguard")]
const ETH_HDR_LEN: usize = 0;
