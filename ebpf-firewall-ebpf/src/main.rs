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

#[allow(clippy::all)]
mod bindings;
use bindings::iphdr;

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

macro_rules! offsets_off {
    ($parent:path, $($field:tt),+) => {
        ($(offset_of!($parent, $field)),+)
    };
}

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
        6 => process(ctx, version, &SOURCE_ID_IPV6, &ACTION_MAP_IPV6),
        4 => process(ctx, version, &SOURCE_ID_IPV4, &ACTION_MAP_IPV4),
        _ => Err(-1),
    }
}

unsafe fn process<const N: usize, const M: usize>(
    ctx: SkBuffContext,
    version: u8,
    source_map: &HashMap<[u8; N], u32>,
    action_map: &LpmTrie<[u8; M], ActionStore>,
) -> Result<i32, i64> {
    let prefix_len = match version {
        6 => 160,
        4 => 64,
        _ => unreachable!("Should only call with valid packet"),
    };

    let (source, dest, proto) = load_ntw_headers(&ctx, version)?;
    let port = get_port(&ctx, version, proto)?;
    let class = source_class(source_map, source);
    let action = get_action(class, dest, action_map, port, proto, prefix_len);
    let source = as_log_array(source);
    let dest = as_log_array(dest);
    let log_entry = PacketLog {
        source,
        dest,
        action,
        port,
        proto,
        version,
    };
    EVENTS.output(&ctx, &log_entry, 0);
    Ok(action)
}

fn load_sk_buff<T>(ctx: &SkBuffContext, offset: usize) -> Result<T, i64> {
    ctx.load::<T>(ETH_HDR_LEN + offset)
}

fn load_ntw_headers<const N: usize>(
    ctx: &SkBuffContext,
    version: u8,
) -> Result<([u8; N], [u8; N], u8), i64> {
    let (source_off, dest_off, proto_off) = match version {
        6 => offsets_off!(ipv6hdr, saddr, daddr, nexthdr),
        4 => offsets_off!(iphdr, saddr, daddr, protocol),
        _ => unreachable!("Should only call with valid packet"),
    };
    let source = load_sk_buff(ctx, source_off)?;
    let dest = load_sk_buff(ctx, dest_off)?;
    let next_header = load_sk_buff(ctx, proto_off)?;
    Ok((source, dest, next_header))
}

fn get_port(ctx: &SkBuffContext, version: u8, proto: u8) -> Result<u16, i64> {
    let ip_len = match version {
        6 => IPV6_HDR_LEN,
        4 => IP_HDR_LEN,
        _ => unreachable!("Should only call with valid packet"),
    };
    let port = match proto {
        TCP => u16::from_be(ctx.load(ETH_HDR_LEN + ip_len + offset_of!(tcphdr, dest))?),
        UDP => u16::from_be(ctx.load(ETH_HDR_LEN + ip_len + offset_of!(udphdr, dest))?),
        _ => 0,
    };

    Ok(port)
}

fn as_log_array<const N: usize>(from: [u8; N]) -> [u8; 16] {
    let mut to = [0u8; 16];
    let (to_l, _) = to.split_at_mut(N);
    to_l.copy_from_slice(&from);
    to
}

unsafe fn source_class<const N: usize>(
    source_map: &HashMap<[u8; N], u32>,
    address: [u8; N],
) -> Option<[u8; 4]> {
    // Race condition if ip changes group?
    source_map.get(&address).map(|x| u32::to_be_bytes(*x))
}

fn get_action<const N: usize, const M: usize>(
    group: Option<[u8; 4]>,
    address: [u8; N],
    action_map: &LpmTrie<[u8; M], ActionStore>,
    port: u16,
    proto: u8,
    prefix_len: u32,
) -> i32 {
    let action_store = action_map.get(&Key::new(prefix_len, get_key(group, address)));
    if let Some(action) = get_store_action(&action_store, port, proto) {
        return action;
    }

    if group.is_some() {
        let action_store = action_map.get(&Key::new(prefix_len, get_key(None, address)));
        if let Some(action) = get_store_action(&action_store, port, proto) {
            return action;
        }
    }

    DEFAULT_ACTION
}

fn get_store_action(action_store: &Option<&ActionStore>, port: u16, proto: u8) -> Option<i32> {
    action_store
        .map(|store| store.lookup(port, proto))
        .flatten()
}

fn get_key<const N: usize, const M: usize>(group: Option<[u8; 4]>, address: [u8; N]) -> [u8; M] {
    // TODO: Could use MaybeUninit
    let group = group.unwrap_or_default();
    let mut res = [0; M];
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
