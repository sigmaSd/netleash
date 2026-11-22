//! Bandito's traffic counter and limiter, attached as cgroup_skb programs to
//! the root cgroup. Every packet a local socket sends or receives passes
//! through here with the socket's cgroup id, which systemd makes one per app
//! (`app-*.scope`) or service (`*.service`).
//!
//! - `app_stats` counts bytes per cgroup.
//! - `flows` counts bytes per cgroup and remote address, IPv4 and IPv6.
//! - `cgroup_buckets` assigns a cgroup a token bucket per direction; packets
//!   over the bucket's rate are dropped. Buckets [`GLOBAL_DOWN`] and
//!   [`GLOBAL_UP`] limit every app together.
//!
//! Only traffic on the interface set in `config` is counted or limited.

#![no_std]
#![no_main]
// The BPF target has no 64-bit atomic types in core; its intrinsics compile
// to BPF's atomic instructions.
#![feature(core_intrinsics)]
#![allow(internal_features)]

use aya_ebpf::{
    EbpfContext,
    bindings::{BPF_NOEXIST, __sk_buff},
    helpers::{bpf_ktime_get_ns, generated::bpf_skb_cgroup_id},
    macros::{cgroup_skb, map},
    maps::{Array, HashMap, LruHashMap, PerCpuHashMap},
    programs::SkBuffContext,
};
use bandito_helper_common::{
    AF_INET, AF_INET6, AppCounters, Bucket, BucketKey, Config, DIR_DOWN, DIR_UP, FlowCounters,
    FlowKey, GLOBAL_DOWN, GLOBAL_UP, LOOPBACK_IFINDEX, MAX_BUCKETS,
};
use core::{
    intrinsics::{AtomicOrdering::SeqCst, atomic_cxchg, atomic_xadd},
    ptr::addr_of_mut,
};

/// Atomically add to a value in a map and return what it held before.
///
/// Sequentially consistent on purpose: LLVM's BPF backend turns a relaxed
/// add into BPF's plain `lock add`, which returns nothing, even when the old
/// value is used, so the token arithmetic would read garbage. With SeqCst it
/// emits `atomic_fetch_add`, as clang does for `__sync_fetch_and_add`. The
/// `every_atomic_add_fetches` test guards this.
#[inline(always)]
unsafe fn fetch_add<T: Copy>(value: *mut T, add: T) -> T {
    // SAFETY: the caller passes a pointer into a map value.
    unsafe { atomic_xadd::<T, T, { SeqCst }>(value, add) }
}

/// Atomically replace `old` with `new`; whether it did.
#[inline(always)]
unsafe fn compare_exchange(value: *mut u64, old: u64, new: u64) -> bool {
    // SAFETY: the caller passes a pointer into a map value.
    unsafe { atomic_cxchg::<u64, { SeqCst }, { SeqCst }>(value, old, new).1 }
}

/// Read a value other CPUs may be updating. BPF has no plain atomic load
/// before ISA v4, and an aligned 64-bit read is never torn anyway.
#[inline(always)]
unsafe fn load(value: *mut u64) -> u64 {
    // SAFETY: the caller passes an aligned pointer into a map value.
    unsafe { core::ptr::read_volatile(value) }
}

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const NS_PER_SEC: u64 = 1_000_000_000;

/// cgroup_skb return values.
const DROP: i32 = 0;
const PASS: i32 = 1;

#[map(name = "config")]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);

#[map(name = "app_stats")]
static APP_STATS: PerCpuHashMap<u64, AppCounters> = PerCpuHashMap::with_max_entries(16384, 0);

#[map(name = "flows")]
static FLOWS: LruHashMap<FlowKey, FlowCounters> = LruHashMap::with_max_entries(65536, 0);

#[map(name = "cgroup_buckets")]
static CGROUP_BUCKETS: HashMap<BucketKey, u32> = HashMap::with_max_entries(16384, 0);

#[map(name = "buckets")]
static BUCKETS: Array<Bucket> = Array::with_max_entries(MAX_BUCKETS, 0);

#[cgroup_skb(ingress)]
pub fn bandito_ingress(ctx: SkBuffContext) -> i32 {
    handle(&ctx, DIR_DOWN)
}

#[cgroup_skb(egress)]
pub fn bandito_egress(ctx: SkBuffContext) -> i32 {
    handle(&ctx, DIR_UP)
}

/// Take `len` tokens from a bucket, refilling it for the time passed.
/// Lock-free: concurrent packets may refill a little more or less than
/// exact, which only shifts the rate by a packet's worth.
#[inline(always)]
fn take(index: u32, len: u32, now: u64) -> bool {
    let Some(bucket) = BUCKETS.get_ptr_mut(index) else {
        return true;
    };
    // SAFETY: the pointer is into a map value, valid for this program run;
    // concurrent runs only touch it through atomics.
    unsafe {
        let rate = (*bucket).rate;
        if rate == 0 {
            return true;
        }
        let burst = (*bucket).burst as i64;
        let tokens = addr_of_mut!((*bucket).tokens);
        let last_ns = addr_of_mut!((*bucket).last_ns);

        let last = load(last_ns);
        if now > last && compare_exchange(last_ns, last, now) {
            let elapsed = now - last;
            let refill = if elapsed >= NS_PER_SEC {
                burst
            } else {
                (elapsed * rate / NS_PER_SEC) as i64
            };
            let filled = fetch_add(tokens, refill) + refill;
            if filled > burst {
                fetch_add(tokens, burst - filled);
            }
        }

        let len = len as i64;
        if fetch_add(tokens, -len) - len >= 0 {
            return true;
        }
        fetch_add(tokens, len);
        false
    }
}

/// The cgroup's bucket slot in one direction, if it has a limit.
#[inline(always)]
fn bucket_of(cgroup: u64, direction: u32) -> Option<u32> {
    let key = BucketKey { cgroup, direction, pad: 0 };
    // SAFETY: the value is copied out immediately.
    unsafe { CGROUP_BUCKETS.get(&key) }
        .copied()
        .filter(|index| *index < MAX_BUCKETS)
}

/// Whether a download packet fits the cgroup's bucket and the global one.
/// Incoming packets can't be delayed, only dropped; TCP then slows down.
#[inline(always)]
fn download_allowed(cgroup: u64, len: u32, now: u64) -> bool {
    if let Some(index) = bucket_of(cgroup, DIR_DOWN)
        && !take(index, len, now)
    {
        return false;
    }
    take(GLOBAL_DOWN, len, now)
}

/// How far ahead an upload packet may be scheduled before it is dropped.
/// With `fq`, TCP keeps far less than this queued. Without `fq`, packets
/// leave at once, so this is the burst a limit lets through before it
/// drops: half a second of traffic.
const HORIZON_NS: u64 = NS_PER_SEC / 2;

/// Schedule `len` bytes on a pacing bucket: returns when they may leave
/// (0 if the bucket has no limit), or None to drop them. For upload buckets,
/// `last_ns` is the time the bucket's next byte may leave.
#[inline(always)]
fn pace(index: u32, len: u32, now: u64) -> Option<u64> {
    let Some(bucket) = BUCKETS.get_ptr_mut(index) else {
        return Some(0);
    };
    // SAFETY: as in `take`: a map value, shared only through atomics.
    unsafe {
        let rate = (*bucket).rate;
        if rate == 0 {
            return Some(0);
        }
        let delta = len as u64 * NS_PER_SEC / rate;
        let next = addr_of_mut!((*bucket).last_ns);
        // An idle bucket starts from now; a busy one queues behind itself.
        let old = load(next);
        let start = if old < now && compare_exchange(next, old, now + delta) {
            now
        } else {
            fetch_add(next, delta)
        };
        if start > now + HORIZON_NS {
            fetch_add(next, delta.wrapping_neg());
            return None;
        }
        Some(start)
    }
}

/// When an upload packet may leave under its cgroup's and the global limit,
/// or None to drop it. The time goes in the packet's timestamp, which the
/// `fq` queueing discipline honors (Earliest Departure Time); without `fq`
/// the horizon still drops what is over the rate.
#[inline(always)]
fn upload_departure(cgroup: u64, len: u32, now: u64) -> Option<u64> {
    let own = match bucket_of(cgroup, DIR_UP) {
        Some(index) => pace(index, len, now)?,
        None => 0,
    };
    let global = pace(GLOBAL_UP, len, now)?;
    Some(own.max(global))
}

/// Fill in a flow's remote address and ports from the packet's headers.
#[inline(always)]
fn parse(ctx: &SkBuffContext, protocol: u16, direction: u32, key: &mut FlowKey) -> bool {
    let up = direction == DIR_UP;
    let l4 = if protocol == ETH_P_IP {
        let Ok(ip) = ctx.load::<[u8; 20]>(0) else {
            return false;
        };
        key.family = AF_INET;
        key.protocol = ip[9];
        let remote = if up { [ip[16], ip[17], ip[18], ip[19]] } else { [ip[12], ip[13], ip[14], ip[15]] };
        key.remote[0] = remote[0];
        key.remote[1] = remote[1];
        key.remote[2] = remote[2];
        key.remote[3] = remote[3];
        ((ip[0] & 0x0f) as usize) * 4
    } else if protocol == ETH_P_IPV6 {
        // Addresses at 8 (source) and 24 (destination).
        let Ok(next) = ctx.load::<u8>(6) else {
            return false;
        };
        let Ok(remote) = ctx.load::<[u8; 16]>(if up { 24 } else { 8 }) else {
            return false;
        };
        key.family = AF_INET6;
        key.protocol = next;
        key.remote = remote;
        40
    } else {
        return false;
    };

    if (key.protocol == IPPROTO_TCP || key.protocol == IPPROTO_UDP)
        && let Ok(ports) = ctx.load::<[u8; 4]>(l4)
    {
        let source = u16::from_be_bytes([ports[0], ports[1]]);
        let dest = u16::from_be_bytes([ports[2], ports[3]]);
        key.local_port = if up { source } else { dest };
        key.remote_port = if up { dest } else { source };
    }
    true
}

#[inline(always)]
fn handle(ctx: &SkBuffContext, direction: u32) -> i32 {
    let Some(config) = CONFIG.get(0) else {
        return PASS;
    };
    if config.enabled == 0 {
        return PASS;
    }
    let skb = ctx.as_ptr() as *mut __sk_buff;
    // SAFETY: the context is a valid __sk_buff for this program run.
    let (ifindex, protocol, len) = unsafe { ((*skb).ifindex, (*skb).protocol, (*skb).len) };
    if ifindex == LOOPBACK_IFINDEX || (config.ifindex != 0 && ifindex != config.ifindex) {
        return PASS;
    }
    // __sk_buff.protocol is in network byte order.
    let protocol = u16::from_be(protocol as u16);

    // SAFETY: plain helper calls on the program's own context.
    let cgroup = unsafe { bpf_skb_cgroup_id(skb) };
    let now = unsafe { bpf_ktime_get_ns() };
    if direction == DIR_UP {
        let Some(departure) = upload_departure(cgroup, len, now) else {
            return DROP;
        };
        // SAFETY: cgroup_skb egress programs may set the timestamp. Keep a
        // later one TCP's own pacing already chose.
        unsafe {
            if departure > now && departure > (*skb).tstamp {
                (*skb).tstamp = departure;
            }
        }
    } else if !download_allowed(cgroup, len, now) {
        return DROP;
    }

    let counters = match APP_STATS.get_ptr_mut(&cgroup) {
        Some(counters) => Some(counters),
        None => {
            let _ = APP_STATS.insert(&cgroup, &AppCounters::default(), BPF_NOEXIST.into());
            APP_STATS.get_ptr_mut(&cgroup)
        }
    };
    if let Some(counters) = counters {
        // SAFETY: per-CPU value: no other CPU writes this copy.
        unsafe {
            if direction == DIR_UP {
                (*counters).tx_bytes += len as u64;
                (*counters).tx_packets += 1;
            } else {
                (*counters).rx_bytes += len as u64;
                (*counters).rx_packets += 1;
            }
        }
    }

    let mut key = FlowKey { cgroup, ..FlowKey::default() };
    if parse(ctx, protocol, direction, &mut key) {
        let flow = match FLOWS.get_ptr_mut(&key) {
            Some(flow) => Some(flow),
            None => {
                let _ = FLOWS.insert(&key, &FlowCounters::default(), BPF_NOEXIST.into());
                FLOWS.get_ptr_mut(&key)
            }
        };
        if let Some(flow) = flow {
            // SAFETY: shared map value, updated only through atomics.
            unsafe {
                let bytes = if direction == DIR_UP {
                    addr_of_mut!((*flow).tx_bytes)
                } else {
                    addr_of_mut!((*flow).rx_bytes)
                };
                fetch_add(bytes, len as u64);
                (*flow).last_seen_ns = bpf_ktime_get_ns();
            }
        }
    }
    PASS
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // The verifier rejects programs that could reach this.
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
