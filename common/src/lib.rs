//! Types shared by the eBPF programs and the userspace helper: map keys and
//! values, and the constants both sides agree on. One definition, so the two
//! sides can't drift apart.

#![no_std]

/// Direction index in bucket keys.
pub const DIR_DOWN: u32 = 0;
pub const DIR_UP: u32 = 1;

/// Bucket slots 0 and 1 hold the global download and upload limits.
pub const GLOBAL_DOWN: u32 = 0;
pub const GLOBAL_UP: u32 = 1;
pub const MAX_BUCKETS: u32 = 1024;

pub const LOOPBACK_IFINDEX: u32 = 1;

/// Address families in [`FlowKey::family`].
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

/// What to count, set by userspace in the `config` map.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Config {
    /// 0: every interface but loopback.
    pub ifindex: u32,
    /// 0 until userspace has configured the maps.
    pub enabled: u32,
}

/// Bytes (IP packet lengths) and wire frames per cgroup, per CPU.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AppCounters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

/// One process's traffic in one cgroup: the process that created the socket.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Debug)]
pub struct ProcessKey {
    pub cgroup: u64,
    /// Thread group id (the PID `ps` shows), in the initial PID namespace.
    pub pid: u32,
    pub pad: u32,
}

/// A process name as the kernel keeps it: up to 15 bytes, NUL-padded.
pub type Comm = [u8; 16];

/// One remote endpoint of one cgroup.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub cgroup: u64,
    /// [`AF_INET`] or [`AF_INET6`].
    pub family: u8,
    /// IPPROTO_TCP, IPPROTO_UDP or another.
    pub protocol: u8,
    /// Host byte order.
    pub local_port: u16,
    /// Host byte order.
    pub remote_port: u16,
    pub pad: u16,
    /// IPv4 uses the first 4 bytes.
    pub remote: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FlowCounters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_seen_ns: u64,
}

/// Which bucket limits a cgroup in one direction.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct BucketKey {
    pub cgroup: u64,
    pub direction: u32,
    pub pad: u32,
}

/// A token bucket. Tokens are bytes; `rate` is bytes per second, 0 = no limit.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Bucket {
    pub tokens: i64,
    pub last_ns: u64,
    pub rate: u64,
    pub burst: u64,
}

#[cfg(feature = "user")]
mod user {
    use super::*;

    // SAFETY: plain #[repr(C)] integer structs without implicit padding.
    unsafe impl aya::Pod for Config {}
    unsafe impl aya::Pod for AppCounters {}
    unsafe impl aya::Pod for FlowKey {}
    unsafe impl aya::Pod for ProcessKey {}
    unsafe impl aya::Pod for FlowCounters {}
    unsafe impl aya::Pod for BucketKey {}
    unsafe impl aya::Pod for Bucket {}
}
