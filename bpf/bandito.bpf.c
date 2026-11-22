// SPDX-License-Identifier: GPL-2.0 OR MIT
//
// Bandito's traffic counter and limiter, attached as cgroup_skb programs to
// the root cgroup. Every packet a local socket sends or receives passes
// through here with the socket's cgroup id, which systemd makes one per app
// (app-*.scope) or service (*.service).
//
// - app_stats counts bytes per cgroup.
// - flows counts bytes per cgroup and remote address, IPv4 and IPv6.
// - cgroup_buckets assigns a cgroup a token bucket per direction; packets
//   over the bucket's rate are dropped. Bucket 0 (download) and 1 (upload)
//   limit every app together.
//
// Only traffic on the interface set in config is counted or limited.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define INLINE static inline __attribute__((always_inline))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) = (void *)2;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to,
                                  __u32 len) = (void *)26;
static __u64 (*bpf_skb_cgroup_id)(struct __sk_buff *skb) = (void *)79;

#define DIR_DOWN 0
#define DIR_UP 1
#define GLOBAL_DOWN 0
#define GLOBAL_UP 1
#define MAX_BUCKETS 1024
#define LOOPBACK_IFINDEX 1

struct config {
  __u32 ifindex; // 0: every interface but loopback
  __u32 enabled; // 0 until userspace configured the maps
};

struct app_counters {
  __u64 rx_bytes;
  __u64 tx_bytes;
  __u64 rx_packets;
  __u64 tx_packets;
};

struct flow_key {
  __u64 cgroup;
  __u8 family; // AF_INET (2) or AF_INET6 (10)
  __u8 protocol; // IPPROTO_TCP, IPPROTO_UDP or another
  __u16 local_port; // host byte order
  __u16 remote_port; // host byte order
  __u16 pad;
  __u8 remote[16]; // IPv4 uses the first 4 bytes
};

struct flow_counters {
  __u64 rx_bytes;
  __u64 tx_bytes;
  __u64 last_seen_ns;
};

struct bucket_key {
  __u64 cgroup;
  __u32 direction;
  __u32 pad;
};

// A token bucket. Tokens are bytes; rate is bytes per second, 0 = no limit.
struct bucket {
  __s64 tokens;
  __u64 last_ns;
  __u64 rate;
  __u64 burst;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct config);
} config SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 16384);
  __type(key, __u64);
  __type(value, struct app_counters);
} app_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct flow_key);
  __type(value, struct flow_counters);
} flows SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16384);
  __type(key, struct bucket_key);
  __type(value, __u32);
} cgroup_buckets SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_BUCKETS);
  __type(key, __u32);
  __type(value, struct bucket);
} buckets SEC(".maps");

// Take len tokens from a bucket, refilling it for the time passed. Lock-free:
// concurrent packets may refill a little more or less than exact, which only
// shifts the rate by a packet's worth.
INLINE int take(__u32 index, __u32 len, __u64 now) {
  struct bucket *b = bpf_map_lookup_elem(&buckets, &index);
  if (!b || b->rate == 0)
    return 1;

  __u64 last = b->last_ns;
  if (now > last &&
      __sync_val_compare_and_swap(&b->last_ns, last, now) == last) {
    __u64 elapsed = now - last;
    __u64 refill = elapsed >= 1000000000ULL
                       ? b->burst
                       : elapsed * b->rate / 1000000000ULL;
    __s64 tokens = __sync_fetch_and_add(&b->tokens, (__s64)refill) + refill;
    if (tokens > (__s64)b->burst)
      __sync_fetch_and_add(&b->tokens, (__s64)b->burst - tokens);
  }

  __s64 left = __sync_fetch_and_add(&b->tokens, -(__s64)len) - len;
  if (left >= 0)
    return 1;
  __sync_fetch_and_add(&b->tokens, (__s64)len);
  return 0;
}

// Whether the packet fits the cgroup's bucket and the global one.
INLINE int allowed(__u64 cgroup, __u32 direction, __u32 len) {
  __u64 now = bpf_ktime_get_ns();
  struct bucket_key key = {.cgroup = cgroup, .direction = direction};
  __u32 *index = bpf_map_lookup_elem(&cgroup_buckets, &key);
  if (index && *index < MAX_BUCKETS && !take(*index, len, now))
    return 0;
  return take(direction == DIR_DOWN ? GLOBAL_DOWN : GLOBAL_UP, len, now);
}

// Fill the remote address and ports of a flow from the packet's headers.
INLINE int parse(struct __sk_buff *skb, __u32 direction, struct flow_key *key) {
  __u16 ports[2] = {0, 0};
  __u32 l4 = 0;

  if (skb->protocol == __constant_htons(ETH_P_IP)) {
    struct iphdr ip;
    if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) < 0)
      return 0;
    key->family = 2;
    key->protocol = ip.protocol;
    __u32 remote = direction == DIR_UP ? ip.daddr : ip.saddr;
    __builtin_memcpy(key->remote, &remote, 4);
    l4 = ip.ihl * 4;
  } else if (skb->protocol == __constant_htons(ETH_P_IPV6)) {
    struct ipv6hdr ip6;
    if (bpf_skb_load_bytes(skb, 0, &ip6, sizeof(ip6)) < 0)
      return 0;
    key->family = 10;
    key->protocol = ip6.nexthdr;
    __builtin_memcpy(key->remote,
                     direction == DIR_UP ? &ip6.daddr : &ip6.saddr, 16);
    l4 = sizeof(ip6);
  } else {
    return 0;
  }

  if (key->protocol == IPPROTO_TCP || key->protocol == IPPROTO_UDP) {
    if (bpf_skb_load_bytes(skb, l4, ports, sizeof(ports)) == 0) {
      __u16 source = __builtin_bswap16(ports[0]);
      __u16 dest = __builtin_bswap16(ports[1]);
      key->local_port = direction == DIR_UP ? source : dest;
      key->remote_port = direction == DIR_UP ? dest : source;
    }
  }
  return 1;
}

INLINE int handle(struct __sk_buff *skb, __u32 direction) {
  __u32 zero = 0;
  struct config *cfg = bpf_map_lookup_elem(&config, &zero);
  if (!cfg || !cfg->enabled)
    return 1;
  if (skb->ifindex == LOOPBACK_IFINDEX)
    return 1;
  if (cfg->ifindex && skb->ifindex != cfg->ifindex)
    return 1;

  __u64 cgroup = bpf_skb_cgroup_id(skb);
  __u32 len = skb->len;
  if (!allowed(cgroup, direction, len))
    return 0;

  struct app_counters *counters = bpf_map_lookup_elem(&app_stats, &cgroup);
  if (!counters) {
    struct app_counters fresh = {};
    bpf_map_update_elem(&app_stats, &cgroup, &fresh, BPF_NOEXIST);
    counters = bpf_map_lookup_elem(&app_stats, &cgroup);
  }
  if (counters) {
    // Per-CPU values: no other CPU writes this copy.
    if (direction == DIR_UP) {
      counters->tx_bytes += len;
      counters->tx_packets += 1;
    } else {
      counters->rx_bytes += len;
      counters->rx_packets += 1;
    }
  }

  struct flow_key key = {.cgroup = cgroup};
  if (parse(skb, direction, &key)) {
    struct flow_counters *flow = bpf_map_lookup_elem(&flows, &key);
    if (!flow) {
      struct flow_counters fresh = {};
      bpf_map_update_elem(&flows, &key, &fresh, BPF_NOEXIST);
      flow = bpf_map_lookup_elem(&flows, &key);
    }
    if (flow) {
      if (direction == DIR_UP)
        __sync_fetch_and_add(&flow->tx_bytes, len);
      else
        __sync_fetch_and_add(&flow->rx_bytes, len);
      flow->last_seen_ns = bpf_ktime_get_ns();
    }
  }
  return 1;
}

SEC("cgroup_skb/ingress")
int bandito_ingress(struct __sk_buff *skb) { return handle(skb, DIR_DOWN); }

SEC("cgroup_skb/egress")
int bandito_egress(struct __sk_buff *skb) { return handle(skb, DIR_UP); }

char LICENSE[] SEC("license") = "Dual MIT/GPL";
