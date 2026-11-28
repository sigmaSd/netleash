//! Traffic per process: the eBPF programs count bytes per cgroup and the
//! process that created each socket; this turns those counters into rates.

use crate::protocol::{ProcessTraffic, Rates};
use netleash_common::{AppCounters, Comm, ProcessKey};
use std::collections::{HashMap, HashSet};

/// Received and sent bytes, summed over CPUs, with `header` link-layer bytes
/// added per frame as the interface counts them.
pub fn sum(values: &[AppCounters], header: u64) -> (u64, u64) {
    values.iter().fold((0, 0), |(rx, tx), v| {
        (
            rx + v.rx_bytes + v.rx_packets * header,
            tx + v.tx_bytes + v.tx_packets * header,
        )
    })
}

/// Bytes since `previous`; a counter smaller than before was evicted or
/// removed and started over.
fn delta(now: u64, previous: u64) -> u64 {
    if now >= previous { now - previous } else { now }
}

/// Rates per cgroup and PID since the previous sample, leaving out idle ones.
pub fn rates(
    now: &HashMap<ProcessKey, (u64, u64)>,
    previous: &HashMap<ProcessKey, (u64, u64)>,
    elapsed: f64,
) -> HashMap<u64, Vec<(u32, Rates)>> {
    let mut by_cgroup: HashMap<u64, Vec<(u32, Rates)>> = HashMap::new();
    for (key, (rx, tx)) in now {
        let (prev_rx, prev_tx) = previous.get(key).copied().unwrap_or((0, 0));
        let rates = Rates {
            rx: crate::per_second(delta(*rx, prev_rx), elapsed),
            tx: crate::per_second(delta(*tx, prev_tx), elapsed),
        };
        if rates.rx != 0 || rates.tx != 0 {
            by_cgroup
                .entry(key.cgroup)
                .or_default()
                .push((key.pid, rates));
        }
    }
    by_cgroup
}

/// Add a process's rates to an app's list: an app can span several cgroups,
/// and a process that moved between them has counters in each.
pub fn merge(list: &mut Vec<ProcessTraffic>, pid: u32, rates: Rates) {
    match list.iter_mut().find(|p| p.pid == pid) {
        Some(process) => {
            process.rates.rx += rates.rx;
            process.rates.tx += rates.tx;
        }
        None => list.push(ProcessTraffic {
            pid,
            name: String::new(),
            rates,
        }),
    }
}

/// Counters that didn't change since the previous sample.
pub fn idle(
    now: &HashMap<ProcessKey, (u64, u64)>,
    previous: &HashMap<ProcessKey, (u64, u64)>,
) -> Vec<ProcessKey> {
    now.iter()
        .filter(|(key, totals)| previous.get(key) == Some(totals))
        .map(|(key, _)| *key)
        .collect()
}

/// The PIDs among `idle` whose process is gone, each once.
pub fn exited(idle: &[ProcessKey], gone: impl Fn(u32) -> bool) -> HashSet<u32> {
    let pids: HashSet<u32> = idle.iter().map(|key| key.pid).collect();
    pids.into_iter().filter(|pid| gone(*pid)).collect()
}

/// A kernel process name, up to its NUL.
pub fn comm_name(comm: &Comm) -> String {
    let end = comm.iter().position(|b| *b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(cgroup: u64, pid: u32) -> ProcessKey {
        ProcessKey {
            cgroup,
            pid,
            pad: 0,
        }
    }

    #[test]
    fn sums_cpus_and_adds_link_headers() {
        let cpu = |rx, tx, frames| AppCounters {
            rx_bytes: rx,
            tx_bytes: tx,
            rx_packets: frames,
            tx_packets: frames,
        };
        assert_eq!(sum(&[cpu(1000, 100, 2), cpu(500, 0, 1)], 14), (1542, 142));
        assert_eq!(sum(&[], 14), (0, 0));
    }

    #[test]
    fn rates_per_cgroup_and_pid_skip_idle_processes() {
        let previous = HashMap::from([(key(1, 10), (1000, 100)), (key(1, 11), (50, 50))]);
        let now = HashMap::from([
            (key(1, 10), (3000, 100)),
            (key(1, 11), (50, 50)),
            (key(2, 20), (0, 400)),
        ]);
        let rates = rates(&now, &previous, 2.0);
        let one = &rates[&1];
        assert_eq!(one.len(), 1, "pid 11 was idle");
        assert_eq!(one[0].0, 10);
        assert_eq!((one[0].1.rx, one[0].1.tx), (1000, 0));
        let two = &rates[&2];
        assert_eq!((two[0].0, two[0].1.rx, two[0].1.tx), (20, 0, 200));
    }

    #[test]
    fn a_counter_that_started_over_counts_from_zero() {
        let previous = HashMap::from([(key(1, 10), (5000, 5000))]);
        let now = HashMap::from([(key(1, 10), (300, 0))]);
        let rates = rates(&now, &previous, 1.0);
        assert_eq!((rates[&1][0].1.rx, rates[&1][0].1.tx), (300, 0));
    }

    #[test]
    fn merges_a_process_seen_in_two_cgroups() {
        let mut list = Vec::new();
        merge(&mut list, 10, Rates { rx: 5, tx: 1 });
        merge(&mut list, 11, Rates { rx: 1, tx: 1 });
        merge(&mut list, 10, Rates { rx: 2, tx: 3 });
        assert_eq!(list.len(), 2);
        assert_eq!(
            (list[0].pid, list[0].rates.rx, list[0].rates.tx),
            (10, 7, 4)
        );
    }

    #[test]
    fn idle_counters_are_unchanged_ones() {
        let previous = HashMap::from([(key(1, 10), (5, 5)), (key(1, 11), (5, 5))]);
        let now = HashMap::from([
            (key(1, 10), (5, 5)),
            (key(1, 11), (6, 5)),
            (key(1, 12), (0, 0)),
        ]);
        assert_eq!(idle(&now, &previous), vec![key(1, 10)]);
    }

    #[test]
    fn exited_pids_are_listed_once() {
        let idle = [key(1, 10), key(2, 10), key(1, 11), key(1, 12)];
        let exited = exited(&idle, |pid| pid != 11);
        assert_eq!(exited, HashSet::from([10, 12]));
    }

    #[test]
    fn comm_names_stop_at_nul() {
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"wget");
        assert_eq!(comm_name(&comm), "wget");
        assert_eq!(comm_name(b"abcdefghijklmnop"), "abcdefghijklmnop");
    }
}
