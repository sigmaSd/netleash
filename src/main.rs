//! bandito-helper: measures and limits network traffic per app with eBPF.
//!
//! Runs as root, attaches the two cgroup_skb programs in `ebpf/` to the
//! root cgroup, and
//! talks JSON lines on stdin/stdout (see `protocol`). The programs detach
//! when the helper exits, however it exits: they are held by bpf_link file
//! descriptors, not left behind in the kernel like tc rules.

mod apps;
mod dns;
mod limits;
mod protocol;

use anyhow::{bail, Context, Result};
use apps::{Cgroup, Kind, CGROUP_ROOT};
use aya::{
    maps::{Array, HashMap as BpfHashMap, MapData, PerCpuHashMap},
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType},
    Ebpf,
};
use bandito_helper_common::{AppCounters, Bucket, BucketKey, Config, FlowCounters, FlowKey};
use limits::{Direction, Slots, GLOBAL_DOWN, GLOBAL_UP, MAX_RATE};
use protocol::{Command, Connection, Event, Rates, Sample};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{self, BufRead, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

static OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/bandito"));

struct Maps {
    config: Array<MapData, Config>,
    app_stats: PerCpuHashMap<MapData, u64, AppCounters>,
    // An LRU hash map; aya reads both kinds through HashMap.
    flows: BpfHashMap<MapData, FlowKey, FlowCounters>,
    cgroup_buckets: BpfHashMap<MapData, BucketKey, u32>,
    buckets: Array<MapData, Bucket>,
}

/// Load the programs, attach them to the root cgroup and take the maps.
fn load() -> Result<(Ebpf, Maps)> {
    let mut bpf = Ebpf::load(OBJECT).context("loading the eBPF object")?;
    let root = fs::File::open(CGROUP_ROOT).context("opening the root cgroup")?;
    for (name, attach) in [
        ("bandito_ingress", CgroupSkbAttachType::Ingress),
        ("bandito_egress", CgroupSkbAttachType::Egress),
    ] {
        let program: &mut CgroupSkb = bpf
            .program_mut(name)
            .with_context(|| format!("missing program {name}"))?
            .try_into()?;
        program.load().with_context(|| format!("verifying {name}"))?;
        // aya attaches with a bpf_link (Linux 5.7+), which the kernel always
        // adds alongside other programs, such as systemd's; it rejects an
        // explicit multi-attach flag.
        program
            .attach(&root, attach, CgroupAttachMode::Single)
            .with_context(|| format!("attaching {name}"))?;
    }
    let mut take = |name: &str| {
        bpf.take_map(name)
            .with_context(|| format!("missing map {name}"))
    };
    let maps = Maps {
        config: Array::try_from(take("config")?)?,
        app_stats: PerCpuHashMap::try_from(take("app_stats")?)?,
        flows: BpfHashMap::try_from(take("flows")?)?,
        cgroup_buckets: BpfHashMap::try_from(take("cgroup_buckets")?)?,
        buckets: Array::try_from(take("buckets")?)?,
    };
    Ok((bpf, maps))
}

fn emit(event: &Event) {
    let mut out = io::stdout().lock();
    let _ = serde_json::to_writer(&mut out, event);
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

/// Bytes received and sent on an interface, or on all but loopback.
fn interface_totals(interface: Option<&str>) -> (u64, u64) {
    let read = |name: &str, counter: &str| {
        fs::read_to_string(format!("/sys/class/net/{name}/statistics/{counter}"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0)
    };
    match interface {
        Some(name) => (read(name, "rx_bytes"), read(name, "tx_bytes")),
        None => fs::read_dir("/sys/class/net")
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|name| name != "lo")
                    .fold((0, 0), |(rx, tx), name| {
                        (rx + read(&name, "rx_bytes"), tx + read(&name, "tx_bytes"))
                    })
            })
            .unwrap_or((0, 0)),
    }
}

fn ifindex(name: &str) -> Result<u32> {
    let c_name = std::ffi::CString::new(name)?;
    // SAFETY: c_name is a valid NUL-terminated string.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        bail!("no network interface named {name}");
    }
    Ok(index)
}

fn remote_address(key: &FlowKey) -> IpAddr {
    if key.family == bandito_helper_common::AF_INET6 {
        IpAddr::V6(Ipv6Addr::from(key.remote))
    } else {
        IpAddr::V4(Ipv4Addr::new(
            key.remote[0],
            key.remote[1],
            key.remote[2],
            key.remote[3],
        ))
    }
}

fn protocol_name(protocol: u8) -> &'static str {
    match protocol {
        6 => "tcp",
        17 => "udp",
        1 | 58 => "icmp",
        _ => "other",
    }
}

/// The id traffic is reported under: the app or service id, or for other
/// units (sessions) the busiest process name.
fn report_id(cgroup: &Cgroup) -> String {
    match cgroup.unit.kind {
        Kind::App | Kind::Service => cgroup.unit.id.clone(),
        Kind::Other => cgroup
            .processes()
            .into_iter()
            .next()
            .unwrap_or_else(|| cgroup.unit.id.clone()),
    }
}

/// Bytes per second from a counter delta over `elapsed` seconds.
fn per_second(delta: u64, elapsed: f64) -> u64 {
    (delta as f64 / elapsed).round() as u64
}

struct Helper {
    maps: Maps,
    interface: Option<String>,
    cgroups: HashMap<u64, Cgroup>,
    ids: HashMap<u64, String>,
    last_scan: Instant,
    app_totals: HashMap<u64, (u64, u64)>,
    flow_totals: HashMap<FlowKey, (u64, u64)>,
    iface_totals: (u64, u64),
    last_tick: Instant,
    slots: Slots,
    /// Limits by app id and direction, in bytes per second.
    limits: HashMap<(String, Direction), u64>,
    resolver: dns::Resolver,
}

impl Helper {
    fn new(maps: Maps) -> Result<Self> {
        let mut helper = Self {
            maps,
            interface: None,
            cgroups: HashMap::new(),
            ids: HashMap::new(),
            last_scan: Instant::now(),
            app_totals: HashMap::new(),
            flow_totals: HashMap::new(),
            iface_totals: interface_totals(None),
            last_tick: Instant::now(),
            slots: Slots::default(),
            limits: HashMap::new(),
            resolver: dns::Resolver::new(),
        };
        helper.rescan();
        helper.maps.config.set(0, &Config { ifindex: 0, enabled: 1 }, 0)?;
        Ok(helper)
    }

    fn rescan(&mut self) {
        self.cgroups = apps::scan(Path::new(CGROUP_ROOT));
        self.ids = self
            .cgroups
            .iter()
            .map(|(id, cg)| (*id, report_id(cg)))
            .collect();
        self.last_scan = Instant::now();
        self.sync_cgroup_buckets();
    }

    /// Point every cgroup of a limited app at the app's bucket, and drop
    /// entries for cgroups that are gone or no longer limited.
    fn sync_cgroup_buckets(&mut self) {
        let mut wanted: HashMap<(u64, u32), u32> = HashMap::new();
        for (app, direction, slot) in self.slots.iter() {
            for (cgroup, id) in &self.ids {
                if id == app {
                    wanted.insert((*cgroup, direction as u32), slot);
                }
            }
        }
        let existing: Vec<BucketKey> = self.maps.cgroup_buckets.keys().flatten().collect();
        for key in existing {
            if !wanted.contains_key(&(key.cgroup, key.direction)) {
                let _ = self.maps.cgroup_buckets.remove(&key);
            }
        }
        for ((cgroup, direction), slot) in wanted {
            let key = BucketKey { cgroup, direction, pad: 0 };
            let _ = self.maps.cgroup_buckets.insert(&key, &slot, 0);
        }
    }

    fn set_bucket(&mut self, slot: u32, rate: Option<u64>) -> Result<()> {
        let bucket = match rate {
            Some(rate) => {
                let rate = rate.clamp(1, MAX_RATE);
                let burst = limits::burst(rate);
                Bucket { tokens: burst as i64, last_ns: 0, rate, burst }
            }
            None => Bucket::default(),
        };
        self.maps.buckets.set(slot, &bucket, 0)?;
        Ok(())
    }

    /// Apply a command; returns false when the helper should stop.
    fn command(&mut self, command: Command) -> Result<bool> {
        match command {
            Command::Stop => return Ok(false),
            Command::Interface { name } => {
                let index = ifindex(&name)?;
                self.maps
                    .config
                    .set(0, &Config { ifindex: index, enabled: 1 }, 0)?;
                self.iface_totals = interface_totals(Some(&name));
                self.interface = Some(name);
            }
            Command::Limit { app: None, down, up } => {
                self.set_bucket(GLOBAL_DOWN, down)?;
                self.set_bucket(GLOBAL_UP, up)?;
            }
            Command::Limit { app: Some(app), down, up } => {
                for (direction, rate) in [(Direction::Down, down), (Direction::Up, up)] {
                    match rate {
                        Some(rate) => {
                            let slot = self
                                .slots
                                .get_or_assign(&app, direction)
                                .context("too many limited apps")?;
                            self.set_bucket(slot, Some(rate))?;
                            self.limits.insert((app.clone(), direction), rate);
                        }
                        None => {
                            if let Some(slot) = self.slots.release(&app, direction) {
                                self.set_bucket(slot, None)?;
                            }
                            self.limits.remove(&(app.clone(), direction));
                        }
                    }
                }
                self.sync_cgroup_buckets();
            }
        }
        Ok(true)
    }

    fn sample(&mut self) -> Sample {
        let elapsed = self.last_tick.elapsed().as_secs_f64().max(0.001);
        self.last_tick = Instant::now();

        // Per-cgroup byte counters, summed over CPUs.
        let mut current: HashMap<u64, (u64, u64)> = HashMap::new();
        for (cgroup, values) in self.maps.app_stats.iter().flatten() {
            let sum = values
                .iter()
                .fold((0, 0), |(rx, tx), v| (rx + v.rx_bytes, tx + v.tx_bytes));
            current.insert(cgroup, sum);
        }
        if current.keys().any(|id| !self.ids.contains_key(id))
            || self.last_scan.elapsed() > Duration::from_secs(10)
        {
            self.rescan();
        }

        let mut apps: BTreeMap<String, protocol::App> = BTreeMap::new();
        for (cgroup, (rx, tx)) in &current {
            let (prev_rx, prev_tx) = self.app_totals.get(cgroup).copied().unwrap_or((0, 0));
            let rates = Rates {
                rx: per_second(rx.saturating_sub(prev_rx), elapsed),
                tx: per_second(tx.saturating_sub(prev_tx), elapsed),
            };
            if rates.rx == 0 && rates.tx == 0 {
                continue;
            }
            let Some(info) = self.cgroups.get(cgroup) else { continue };
            let id = self.ids.get(cgroup).cloned().unwrap_or_else(|| info.unit.id.clone());
            let app = apps.entry(id.clone()).or_insert_with(|| protocol::App {
                id: id.clone(),
                kind: info.unit.kind.clone(),
                units: Vec::new(),
                processes: Vec::new(),
                rates: Rates::default(),
                limit_down: self.limits.get(&(id.clone(), Direction::Down)).copied(),
                limit_up: self.limits.get(&(id.clone(), Direction::Up)).copied(),
            });
            app.rates.rx += rates.rx;
            app.rates.tx += rates.tx;
            app.units.push(info.unit.unit.clone());
            for process in info.processes() {
                if !app.processes.contains(&process) {
                    app.processes.push(process);
                }
            }
        }
        self.app_totals = current;

        // Per-connection counters.
        let mut connections = Vec::new();
        let mut flow_now: HashMap<FlowKey, (u64, u64)> = HashMap::new();
        for (key, counters) in self.maps.flows.iter().flatten() {
            let totals = (counters.rx_bytes, counters.tx_bytes);
            flow_now.insert(key, totals);
            let (prev_rx, prev_tx) = self.flow_totals.get(&key).copied().unwrap_or((0, 0));
            let rx = per_second(totals.0.saturating_sub(prev_rx), elapsed);
            let tx = per_second(totals.1.saturating_sub(prev_tx), elapsed);
            if rx == 0 && tx == 0 {
                continue;
            }
            let remote = remote_address(&key);
            connections.push(Connection {
                app: self
                    .ids
                    .get(&key.cgroup)
                    .cloned()
                    .unwrap_or_else(|| key.cgroup.to_string()),
                protocol: protocol_name(key.protocol),
                remote: remote.to_string(),
                host: self.resolver.name(remote),
                remote_port: key.remote_port,
                local_port: key.local_port,
                rates: Rates { rx, tx },
            });
        }
        self.flow_totals = flow_now;

        let totals = interface_totals(self.interface.as_deref());
        let total = Rates {
            rx: per_second(totals.0.saturating_sub(self.iface_totals.0), elapsed),
            tx: per_second(totals.1.saturating_sub(self.iface_totals.1), elapsed),
        };
        self.iface_totals = totals;

        let mut apps: Vec<protocol::App> = apps.into_values().collect();
        apps.sort_by_key(|a| std::cmp::Reverse(a.rates.rx + a.rates.tx));
        connections.sort_by_key(|c| std::cmp::Reverse(c.rates.rx + c.rates.tx));
        Sample { interface: self.interface.clone(), total, apps, connections }
    }
}

fn run() -> Result<()> {
    let (_bpf, maps) = load()?;
    let mut helper = Helper::new(maps)?;

    let (commands, incoming) = mpsc::channel::<String>();
    thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if commands.send(line).is_err() {
                return;
            }
        }
        // stdin closed: whoever started the helper is gone, so stop.
        let _ = commands.send(r#"{"cmd":"stop"}"#.into());
    });

    emit(&Event::Ready { version: env!("CARGO_PKG_VERSION") });
    let mut next = Instant::now() + Duration::from_secs(1);
    loop {
        let wait = next.saturating_duration_since(Instant::now());
        match incoming.recv_timeout(wait) {
            Ok(line) if line.trim().is_empty() => {}
            Ok(line) => match serde_json::from_str::<Command>(&line) {
                Ok(command) => match helper.command(command) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(error) => emit(&Event::Error { message: format!("{error:#}") }),
                },
                Err(error) => emit(&Event::Error { message: format!("bad command: {error}") }),
            },
            Err(mpsc::RecvTimeoutError::Timeout) => {
                emit(&Event::Sample(helper.sample()));
                next += Duration::from_secs(1);
                if next < Instant::now() {
                    next = Instant::now() + Duration::from_secs(1);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    // Dropping the eBPF object closes the links, which detaches the programs.
    emit(&Event::Stopped);
    Ok(())
}

fn main() {
    if std::env::args().any(|a| a == "-h" || a == "--help") {
        println!(
            "bandito-helper {}: measures and limits traffic per app with eBPF.\n\
             Run as root. Speaks JSON lines on stdin/stdout; see README.md.",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }
    if let Err(error) = run() {
        emit(&Event::Error { message: format!("{error:#}") });
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_object_has_both_programs_and_all_maps() {
        let object = aya_obj::Object::parse(OBJECT).expect("aya parses the object");
        for program in ["bandito_ingress", "bandito_egress"] {
            assert!(object.programs.contains_key(program), "{program}");
        }
        for map in ["config", "app_stats", "flows", "cgroup_buckets", "buckets"] {
            assert!(object.maps.contains_key(map), "{map}");
        }
    }

    /// A plain BPF atomic add (no fetch flag) never returns the old value,
    /// so code relying on it would silently compute garbage; see `fetch_add`
    /// in ebpf/src/main.rs.
    #[test]
    fn every_atomic_add_fetches() {
        const BPF_STX_ATOMIC_DW: u8 = 0xdb;
        const BPF_FETCH: i32 = 0x01;
        let object = aya_obj::Object::parse(OBJECT).unwrap();
        let mut atomics = 0;
        for function in object.functions.values() {
            for insn in &function.instructions {
                if insn.code == BPF_STX_ATOMIC_DW {
                    atomics += 1;
                    assert_ne!(insn.imm & BPF_FETCH, 0, "{} has a plain atomic add", function.name);
                }
            }
        }
        assert!(atomics > 0, "the token buckets use atomics");
    }

    #[test]
    fn remote_addresses_by_family() {
        let mut key = FlowKey { family: 2, ..Default::default() };
        key.remote[..4].copy_from_slice(&[93, 184, 216, 34]);
        assert_eq!(remote_address(&key).to_string(), "93.184.216.34");
        let v6: Ipv6Addr = "2606:2800:220:1::1".parse().unwrap();
        let key = FlowKey { family: 10, remote: v6.octets(), ..Default::default() };
        assert_eq!(remote_address(&key).to_string(), "2606:2800:220:1::1");
    }

    #[test]
    fn rates_round_per_second() {
        assert_eq!(per_second(1500, 1.0), 1500);
        assert_eq!(per_second(1500, 0.5), 3000);
        assert_eq!(per_second(0, 1.0), 0);
    }
}
