# bandito-helper

Measures and limits network traffic per app with eBPF, for
[Bandito](https://github.com/sigmaSd/bandito-gtk). One root helper replaces the
two Bandito used before: `bandwhich` for measuring and `eltrafico-tc` for
limiting.

## How it works

Two `cgroup_skb` eBPF programs (`bpf/bandito.bpf.c`) are attached to the root
cgroup. Every packet a local socket sends or receives passes through them with
the socket's cgroup id. Desktops run each app in its own systemd scope
(`app-gnome-org.mozilla.firefox-9848.scope`) and each service in its own unit,
so the cgroup names the app.

- **Counting:** bytes per cgroup and per connection (remote address and ports),
  IPv4 and IPv6, on the chosen interface only.
- **Limiting:** a token bucket per limited app and direction, plus a global one.
  Packets over the rate are dropped, and TCP slows down to match.
- **Naming:** cgroups are mapped to application IDs (desktop file names) by
  reading `/sys/fs/cgroup`. Services are named after their unit, and other units
  after their busiest process.
- **Host names:** looked up in the background and cached.
- **Unidentified traffic:** traffic no local socket owns (forwarded packets,
  ICMP, the kernel's own) is the interface total minus the apps.

Compared with the previous helpers:

- IPv6 is limited too.
- Traffic is attributed per packet in the kernel, not by polling `ss` or
  `/proc`.
- Apps are named by their application ID instead of a 15-character process
  name.
- Nothing is left behind: the programs are held by `bpf_link` file
  descriptors and detach when the helper exits, however it exits.

## Build

Needs Rust 1.98 (pinned in `rust-toolchain.toml`) and clang.

```sh
cargo build --release
```

`build.rs` compiles `bpf/bandito.bpf.c` and embeds the object in the binary.
`cargo test` runs the userspace tests without root.

## Protocol

The helper runs as root and speaks JSON lines.

Commands, one per line on stdin:

```json
{"cmd": "interface", "name": "wlan0"}
{"cmd": "limit", "app": "org.mozilla.firefox", "down": 2500000, "up": null}
{"cmd": "limit", "app": null, "down": 10000000, "up": 1000000}
{"cmd": "stop"}
```

- `app` is an ID from the samples. `null` limits all apps together.
- Rates are bytes per second. `null` removes that limit.
- Closing stdin stops the helper.

Events, one per line on stdout:

```json
{"type": "ready", "version": "0.1.0"}
{"type": "sample", "interface": "wlan0", "total": {"rx": 3200000, "tx": 410000},
 "apps": [{"id": "org.mozilla.firefox", "kind": "app",
           "units": ["app-gnome-org.mozilla.firefox-9848.scope"],
           "processes": ["firefox", "Socket Process"],
           "rx": 2500000, "tx": 200000, "limitDown": 2500000}],
 "connections": [{"app": "org.mozilla.firefox", "protocol": "tcp",
                  "remote": "2606:4700::6810:84e5", "host": "example.com",
                  "remotePort": 443, "localPort": 51000, "rx": 2500000, "tx": 200000}]}
{"type": "error", "message": "no network interface named wlan9"}
{"type": "stopped"}
```

- A sample is sent once a second.
- `kind` is `app`, `service` or `other`.

## Trying it

```sh
sudo ~/dev/rust/cargo_target_dir/release/bandito-helper
```

Type `{"cmd":"interface","name":"wlan0"}` and watch the samples. With Bandito:

```sh
BANDITO_BACKEND=ebpf BANDITO_HELPER=~/dev/rust/cargo_target_dir/release/bandito-helper deno run -A src/main.ts
```

## Not done yet

- The loading and verifier path hasn't run outside a root shell yet. The
  userspace, the protocol and the Bandito side are tested; the kernel side
  needs a live run.
- It runs through `pkexec` like the old helpers. The plan is to install it as
  a system service on the system D-Bus, with polkit deciding who may change
  limits.
- Upload limiting drops packets. Pacing with EDT and the `fq` qdisc would be
  smoother.
- Programs started from a terminal share the terminal's scope, so their traffic
  is reported under the terminal app.
- IPv6 extension headers are not followed when reading ports.
