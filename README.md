# netleash

See and limit network traffic per app on Linux, with eBPF.

netleash counts every app's download and upload, and each of its connections,
as the kernel sends and receives them. It caps any app, or all of them
together, in either direction, over IPv4 and IPv6. Front ends run it and talk
to it in JSON lines on stdin and stdout; [Bandito](https://github.com/sigmaSd/bandito-gtk)
is a GTK one.

- Apps are named by their application ID (`org.mozilla.firefox`), from the
  systemd scope desktops start them in, so front ends can show the right name
  and icon.
- Upload limits are paced, not dropped: TCP doesn't retransmit.
- It installs nothing and leaves nothing behind: everything detaches when
  netleash exits, however it exits.

It needs Linux 5.12 or later with cgroup v2, which any current distribution has.

## Install

From crates.io (the eBPF programs come precompiled, so stable Rust is enough):

```sh
cargo install netleash
```

Or download the static `netleash` binary from the
[latest release](https://github.com/sigmaSd/netleash/releases/latest) and
`chmod +x` it.

## Running it

netleash needs root, or three capabilities. Pick one way:

- **On demand, as root:** run it with `pkexec netleash` or `sudo netleash`. It
  is root only while it runs, nothing is installed, and you're asked for your
  password each time.
- **With file capabilities, as yourself:** grant them to the binary once:

  ```sh
  sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep "$(command -v netleash)"
  ```

  Then run `netleash` as your user, with no prompt and nothing installed: the
  capabilities live in an extended attribute on the binary.
  - `cap_bpf` loads the programs and maps.
  - `cap_net_admin` attaches them and lets `tc` add `fq` for paced uploads.
    netleash passes it on to `tc`.
  - `cap_perfmon` lets the kernel verifier accept the pointer arithmetic it
    otherwise reserves for root.

  Changing the file drops the capabilities, so a replaced or reinstalled
  binary has none until you run `setcap` again. `netleash --capable` says
  whether this binary can run without root.

Then speak the [protocol](#protocol):

```console
$ netleash
{"type":"ready","version":"0.2.0"}
{"cmd":"interface","name":"wlan0"}
{"type":"sample","interface":"wlan0","total":{"rx":3200000,"tx":410000},"apps":[...],"connections":[...]}
{"cmd":"limit","app":"org.mozilla.firefox","down":2500000,"up":null}
```

Closing stdin stops it and removes every limit.

## How it works

Two `cgroup_skb` eBPF programs, written in Rust with
[aya-ebpf](https://crates.io/crates/aya-ebpf) (`ebpf/`), are attached to the
root cgroup. Every packet a local socket sends or receives passes through them with
the socket's cgroup id. Desktops run each app in its own systemd scope
(`app-gnome-org.mozilla.firefox-9848.scope`) and each service in its own unit,
so the cgroup names the app.

- **Counting:** bytes per cgroup and per connection (remote address and ports),
  IPv4 and IPv6, on the chosen interface only.
- **Limiting:** a limit per app and direction, plus a global one.
  - Uploads are paced: each packet gets a departure time (EDT), and the `fq`
    queueing discipline, which netleash puts on the interface while an
    upload limit is set, sends it then. Nothing is dropped and TCP doesn't
    retransmit. Without `fq`, packets more than half a second ahead are
    dropped instead.
  - Downloads can't be delayed, so packets over a token bucket's rate are
    dropped, and TCP slows down to match.
- **Naming:** cgroups are mapped to application IDs (desktop file names) by
  reading `/sys/fs/cgroup`. Services are named after their unit, and other units
  after their busiest process.
- **Host names:** looked up in the background and cached.
- **Unidentified traffic:** traffic no local socket owns (forwarded packets,
  ICMP, the kernel's own) is the interface total minus the apps.

Compared with tools that poll `ss` or walk `/proc` (as `bandwhich` and
`eltrafico` do), traffic is attributed per packet in the kernel, IPv6 is
limited too, and the programs are held by `bpf_link` file descriptors, so they
detach when netleash exits, however it exits.

## Layout

- `ebpf/`: the eBPF programs (`no_std`, BPF target).
- `common/`: the map keys and values both sides use, defined once.
- `src/`: the userspace program.

## Building from source

netleash builds with stable Rust (pinned in `rust-toolchain.toml`). Building the
eBPF programs from source needs, once:

```sh
rustup toolchain install nightly-2026-11-21 --component rust-src
cargo install bpf-linker
```

Then:

```sh
cargo build --release
```

- `build.rs` compiles `ebpf/` for `bpfel-unknown-none` with that nightly, for
  BPF ISA v3 (Linux 5.12+, for atomic fetch-and-add and compare-and-swap),
  and embeds the object in the binary.
- The nightly is pinned because the programs use core's atomic intrinsics:
  `core` has no 64-bit atomic types for the BPF target.
- `cargo test` runs the userspace tests without root. It also checks the
  compiled object: both programs and all maps are there, and every atomic add
  returns the old value. A relaxed add compiles to BPF's plain add, which
  returns nothing, so the atomics are sequentially consistent.

## Protocol

netleash speaks JSON lines on stdin and stdout.

Commands, one per line on stdin:

```json
{"cmd": "interface", "name": "wlan0"}
{"cmd": "limit", "app": "org.mozilla.firefox", "down": 2500000, "up": null}
{"cmd": "limit", "app": null, "down": 10000000, "up": 1000000}
{"cmd": "stop"}
```

- `app` is an ID from the samples. `null` limits all apps together.
- Rates are bytes per second. `null` removes that limit.
- Closing stdin stops netleash.

Events, one per line on stdout:

```json
{"type": "ready", "version": "0.2.0"}
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

## Testing as root without sudo

`scripts/vm.sh` boots your own kernel in a throwaway VM with
[virtme-ng](https://github.com/arighi/virtme-ng) and runs
`scripts/vm-test.sh` there as root. That script:

- builds a veth pair to a server in its own network namespace;
- runs IPv4 and IPv6 traffic from two cgroups named like desktop app scopes;
- checks attribution, per-app and global limits in both directions, upload
  pacing through `fq` without retransmissions, limits without `fq`, error
  reporting, and that nothing stays attached after netleash exits.

`scripts/vm-caps-test.sh` runs in a second VM. It gives the binary its file
capabilities and runs it as the unprivileged `nobody` user, checking that it
starts, attributes traffic, and holds paced and dropped limits, with `tc`
adding `fq` through the passed-on capability.

It needs `/dev/kvm`, QEMU, `uv tool install virtme-ng`, and a static busybox.
On Fedora you can extract one without installing it:

```sh
dnf download busybox && rpm2cpio busybox-*.x86_64.rpm | cpio -idm ./usr/bin/busybox
BUSYBOX=$PWD/usr/bin/busybox scripts/vm.sh
```

To try a build with Bandito, run Bandito with `NETLEASH=target/release/netleash`.

To publish, `scripts/publish.sh` builds the eBPF object, which the crate ships
instead of `ebpf/`, and publishes `netleash-common` and `netleash`.

## Limitations

- Programs started from a terminal share the terminal's scope, so their traffic
  is reported under the terminal app.
- IPv6 extension headers are not followed when reading ports.
