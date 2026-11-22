# netleash

See and limit network traffic per app on Linux, with eBPF.

netleash counts every app's download and upload, and each of its connections,
as the kernel sends and receives them. It caps any app, or all of them
together, in either direction, over IPv4 and IPv6. It runs as a small system
service that apps talk to over D-Bus. [Bandito](https://github.com/sigmaSd/bandito-gtk)
is a GTK front end for it; anything that speaks its JSON protocol can be one.

- Apps are named by their application ID (`org.mozilla.firefox`), from the
  systemd scope desktops start them in, so front ends can show the right name
  and icon.
- Upload limits are paced, not dropped: TCP doesn't retransmit.
- Nothing is left behind: everything detaches when netleash exits, however it
  exits.

It needs Linux 5.12 or later with cgroup v2, which any current distribution has.

## Install

From crates.io (the eBPF programs come precompiled, so stable Rust is enough):

```sh
cargo install netleash
sudo ~/.cargo/bin/netleash --install
```

Or download `netleash` from the
[latest release](https://github.com/sigmaSd/netleash/releases/latest), then run
`chmod +x netleash` and `sudo ./netleash --install`.

`--install` copies the binary to `/usr/bin/netleash` and adds:

- a D-Bus policy: only root may run the service, anyone may call it;
- a D-Bus activation file and a systemd unit, so the service starts on demand;
- a polkit action, `io.github.sigmasd.Netleash.configure`. The user at the
  computer may change limits without a password, like network settings;
  others must authenticate as an administrator.

`sudo netleash --uninstall` removes them again. Both take `--prefix DIR`
(default `/usr`). Packagers can use `scripts/install.sh`, which honours
`DESTDIR` and `PREFIX`.

## Use

As your user, `netleash --client` connects to the service, starting it if
needed, and speaks the [protocol](#protocol) on stdin and stdout:

```console
$ netleash --client
{"type":"ready","version":"0.1.0"}
{"cmd":"interface","name":"wlan0"}
{"type":"sample","interface":"wlan0","total":{"rx":3200000,"tx":410000},"apps":[...],"connections":[...]}
{"cmd":"limit","app":"org.mozilla.firefox","down":2500000,"up":null}
```

When the client exits, the limits it set are removed.

Bandito uses netleash automatically when the service is installed.

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

Run as root (`sudo netleash`, as a front end does through `pkexec`), or through
the service with `netleash --client`, netleash speaks JSON lines.

Commands, one per line on stdin:

```json
{"cmd": "interface", "name": "wlan0"}
{"cmd": "limit", "app": "org.mozilla.firefox", "down": 2500000, "up": null}
{"cmd": "limit", "app": null, "down": 10000000, "up": 1000000}
{"cmd": "stop"}
```

- `app` is an ID from the samples. `null` limits all apps together.
- Rates are bytes per second. `null` removes that limit.
- Closing stdin stops netleash (or, with `--client`, removes the client's
  limits).

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

## D-Bus service

How the pieces talk:

- **Service:** `netleash --dbus` owns `io.github.sigmasd.Netleash`
  on the system bus, at `/io/github/sigmasd/Netleash`.
- **Interface `io.github.sigmasd.Netleash1`:**
  - method `Command(s json)` takes the protocol commands below; polkit checks
    the caller first;
  - signal `Sample(s json)` sends a `sample` event once a second;
  - property `Version`.
- **When clients leave:** if the last client that sent a command leaves the
  bus, its limits are removed. After a minute with no clients the service
  exits, and D-Bus starts it again when needed.
- **Client:** `netleash --client` runs as the user and bridges stdin and
  stdout to the service, so a front end speaks the same JSON lines either way.

## Testing as root without sudo

`scripts/vm.sh` boots your own kernel in a throwaway VM with
[virtme-ng](https://github.com/arighi/virtme-ng) and runs
`scripts/vm-test.sh` there as root. That script:

- builds a veth pair to a server in its own network namespace;
- runs IPv4 and IPv6 traffic from two cgroups named like desktop app scopes;
- checks attribution, per-app and global limits in both directions, upload
  pacing through `fq` without retransmissions, limits without `fq`, error
  reporting, and that nothing stays attached after netleash exits.

`scripts/vm-dbus-test.sh` runs in a second VM. It starts a private system bus
with `dist/`'s policy and checks that:

- only root can run the service, and commands are refused when polkit can't
  answer;
- the unprivileged `nobody` user can set limits through the client and
  receive samples;
- a client's limits go away when it leaves;
- `--install` and `--uninstall` write and remove the service files.

It needs `/dev/kvm`, QEMU, `uv tool install virtme-ng`, and a static busybox.
On Fedora you can extract one without installing it:

```sh
dnf download busybox && rpm2cpio busybox-*.x86_64.rpm | cpio -idm ./usr/bin/busybox
BUSYBOX=$PWD/usr/bin/busybox scripts/vm.sh
```

To try a build with Bandito without installing it, run Bandito with
`BANDITO_BACKEND=ebpf NETLEASH=target/release/netleash`; it then runs that
binary through `pkexec`.

To publish, `scripts/publish.sh` builds the eBPF object, which the crate ships
instead of `ebpf/`, and publishes `netleash-common` and `netleash`.

## Limitations

- The systemd unit and the real polkit daemon haven't been tested: the VM has
  neither. The test bus loads the same D-Bus policy, and the service fails
  closed when polkit doesn't answer.
- Programs started from a terminal share the terminal's scope, so their traffic
  is reported under the terminal app.
- IPv6 extension headers are not followed when reading ports.
