# bandito-helper

Measures and limits network traffic per app with eBPF, for
[Bandito](https://github.com/sigmaSd/bandito-gtk). One root helper replaces the
two Bandito used before: `bandwhich` for measuring and `eltrafico-tc` for
limiting.

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
    queueing discipline, which the helper puts on the interface while an
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

Compared with the previous helpers:

- IPv6 is limited too.
- Traffic is attributed per packet in the kernel, not by polling `ss` or
  `/proc`.
- Apps are named by their application ID instead of a 15-character process
  name.
- Nothing is left behind: the programs are held by `bpf_link` file
  descriptors and detach when the helper exits, however it exits.

## Layout

- `ebpf/`: the eBPF programs (`no_std`, BPF target).
- `common/`: the map keys and values both sides use, defined once.
- `src/`: the userspace helper.

## Build

The helper builds with Rust 1.98 (pinned in `rust-toolchain.toml`). The eBPF
programs need, once:

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

## Installing as a system service

```sh
cargo build --release
sudo scripts/install.sh
```

This installs the helper as `/usr/libexec/bandito-helper` with:

- a D-Bus policy: only root may run the service, anyone may call it;
- a D-Bus activation file and a systemd unit, so the service starts on demand;
- a polkit action, `io.github.sigmasd.Bandito.Helper.configure`. The user at
  the computer may change settings without a password, like network settings;
  others must authenticate as an administrator.

Bandito then uses it automatically, without `pkexec` and without a password
prompt at every start. `DESTDIR` and `PREFIX` work as usual for packaging.

How the pieces talk:

- **Service:** `bandito-helper --dbus` owns `io.github.sigmasd.Bandito.Helper`
  on the system bus, at `/io/github/sigmasd/Bandito/Helper`.
- **Interface `io.github.sigmasd.Bandito.Helper1`:**
  - method `Command(s json)` takes the protocol commands below; polkit checks
    the caller first;
  - signal `Sample(s json)` sends a `sample` event once a second;
  - property `Version`.
- **When clients leave:** if the last client that sent a command leaves the
  bus, its limits are removed. After a minute with no clients the service
  exits, and D-Bus starts it again when needed.
- **Client:** `bandito-helper --client` runs as the user and bridges stdin and
  stdout to the service. Bandito speaks the same JSON lines to it as to the
  helper run through `pkexec`.

## Testing as root without sudo

`scripts/vm.sh` boots your own kernel in a throwaway VM with
[virtme-ng](https://github.com/arighi/virtme-ng) and runs
`scripts/vm-test.sh` there as root. That script:

- builds a veth pair to a server in its own network namespace;
- runs IPv4 and IPv6 traffic from two cgroups named like desktop app scopes;
- checks attribution, per-app and global limits in both directions, upload
  pacing through `fq` without retransmissions, limits without `fq`, error
  reporting, and that nothing stays attached after the helper exits.

`scripts/vm-dbus-test.sh` runs in a second VM. It starts a private system bus
with `dist/`'s policy and checks that:

- only root can run the service, and commands are refused when polkit can't
  answer;
- the unprivileged `nobody` user can set limits through the client and
  receive samples;
- a client's limits go away when it leaves.

It needs `/dev/kvm`, QEMU, `uv tool install virtme-ng`, and a static busybox.
On Fedora you can extract one without installing it:

```sh
dnf download busybox && rpm2cpio busybox-*.x86_64.rpm | cpio -idm ./usr/bin/busybox
BUSYBOX=$PWD/usr/bin/busybox scripts/vm.sh
```

To try the helper on your own machine with Bandito:

```sh
BANDITO_BACKEND=ebpf BANDITO_HELPER=target/release/bandito-helper deno run -A src/main.ts
```

## Not done yet

- The systemd unit and the real polkit daemon haven't been tested: the VM has
  neither. The test bus loads the same D-Bus policy, and the service fails
  closed when polkit doesn't answer.
- Programs started from a terminal share the terminal's scope, so their traffic
  is reported under the terminal app.
- IPv6 extension headers are not followed when reading ports.
