#!/bin/sh
# Live test of the static aarch64 netleash, as root, in an emulated arm64 VM.
# No sudo and no KVM needed: QEMU emulates the CPU (it takes about half a minute).
#
# Needs qemu-system-aarch64, and an aarch64 kernel and static busybox in
# ARM64_ROOT. On Fedora, from any architecture:
#
#   mkdir arm64-root && cd arm64-root
#   dnf download --forcearch=aarch64 kernel-core kernel-modules-core busybox
#   for rpm in *.rpm; do rpm2cpio "$rpm" | cpio -idm --quiet; done
#
# Then, from the repository root:
#
#   ARM64_ROOT=path/to/arm64-root scripts/vm-arm64.sh
#
# QEMU picks another qemu-system-aarch64. The test itself is vm-arm64-init.sh.

set -eu
cd "$(dirname "$0")/.."
: "${ARM64_ROOT:?set ARM64_ROOT to the extracted aarch64 kernel and busybox (see the top of this script)}"
QEMU=${QEMU:-qemu-system-aarch64}

kernel=$(ls "$ARM64_ROOT"/lib/modules/*/vmlinuz | head -n 1)
modules=$(dirname "$kernel")
busybox=$ARM64_ROOT/usr/bin/busybox
for file in "$kernel" "$modules/kernel/drivers/net/veth.ko.xz" "$busybox"; do
  [ -f "$file" ] || { echo "missing $file" >&2; exit 1; }
done

cargo build --release --target aarch64-unknown-linux-musl
helper=${CARGO_TARGET_DIR:-target}/aarch64-unknown-linux-musl/release/netleash

# An initramfs with busybox as init, the veth module and netleash.
out=vm-test-out/arm64
rm -rf "$out"
mkdir -p "$out/root/bin" "$out/root/proc" "$out/root/sys" "$out/root/dev" "$out/root/run"
cp "$busybox" "$out/root/bin/busybox"
cp "$helper" "$out/root/bin/netleash"
xz -dc "$modules/kernel/drivers/net/veth.ko.xz" > "$out/root/veth.ko"
cp scripts/vm-arm64-init.sh "$out/root/init"
chmod +x "$out/root/init"
(cd "$out/root" && find . | cpio -o -H newc --quiet | gzip -1) > "$out/initramfs.gz"

# -nic none: no network card, so QEMU needs no option ROMs; the test makes
# its own veth pair.
timeout 900 "$QEMU" -M virt -cpu max -smp 2 -m 1024 -nographic -no-reboot \
  -nic none -kernel "$kernel" -initrd "$out/initramfs.gz" \
  -append "console=ttyAMA0 rdinit=/init panic=-1 quiet" > "$out/console.log" 2>&1 || true
grep -v '^\[' "$out/console.log" | grep -v '^$' || true
grep -q '^RESULT: [0-9]* passed, 0 failed' "$out/console.log"
