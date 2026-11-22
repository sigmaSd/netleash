#!/bin/sh
# Run scripts/vm-test.sh as root in a VM booting the host's own kernel, with
# virtme-ng. No sudo: it needs /dev/kvm, QEMU, virtme-ng (`uv tool install
# virtme-ng`) and a static busybox (set BUSYBOX, e.g. extracted from your
# distribution's busybox package).

set -eu
cd "$(dirname "$0")/.."
cargo build --release
HELPER=${CARGO_TARGET_DIR:-target}/release/bandito-helper
mkdir -p vm-test-out
exec vng --run "/boot/vmlinuz-$(uname -r)" \
  ${BUSYBOX:+--busybox "$BUSYBOX"} \
  --user root --memory 1G --cpus 2 \
  --rwdir "$PWD/vm-test-out" \
  --exec "HELPER=$HELPER OUT=$PWD/vm-test-out sh scripts/vm-test.sh"
