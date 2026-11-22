#!/bin/sh
# Run the live tests as root in VMs booting the host's own kernel, with
# virtme-ng. No sudo: it needs /dev/kvm, QEMU, virtme-ng (`uv tool install
# virtme-ng`) and a static busybox (set BUSYBOX, e.g. extracted from your
# distribution's busybox package).
#
#   scripts/vm.sh                 both tests
#   scripts/vm.sh vm-test.sh      one of them

set -eu
cd "$(dirname "$0")/.."
cargo build --release
HELPER=${CARGO_TARGET_DIR:-target}/release/netleash
mkdir -p vm-test-out
status=0
for test in ${1:-vm-test.sh vm-caps-test.sh}; do
  echo "== $test"
  vng --run "/boot/vmlinuz-$(uname -r)" \
    ${BUSYBOX:+--busybox "$BUSYBOX"} \
    --user root --memory 1G --cpus 2 \
    --rwdir "$PWD/vm-test-out" \
    --exec "HELPER=$HELPER OUT=$PWD/vm-test-out sh scripts/$test" || status=1
done
exit $status
