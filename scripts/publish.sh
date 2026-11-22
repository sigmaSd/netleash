#!/bin/sh
# Publish netleash-common and netleash to crates.io. The netleash package
# ships the compiled eBPF object (netleash.bpf.o, ignored by git) instead of
# ebpf/, so users can `cargo install netleash` without nightly Rust.
#   scripts/publish.sh            publish
#   scripts/publish.sh --dry-run  check the packages only
set -eu
cd "$(dirname "$0")/.."
cargo build --release
# The object build.rs just made (layouts differ between Cargo versions).
out=$(find "${CARGO_TARGET_DIR:-target}/release/build" -name netleash.bpf.o \
  -newer build.rs -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2)
cp "$out" netleash.bpf.o
# Both in one call, in dependency order.
cargo publish -p netleash-common -p netleash "$@"
