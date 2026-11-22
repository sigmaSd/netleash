#!/bin/sh
# Publish netleash-common and netleash to crates.io. The netleash package
# ships the compiled eBPF object (netleash.bpf.o, ignored by git) instead of
# ebpf/, so users can `cargo install netleash` without nightly Rust.
#   scripts/publish.sh            publish
#   scripts/publish.sh --dry-run  check the packages only
set -eu
cd "$(dirname "$0")/.."
# Only the generated object may differ from git (cargo calls it dirty).
if [ -n "$(git status --porcelain)" ]; then
  echo "Commit or stash your changes first." >&2
  exit 1
fi
cargo build --release
# The object build.rs just made (layouts differ between Cargo versions).
out=$(find "${CARGO_TARGET_DIR:-target}/release/build" -name netleash.bpf.o \
  -newer build.rs -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2)
cp "$out" netleash.bpf.o
# In dependency order, skipping versions crates.io already has.
packages=""
for package in netleash-common netleash; do
  version=$(cargo pkgid -p "$package" | sed 's/.*[#@]//')
  status=$(curl -s -o /dev/null -w '%{http_code}' -A netleash-publish \
    "https://crates.io/api/v1/crates/$package/$version")
  if [ "$status" = 200 ]; then
    echo "$package $version is already on crates.io"
  else
    packages="$packages -p $package"
  fi
done
[ -n "$packages" ] || exit 0
# shellcheck disable=SC2086
cargo publish $packages --allow-dirty "$@"
