//! Builds the eBPF programs in `ebpf/` for the BPF target with nightly Rust
//! and bpf-linker, then embeds the object with `include_bytes_aligned!`.
//!
//! Done by hand rather than with aya-build so the programs can target BPF
//! ISA v3 (`-C target-cpu=v3`): its atomic fetch-and-add and
//! compare-and-swap are what the token buckets use (Linux 5.12+).

use std::{env, fs, path::PathBuf, process::Command};

/// The eBPF crate uses core intrinsics, which change between nightlies.
/// Install with `rustup toolchain install nightly-2026-11-21 --component rust-src`.
const TOOLCHAIN: &str = "nightly-2026-11-21";

fn main() {
    println!("cargo::rerun-if-changed=ebpf");
    println!("cargo::rerun-if-changed=common");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_dir = out_dir.join("ebpf-target");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let flags = [
        format!("--cfg=bpf_target_arch=\"{arch}\""),
        "-Ctarget-cpu=v3".into(),
        "-Cdebuginfo=2".into(),
        "-Clink-arg=--btf".into(),
    ];
    let status = Command::new("rustup")
        .args(["run", TOOLCHAIN, "cargo", "build", "--package", "bandito-helper-ebpf"])
        .args(["--release", "--target", "bpfel-unknown-none", "-Z", "build-std=core"])
        .arg("--target-dir")
        .arg(&target_dir)
        .env("CARGO_ENCODED_RUSTFLAGS", flags.join("\x1f"))
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .status()
        .expect("could not run rustup; the eBPF programs need it and bpf-linker");
    assert!(status.success(), "building the eBPF programs failed");
    fs::copy(
        target_dir.join("bpfel-unknown-none/release/bandito"),
        out_dir.join("bandito"),
    )
    .expect("copying the eBPF object");
}
