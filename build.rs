//! Builds the eBPF programs in `ebpf/` for the BPF target with nightly Rust
//! and bpf-linker, then embeds the object with `include_bytes_aligned!`.
//!
//! Done by hand rather than with aya-build so the programs can target BPF
//! ISA v3 (`-C target-cpu=v3`): its atomic fetch-and-add and
//! compare-and-swap are what the token buckets use (Linux 5.12+).
//!
//! The crate published on crates.io has no `ebpf/`; it ships the compiled
//! object as `netleash.bpf.o` instead, so `cargo install netleash` needs
//! neither nightly Rust nor bpf-linker.

use std::{env, fs, path::Path, path::PathBuf, process::Command};

/// The eBPF crate uses core intrinsics, which change between nightlies.
/// Install with `rustup toolchain install nightly-2026-11-21 --component rust-src`.
const TOOLCHAIN: &str = "nightly-2026-11-21";
/// The compiled programs shipped in the published crate.
const PREBUILT: &str = "netleash.bpf.o";

fn main() {
    println!("cargo::rerun-if-changed=ebpf");
    println!("cargo::rerun-if-changed=common");
    println!("cargo::rerun-if-changed={PREBUILT}");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let object = out_dir.join("netleash.bpf.o");
    if !Path::new("ebpf/Cargo.toml").exists() {
        fs::copy(PREBUILT, &object).expect("the packaged eBPF object, netleash.bpf.o");
        return;
    }
    let target_dir = out_dir.join("ebpf-target");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let flags = [
        format!("--cfg=bpf_target_arch=\"{arch}\""),
        "-Ctarget-cpu=v3".into(),
        "-Cdebuginfo=2".into(),
        "-Clink-arg=--btf".into(),
    ];
    let status = Command::new("rustup")
        .args([
            "run",
            TOOLCHAIN,
            "cargo",
            "build",
            "--package",
            "netleash-ebpf",
        ])
        .args([
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ])
        .arg("--target-dir")
        .arg(&target_dir)
        .env("CARGO_ENCODED_RUSTFLAGS", flags.join("\x1f"))
        // BTF needs debug info; one codegen unit links into one object.
        .env("CARGO_PROFILE_RELEASE_DEBUG", "2")
        .env("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "1")
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .status()
        .expect("could not run rustup; the eBPF programs need it and bpf-linker");
    assert!(status.success(), "building the eBPF programs failed");
    fs::copy(
        target_dir.join("bpfel-unknown-none/release/netleash"),
        &object,
    )
    .expect("copying the eBPF object");
}
