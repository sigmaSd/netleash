//! Compiles the eBPF programs in `bpf/` with clang; the object is embedded in
//! the helper with `include_bytes!`.

use std::{env, path::PathBuf, process::Command};

fn main() {
    let source = "bpf/bandito.bpf.c";
    println!("cargo:rerun-if-changed={source}");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bandito.bpf.o");
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".into());
    let status = Command::new(&clang)
        .args(["-O2", "-g", "-target", "bpf", "-mcpu=v3", "-Wall", "-Werror", "-c"])
        .arg(source)
        .arg("-o")
        .arg(&out)
        .status()
        .unwrap_or_else(|e| panic!("could not run {clang}: {e}"));
    assert!(status.success(), "clang failed to compile {source}");
}
