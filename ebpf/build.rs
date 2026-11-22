//! Checks for bpf-linker, which links the eBPF programs.

fn main() {
    println!("cargo::rerun-if-env-changed=PATH");
    if let Err(error) = which::which("bpf-linker") {
        panic!("bpf-linker is needed to build the eBPF programs ({error}); run `cargo install bpf-linker`");
    }
}
