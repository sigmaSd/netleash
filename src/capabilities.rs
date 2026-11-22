//! Running without root: with `cap_bpf,cap_net_admin,cap_perfmon+ep` on the
//! binary, netleash loads and attaches its programs as the user.

use caps::{CapSet, Capability};

/// What netleash needs: BPF to load programs and maps, NET_ADMIN to attach
/// them to a cgroup and to set the interface's queueing discipline, and
/// PERFMON for the pointer arithmetic the verifier otherwise reserves for
/// root (the compiler's memset, for instance).
const NEEDED: [Capability; 3] = [
    Capability::CAP_BPF,
    Capability::CAP_NET_ADMIN,
    Capability::CAP_PERFMON,
];

/// The needed capabilities this process lacks; empty when running as root
/// or with them granted.
pub fn missing() -> Vec<String> {
    NEEDED
        .iter()
        .filter(|cap| !caps::has_cap(None, CapSet::Effective, **cap).unwrap_or(false))
        .map(|cap| cap.to_string().to_lowercase())
        .collect()
}

/// File capabilities aren't passed to programs netleash runs (`tc`, which
/// installs `fq` for paced uploads). Make NET_ADMIN ambient so `tc` gets it
/// too. Root needs nothing; without the capability, nothing changes.
pub fn pass_to_children() {
    let cap = Capability::CAP_NET_ADMIN;
    if caps::has_cap(None, CapSet::Permitted, cap).unwrap_or(false) {
        let _ = caps::raise(None, CapSet::Inheritable, cap);
        let _ = caps::raise(None, CapSet::Ambient, cap);
    }
}
