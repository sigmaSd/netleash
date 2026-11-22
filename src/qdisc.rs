//! Puts the `fq` queueing discipline on an interface for paced uploads, and
//! removes it again, with iproute2's `tc`.

use std::process::Command;

fn tc(args: &[&str]) -> Option<String> {
    let output = Command::new("tc").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The kind of an interface's root queueing discipline, e.g. `fq_codel`.
pub fn root_kind(interface: &str) -> Option<String> {
    let shown = tc(&["qdisc", "show", "dev", interface, "root"])?;
    kind(&shown)
}

/// The kind in `tc qdisc show` output: `qdisc fq_codel 0: root ...`.
fn kind(shown: &str) -> Option<String> {
    let mut words = shown.split_whitespace();
    (words.next()? == "qdisc").then(|| words.next().map(str::to_string))?
}

/// Make `fq` the root queueing discipline. Returns true if this replaced
/// another one, so it should be removed later; false if `fq` was already
/// there or `tc` failed.
pub fn install_fq(interface: &str) -> bool {
    if root_kind(interface).as_deref() == Some("fq") {
        return false;
    }
    tc(&["qdisc", "replace", "dev", interface, "root", "fq"]).is_some()
}

/// Remove the root queueing discipline, so the kernel's default for the
/// interface applies again.
pub fn restore(interface: &str) {
    let _ = tc(&["qdisc", "del", "dev", interface, "root"]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_kind() {
        assert_eq!(
            kind("qdisc fq_codel 0: root refcnt 2 limit 10240p").as_deref(),
            Some("fq_codel")
        );
        assert_eq!(
            kind("qdisc fq 8001: root refcnt 2 limit 10000p").as_deref(),
            Some("fq")
        );
        assert_eq!(
            kind("qdisc noqueue 0: root refcnt 2").as_deref(),
            Some("noqueue")
        );
        assert_eq!(kind(""), None);
    }
}
