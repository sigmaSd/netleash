//! `netleash --install` / `--uninstall`: put this binary and its D-Bus,
//! systemd and polkit files in place, so the service starts on demand. The
//! files are embedded, so a `cargo install`ed binary is all it needs.

use anyhow::{Context, Result, bail};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

const BINARY: &str = "bin/netleash";

/// Files installed under the prefix, with their contents.
const FILES: &[(&str, &str)] = &[
    (
        "share/dbus-1/system.d/io.github.sigmasd.Netleash.conf",
        include_str!("../dist/io.github.sigmasd.Netleash.conf"),
    ),
    (
        "share/dbus-1/system-services/io.github.sigmasd.Netleash.service",
        include_str!("../dist/io.github.sigmasd.Netleash.service"),
    ),
    (
        "lib/systemd/system/netleash.service",
        include_str!("../dist/netleash.service"),
    ),
    (
        "share/polkit-1/actions/io.github.sigmasd.Netleash.policy",
        include_str!("../dist/io.github.sigmasd.Netleash.policy"),
    ),
];

/// The dist files name /usr/bin/netleash; elsewhere, point them at the prefix.
fn contents(prefix: &Path, text: &str) -> String {
    text.replace("/usr/bin/netleash", &prefix.join(BINARY).to_string_lossy())
}

fn reload() {
    let _ = Command::new("systemctl").arg("daemon-reload").status();
    let _ = Command::new("busctl")
        .args([
            "call",
            "org.freedesktop.DBus",
            "/",
            "org.freedesktop.DBus",
            "ReloadConfig",
        ])
        .status();
}

fn require_root() -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("run this as root, e.g. with sudo");
    }
    Ok(())
}

pub fn install(prefix: &Path) -> Result<()> {
    require_root()?;
    let binary = prefix.join(BINARY);
    let current = std::env::current_exe()?;
    if current != binary {
        fs::create_dir_all(binary.parent().unwrap())?;
        // Copy to a temporary name first: the target may be running.
        let temporary = binary.with_extension("new");
        fs::copy(&current, &temporary)
            .with_context(|| format!("copying to {}", binary.display()))?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755))?;
        fs::rename(&temporary, &binary)?;
    }
    for (path, text) in FILES {
        let path = prefix.join(path);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(&path, contents(prefix, text))
            .with_context(|| format!("writing {}", path.display()))?;
    }
    reload();
    println!(
        "Installed {} and its D-Bus service. Front ends such as Bandito use it from their next start.",
        binary.display()
    );
    Ok(())
}

pub fn uninstall(prefix: &Path) -> Result<()> {
    require_root()?;
    for path in FILES.iter().map(|(path, _)| *path).chain([BINARY]) {
        let path = prefix.join(path);
        match fs::remove_file(&path) {
            Ok(()) => println!("Removed {}", path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", path.display())),
        }
    }
    reload();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_name_the_installed_binary() {
        for (path, text) in FILES {
            if path.ends_with(".service") {
                assert!(text.contains("/usr/bin/netleash --dbus"), "{path}");
            }
        }
        let moved = contents(Path::new("/usr/local"), FILES[1].1);
        assert!(moved.contains("Exec=/usr/local/bin/netleash --dbus"));
    }
}
