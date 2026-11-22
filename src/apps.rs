//! Names cgroups after the apps and services systemd runs in them.
//!
//! Desktops start each app in its own transient unit, named as the XDG
//! standard describes: `app[-<launcher>]-<ApplicationID>-<RANDOM>.scope` or
//! `app[-<launcher>]-<ApplicationID>[@<RANDOM>].service`, with dashes inside
//! the application ID escaped as `\x2d`. System services are `<name>.service`.

use serde::Serialize;
use std::{
    collections::HashMap,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A desktop app; `id` is its application ID (desktop file name).
    App,
    /// A systemd service; `id` is the unit name without `.service`.
    Service,
    /// Anything else, such as a login session; `id` is the unit name.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Unit {
    pub id: String,
    pub kind: Kind,
    /// The cgroup's directory name, e.g. `app-gnome-org.mozilla.firefox-9848.scope`.
    pub unit: String,
}

/// Undo systemd's `\xNN` escaping.
fn unescape(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1] == b'x'
            && let Ok(byte) = u8::from_str_radix(&text[i + 2..i + 4], 16)
        {
            out.push(byte);
            i += 4;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Name the unit a cgroup directory stands for.
pub fn classify(name: &str) -> Unit {
    let unit = name.to_string();
    let (stem, scope) = if let Some(stem) = name.strip_suffix(".scope") {
        (stem, true)
    } else if let Some(stem) = name.strip_suffix(".service") {
        (stem, false)
    } else {
        return Unit {
            id: unescape(name),
            kind: Kind::Other,
            unit,
        };
    };

    if let Some(rest) = stem.strip_prefix("app-") {
        // Dashes in the ID are escaped, so splitting on them is safe.
        let mut parts: Vec<&str> = rest.split('-').collect();
        if scope && parts.len() >= 2 {
            parts.pop(); // -<RANDOM>
        }
        let id = if parts.len() >= 2 {
            parts[parts.len() - 1]
        } else {
            parts[0]
        };
        let id = id.split('@').next().unwrap_or(id);
        return Unit {
            id: unescape(id),
            kind: Kind::App,
            unit,
        };
    }
    if let Some(rest) = stem.strip_prefix("dbus-") {
        // D-Bus activated: dbus-<bus name>-<ApplicationID>@<RANDOM>.service
        if let Some((_, id)) = rest.split_once('-') {
            let id = id.split('@').next().unwrap_or(id);
            return Unit {
                id: unescape(id),
                kind: Kind::App,
                unit,
            };
        }
    }
    if scope {
        return Unit {
            id: unescape(stem),
            kind: Kind::Other,
            unit,
        };
    }
    let id = stem.split('@').next().unwrap_or(stem);
    Unit {
        id: unescape(id),
        kind: Kind::Service,
        unit,
    }
}

/// A cgroup netleash reports traffic for.
#[derive(Debug, Clone)]
pub struct Cgroup {
    pub path: PathBuf,
    pub unit: Unit,
}

impl Cgroup {
    /// Names of the processes in the cgroup, most frequent first.
    pub fn processes(&self) -> Vec<String> {
        let Ok(pids) = fs::read_to_string(self.path.join("cgroup.procs")) else {
            return Vec::new();
        };
        let mut counts: HashMap<String, usize> = HashMap::new();
        for pid in pids.lines() {
            if let Ok(comm) = fs::read_to_string(format!("/proc/{pid}/comm")) {
                *counts.entry(comm.trim().to_string()).or_default() += 1;
            }
        }
        let mut names: Vec<(String, usize)> = counts.into_iter().collect();
        names.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        names.into_iter().map(|(name, _)| name).collect()
    }
}

/// Every cgroup from `root` down, by cgroup id (its directory's inode
/// number). The root itself is systemd's `-.slice`; processes sit there in
/// containers and before systemd moves them.
pub fn scan(root: &Path) -> HashMap<u64, Cgroup> {
    let mut found = HashMap::new();
    if let Ok(meta) = fs::metadata(root) {
        found.insert(
            meta.ino(),
            Cgroup {
                path: root.to_path_buf(),
                unit: classify("-.slice"),
            },
        );
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_dir() {
                continue;
            }
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            found.insert(
                meta.ino(),
                Cgroup {
                    path: path.clone(),
                    unit: classify(&name),
                },
            );
            stack.push(path);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(name: &str) -> (String, Kind) {
        let unit = classify(name);
        (unit.id, unit.kind)
    }

    #[test]
    fn app_scopes_with_and_without_launcher() {
        assert_eq!(
            id("app-gnome-org.mozilla.firefox-9848.scope"),
            ("org.mozilla.firefox".into(), Kind::App)
        );
        assert_eq!(
            id("app-com.anthropic.Claude-9687.scope"),
            ("com.anthropic.Claude".into(), Kind::App)
        );
        assert_eq!(
            id("app-flatpak-com.valvesoftware.Steam-2345.scope"),
            ("com.valvesoftware.Steam".into(), Kind::App)
        );
        assert_eq!(
            id("app-gnome-firefox-12.scope"),
            ("firefox".into(), Kind::App)
        );
    }

    #[test]
    fn escaped_dashes_stay_in_the_id() {
        assert_eq!(
            id(r"app-gnome-gnome\x2dterminal-77.scope"),
            ("gnome-terminal".into(), Kind::App)
        );
    }

    #[test]
    fn app_services_and_dbus_activation() {
        assert_eq!(
            id("app-gnome-org.gnome.Evolution@a1b2.service"),
            ("org.gnome.Evolution".into(), Kind::App)
        );
        assert_eq!(
            id("dbus-:1.21-org.a11y.atspi.Registry@0.service"),
            ("org.a11y.atspi.Registry".into(), Kind::App)
        );
    }

    #[test]
    fn system_services_and_other_units() {
        assert_eq!(
            id("NetworkManager.service"),
            ("NetworkManager".into(), Kind::Service)
        );
        assert_eq!(id("getty@tty1.service"), ("getty".into(), Kind::Service));
        assert_eq!(id("session-2.scope"), ("session-2".into(), Kind::Other));
        assert_eq!(
            id(r"app-gnome\x2dsession\x2dmanager.slice"),
            (r"app-gnome-session-manager.slice".into(), Kind::Other)
        );
    }

    #[test]
    fn scan_finds_this_process_cgroup() {
        let own = fs::read_to_string("/proc/self/cgroup").unwrap();
        let relative = own.trim().trim_start_matches("0::/");
        let path = Path::new(CGROUP_ROOT).join(relative);
        let ino = fs::metadata(&path).unwrap().ino();
        let found = scan(Path::new(CGROUP_ROOT));
        let cgroup = found.get(&ino).expect("own cgroup is found");
        assert_eq!(cgroup.path, path);
        assert!(!cgroup.processes().is_empty());
    }
}
