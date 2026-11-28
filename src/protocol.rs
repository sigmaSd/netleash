//! The JSON-lines protocol on stdin and stdout.
//!
//! Commands, one JSON object per line on stdin:
//!
//! ```json
//! {"cmd": "interface", "name": "wlan0"}
//! {"cmd": "limit", "app": "org.mozilla.firefox", "down": 2500000, "up": null}
//! {"cmd": "limit", "app": null, "down": 10000000, "up": 1000000}
//! {"cmd": "stop"}
//! ```
//!
//! `app` is an app or service id as reported in samples; `null` limits every
//! app together. Rates are bytes per second; `null` removes the limit.
//!
//! Events, one JSON object per line on stdout: `ready`, `sample` (once a
//! second), `error` and `stopped`.

use crate::apps::Kind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, PartialEq)]
#[serde(tag = "cmd", rename_all = "lowercase")]
pub enum Command {
    Interface {
        name: String,
    },
    Limit {
        app: Option<String>,
        down: Option<u64>,
        up: Option<u64>,
    },
    Stop,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Event {
    Ready { version: String },
    Sample(Sample),
    Error { message: String },
    Stopped,
}

#[derive(Debug, Serialize, Default)]
pub struct Rates {
    /// Bytes per second received.
    pub rx: u64,
    /// Bytes per second sent.
    pub tx: u64,
}

#[derive(Debug, Serialize)]
pub struct App {
    pub id: String,
    pub kind: Kind,
    /// systemd units the app runs in, e.g. `app-gnome-org.mozilla.firefox-9848.scope`.
    pub units: Vec<String>,
    /// Process names in those units, most frequent first.
    pub processes: Vec<String>,
    /// The app's traffic by the process that created each socket, busiest
    /// first. Traffic of sockets whose creator netleash didn't see (opened
    /// before it started, or accepted from a listening socket) is in the
    /// app's totals only.
    #[serde(rename = "processTraffic")]
    pub process_traffic: Vec<ProcessTraffic>,
    #[serde(flatten)]
    pub rates: Rates,
    /// Limits currently applied, in bytes per second.
    #[serde(rename = "limitDown", skip_serializing_if = "Option::is_none")]
    pub limit_down: Option<u64>,
    #[serde(rename = "limitUp", skip_serializing_if = "Option::is_none")]
    pub limit_up: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ProcessTraffic {
    pub pid: u32,
    /// The process's name (`/proc/<pid>/comm`), or once it has exited, the
    /// name of the thread that created its last socket.
    pub name: String,
    #[serde(flatten)]
    pub rates: Rates,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Connection {
    pub app: String,
    pub protocol: &'static str,
    pub remote: String,
    pub host: Option<String>,
    pub remote_port: u16,
    pub local_port: u16,
    #[serde(flatten)]
    pub rates: Rates,
}

#[derive(Debug, Serialize)]
pub struct Sample {
    pub interface: Option<String>,
    /// Everything on the interface, including traffic no local socket owns.
    pub total: Rates,
    pub apps: Vec<App>,
    pub connections: Vec<Connection>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_commands() {
        let parse = |s: &str| serde_json::from_str::<Command>(s).unwrap();
        assert_eq!(
            parse(r#"{"cmd":"interface","name":"wlan0"}"#),
            Command::Interface {
                name: "wlan0".into()
            }
        );
        assert_eq!(
            parse(r#"{"cmd":"limit","app":"steam","down":2500000,"up":null}"#),
            Command::Limit {
                app: Some("steam".into()),
                down: Some(2_500_000),
                up: None
            }
        );
        assert_eq!(
            parse(r#"{"cmd":"limit","app":null,"down":null,"up":1000}"#),
            Command::Limit {
                app: None,
                down: None,
                up: Some(1000)
            }
        );
        assert_eq!(parse(r#"{"cmd":"stop"}"#), Command::Stop);
        assert!(serde_json::from_str::<Command>(r#"{"cmd":"nope"}"#).is_err());
    }

    #[test]
    fn writes_events() {
        let app = App {
            id: "org.mozilla.firefox".into(),
            kind: Kind::App,
            units: vec!["app-gnome-org.mozilla.firefox-1.scope".into()],
            processes: vec!["firefox".into()],
            process_traffic: vec![ProcessTraffic {
                pid: 4242,
                name: "firefox".into(),
                rates: Rates { rx: 9, tx: 2 },
            }],
            rates: Rates { rx: 10, tx: 2 },
            limit_down: Some(100),
            limit_up: None,
        };
        let json = serde_json::to_string(&Event::Sample(Sample {
            interface: Some("wlan0".into()),
            total: Rates { rx: 12, tx: 3 },
            apps: vec![app],
            connections: vec![],
        }))
        .unwrap();
        assert_eq!(
            json,
            r#"{"type":"sample","interface":"wlan0","total":{"rx":12,"tx":3},"apps":[{"id":"org.mozilla.firefox","kind":"app","units":["app-gnome-org.mozilla.firefox-1.scope"],"processes":["firefox"],"processTraffic":[{"pid":4242,"name":"firefox","rx":9,"tx":2}],"rx":10,"tx":2,"limitDown":100}],"connections":[]}"#
        );
    }
}
