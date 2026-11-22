//! The helper as a system D-Bus service, and the unprivileged client that
//! bridges it to the JSON-lines protocol on stdin/stdout.
//!
//! The service runs as root (started by D-Bus activation through systemd)
//! and owns `io.github.sigmasd.Bandito.Helper`. Its one method, `Command`,
//! takes a protocol command as JSON; polkit decides whether the caller may
//! run it. Once a second it emits the `Sample` signal with a protocol
//! `sample` event as JSON. When the last client that sent a command leaves
//! the bus, its limits are removed, and the service exits after a minute
//! without clients (D-Bus starts it again on the next call).
//!
//! The client (`bandito-helper --client`) runs as the user: it forwards
//! stdin lines to `Command` and prints `Sample` signals, so Bandito talks to
//! it exactly as it talks to the helper run through pkexec, without a
//! password at every start.

use crate::{
    Helper, emit, load,
    protocol::{Command, Event},
};
use anyhow::{Context, Result};
use std::{
    collections::{HashMap, HashSet},
    io::{self, BufRead},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use zbus::{
    blocking,
    fdo,
    message::Header,
    zvariant::Value,
};

pub const BUS_NAME: &str = "io.github.sigmasd.Bandito.Helper";
pub const PATH: &str = "/io/github/sigmasd/Bandito/Helper";
pub const INTERFACE: &str = "io.github.sigmasd.Bandito.Helper1";
/// The polkit action that guards every command.
pub const ACTION: &str = "io.github.sigmasd.Bandito.Helper.configure";
/// How long the service waits without clients before it exits.
const IDLE_EXIT: Duration = Duration::from_secs(60);

/// Clients that have sent commands, by unique bus name.
#[derive(Default)]
struct Clients {
    names: HashSet<String>,
    /// When the last client left; None while there are clients.
    empty_since: Option<Instant>,
}

struct Service {
    helper: Arc<Mutex<Helper>>,
    clients: Arc<Mutex<Clients>>,
    polkit: bool,
}

/// Ask polkit whether a bus client may change Bandito's settings, letting
/// polkit ask the user to authenticate when its policy says so.
async fn authorized(connection: &zbus::Connection, sender: &str) -> fdo::Result<bool> {
    let authority = zbus::Proxy::new(
        connection,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority",
    )
    .await?;
    let subject = (
        "system-bus-name",
        HashMap::from([("name", Value::from(sender))]),
    );
    const ALLOW_USER_INTERACTION: u32 = 1;
    let (allowed, _challenge, _details): (bool, bool, HashMap<String, String>) = authority
        .call(
            "CheckAuthorization",
            &(
                subject,
                ACTION,
                HashMap::<&str, &str>::new(),
                ALLOW_USER_INTERACTION,
                "",
            ),
        )
        .await?;
    Ok(allowed)
}

#[zbus::interface(name = "io.github.sigmasd.Bandito.Helper1")]
impl Service {
    /// Run one protocol command, given as JSON: `interface` or `limit`.
    async fn command(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        json: String,
    ) -> fdo::Result<()> {
        let sender = header
            .sender()
            .ok_or_else(|| fdo::Error::AccessDenied("no sender".into()))?
            .to_string();
        let command: Command = serde_json::from_str(&json)
            .map_err(|e| fdo::Error::InvalidArgs(format!("bad command: {e}")))?;
        if matches!(command, Command::Stop) {
            return Ok(());
        }
        if self.polkit && !authorized(connection, &sender).await? {
            return Err(fdo::Error::AccessDenied(
                "not authorized to change Bandito's network settings".into(),
            ));
        }
        {
            let mut clients = self.clients.lock().unwrap();
            clients.names.insert(sender);
            clients.empty_since = None;
        }
        self.helper
            .lock()
            .unwrap()
            .command(command)
            .map(|_| ())
            .map_err(|e| fdo::Error::Failed(format!("{e:#}")))
    }

    /// The helper's version.
    #[zbus(property)]
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
}

/// Run as the system service.
pub fn serve(polkit: bool) -> Result<()> {
    let (_bpf, maps) = load()?;
    let helper = Arc::new(Mutex::new(Helper::new(maps)?));
    let clients = Arc::new(Mutex::new(Clients {
        empty_since: Some(Instant::now()),
        ..Clients::default()
    }));
    let service = Service { helper: Arc::clone(&helper), clients: Arc::clone(&clients), polkit };
    let connection = blocking::connection::Builder::system()?
        .name(BUS_NAME)?
        .serve_at(PATH, service)?
        .build()
        .context("taking the bus name")?;

    // Drop a client's limits when it leaves the bus.
    {
        let connection = connection.clone();
        let helper = Arc::clone(&helper);
        let clients = Arc::clone(&clients);
        thread::spawn(move || -> Result<()> {
            let bus = blocking::fdo::DBusProxy::new(&connection)?;
            for change in bus.receive_name_owner_changed()? {
                let args = change.args()?;
                if args.new_owner().is_some() {
                    continue;
                }
                let mut clients = clients.lock().unwrap();
                if clients.names.remove(args.name().as_str()) && clients.names.is_empty() {
                    clients.empty_since = Some(Instant::now());
                    helper.lock().unwrap().clear_limits();
                }
            }
            Ok(())
        });
    }

    loop {
        thread::sleep(Duration::from_secs(1));
        let sample = helper.lock().unwrap().sample();
        let json = serde_json::to_string(&Event::Sample(sample))?;
        connection.emit_signal(None::<()>, PATH, INTERFACE, "Sample", &(json,))?;
        if clients
            .lock()
            .unwrap()
            .empty_since
            .is_some_and(|since| since.elapsed() > IDLE_EXIT)
        {
            // Dropping the eBPF object detaches the programs.
            return Ok(());
        }
    }
}

/// Bridge stdin/stdout to the service, as the user.
pub fn client() -> Result<()> {
    let connection = blocking::Connection::system().context("connecting to the system bus")?;
    let proxy = blocking::Proxy::new(&connection, BUS_NAME, PATH, INTERFACE)?;
    // Starts the service through D-Bus activation if it isn't running.
    let version: String = proxy
        .get_property("Version")
        .context("reaching bandito-helper's service; is it installed?")?;
    let samples = proxy.receive_signal("Sample")?;

    let commands = proxy.clone();
    thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            if line.contains(r#""stop""#) {
                break;
            }
            if let Err(error) = commands.call_method("Command", &(line,)) {
                let message = match error {
                    zbus::Error::MethodError(_, Some(message), _) => message,
                    other => other.to_string(),
                };
                emit(&Event::Error { message });
            }
        }
        emit(&Event::Stopped);
        // Leaving the bus makes the service drop this client's limits.
        std::process::exit(0);
    });

    emit(&Event::Ready { version });
    for signal in samples {
        let (json,): (String,) = signal.body().deserialize()?;
        println!("{json}");
    }
    Ok(())
}
