//! Read-only link to the Talos **agent service** (if installed/running): find
//! the endpoint file it publishes and query its status over IPC. The GUI shows
//! the service state; it still runs its own embedded engine for on-demand work.
//!
//! The query runs on a background thread (like the other async actions) so the
//! UI never blocks on the socket.

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};

use talos_ipc::proto::{Request, Response};
use talos_ipc::{EndpointInfo, Status};

/// Per-machine data directory where the agent publishes its endpoint file —
/// mirrors `talos-agent`'s own path resolution.
fn data_dir() -> PathBuf {
    if let Ok(pd) = std::env::var("PROGRAMDATA") {
        return PathBuf::from(pd).join("Talos EPP");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("talos-epp");
    }
    std::env::temp_dir().join("talos-epp")
}

fn read_endpoint() -> Option<EndpointInfo> {
    let text = std::fs::read_to_string(data_dir().join("agent.endpoint")).ok()?;
    serde_json::from_str(&text).ok()
}

/// Query the running agent's status synchronously; `None` if unreachable.
fn query() -> Option<Status> {
    let endpoint = read_endpoint()?;
    match talos_ipc::client::call(&endpoint, Request::GetStatus).ok()? {
        Response::Status(status) => Some(status),
        _ => None,
    }
}

/// Start a one-shot status poll on a background thread; the result (`Some` if an
/// agent answered, else `None`) arrives on the returned channel.
pub fn start_poll() -> Receiver<Option<Status>> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let _ = tx.send(query());
    });
    rx
}

/// Fire-and-forget: ask the running agent to turn its real-time monitor on or
/// off. The next status poll reflects the change.
pub fn set_realtime(on: bool) {
    std::thread::spawn(move || {
        if let Some(endpoint) = read_endpoint() {
            let _ = talos_ipc::client::call(&endpoint, Request::SetRealtime { on });
        }
    });
}
