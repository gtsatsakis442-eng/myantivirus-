//! Thin client to the **Talos agent service** (`talos-agent`). When the agent is
//! running, the CLI drives it over local IPC instead of spinning up its own
//! engine — the same role the GUI plays.

use std::path::PathBuf;

use anyhow::Result;
use talos_ipc::proto::{Request, Response};

use crate::paths;

/// Read the endpoint the running agent published (`<data>/agent.endpoint`).
fn endpoint() -> Result<talos_ipc::EndpointInfo> {
    let path = paths::data_dir().join("agent.endpoint");
    let text = std::fs::read_to_string(&path)
        .map_err(|_| anyhow::anyhow!("no running agent found (start it with `talos-agent run`)"))?;
    let info = serde_json::from_str(&text)?;
    Ok(info)
}

fn call(request: Request) -> Result<Response> {
    let endpoint = endpoint()?;
    talos_ipc::client::call(&endpoint, request)
        .map_err(|e| anyhow::anyhow!("could not reach the agent: {e}"))
}

/// `talos agent status` — print the live protection status from the service.
pub fn status() -> Result<()> {
    match call(Request::GetStatus)? {
        Response::Status(s) => {
            println!("Talos agent v{}", s.version);
            println!("  real-time : {}", on_off(s.realtime));
            println!("  firewall  : {}", on_off(s.firewall));
            println!(
                "  signatures: {} hashes, {} YARA files",
                s.hash_signatures, s.yara_files
            );
            println!("  quarantine: {} item(s)", s.quarantined);
            println!("  blocked   : {} threat(s) since start", s.threats_blocked);
            println!("  uptime    : {}s", s.uptime_secs);
            Ok(())
        }
        other => unexpected(other),
    }
}

/// `talos agent events` — print the agent's recent activity log.
pub fn events() -> Result<()> {
    match call(Request::GetEvents { since: 0 })? {
        Response::Events { events, .. } => {
            if events.is_empty() {
                println!("(no events yet)");
            }
            for e in events {
                let path = e.path.map(|p| format!("  {p}")).unwrap_or_default();
                println!("[{:>6}] {:<10} {}{}", e.seq, e.severity, e.message, path);
            }
            Ok(())
        }
        other => unexpected(other),
    }
}

/// `talos agent scan [paths...]` — ask the service to run a background scan.
pub fn scan(paths: Vec<PathBuf>, quarantine: bool) -> Result<()> {
    let paths = paths.iter().map(|p| p.display().to_string()).collect();
    match call(Request::StartScan { paths, quarantine })? {
        Response::ScanStarted { scan_id } => {
            println!("scan #{scan_id} started; follow it with `talos agent events`");
            Ok(())
        }
        other => unexpected(other),
    }
}

/// `talos agent firewall sync|flush|block <ip>` — manage OS-firewall rules via
/// the privileged agent service.
pub fn firewall_sync() -> Result<()> {
    match call(Request::SetFirewall { on: true })? {
        Response::Ack => {
            println!("requested C2 blocklist sync; follow `talos agent events`");
            Ok(())
        }
        other => unexpected(other),
    }
}

pub fn firewall_flush() -> Result<()> {
    match call(Request::SetFirewall { on: false })? {
        Response::Ack => {
            println!("requested removal of all Talos firewall rules");
            Ok(())
        }
        other => unexpected(other),
    }
}

pub fn firewall_block(ip: String) -> Result<()> {
    match call(Request::FirewallBlock { ip: ip.clone() })? {
        Response::Ack => {
            println!("requested block of outbound {ip}; follow `talos agent events`");
            Ok(())
        }
        other => unexpected(other),
    }
}

fn on_off(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

fn unexpected(resp: Response) -> Result<()> {
    match resp {
        Response::Error { message } => anyhow::bail!("agent error: {message}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}
