//! Talos EPP **agent service** — the always-on host for protection.
//!
//! It loads the detection engine, runs the real-time on-access monitor (with
//! auto-quarantine) and the ransomware-canary guard, and exposes a local IPC
//! channel so the GUI and CLI can drive it as thin clients.
//!
//! `talos-agent run` runs it in the foreground (and is the body a Windows
//! service control handler will invoke). `talos-agent status` queries a running
//! instance.

mod core;
mod daemon;
mod embedded;
mod paths;

use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use talos_ipc::proto::{Request, Response};

#[derive(Parser, Debug)]
#[command(
    name = "talos-agent",
    version,
    about = "Talos EPP — endpoint protection agent service"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the agent in the foreground (default).
    Run,
    /// Query a running agent and print its protection status.
    Status,
    /// Print the running agent's recent activity events.
    Events,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command.unwrap_or(Command::Run) {
        Command::Run => daemon::run(),
        Command::Status => cmd_status(),
        Command::Events => cmd_events(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

/// Connect to the running agent over IPC and print a status summary.
fn cmd_status() -> Result<()> {
    let Some(endpoint) = paths::read_endpoint() else {
        anyhow::bail!("no running agent found (start one with `talos-agent run`)");
    };
    match talos_ipc::client::call(&endpoint, Request::GetStatus) {
        Ok(Response::Status(s)) => {
            println!("Talos agent v{}", s.version);
            println!("  real-time : {}", if s.realtime { "on" } else { "off" });
            println!("  firewall  : {}", if s.firewall { "on" } else { "off" });
            println!(
                "  signatures: {} hashes, {} YARA files",
                s.hash_signatures, s.yara_files
            );
            println!("  quarantine: {} item(s)", s.quarantined);
            println!("  blocked   : {} threat(s) since start", s.threats_blocked);
            println!("  uptime    : {}s", s.uptime_secs);
            Ok(())
        }
        Ok(Response::Error { message }) => anyhow::bail!("agent error: {message}"),
        Ok(other) => anyhow::bail!("unexpected response: {other:?}"),
        Err(e) => anyhow::bail!("could not reach the agent: {e}"),
    }
}

/// Connect to the running agent and print its recent activity events.
fn cmd_events() -> Result<()> {
    let Some(endpoint) = paths::read_endpoint() else {
        anyhow::bail!("no running agent found (start one with `talos-agent run`)");
    };
    match talos_ipc::client::call(&endpoint, Request::GetEvents { since: 0 }) {
        Ok(Response::Events { events, .. }) => {
            if events.is_empty() {
                println!("(no events yet)");
            }
            for e in events {
                let path = e.path.map(|p| format!("  {p}")).unwrap_or_default();
                println!("[{:>10}] {:<10} {}{}", e.seq, e.severity, e.message, path);
            }
            Ok(())
        }
        Ok(Response::Error { message }) => anyhow::bail!("agent error: {message}"),
        Ok(other) => anyhow::bail!("unexpected response: {other:?}"),
        Err(e) => anyhow::bail!("could not reach the agent: {e}"),
    }
}
