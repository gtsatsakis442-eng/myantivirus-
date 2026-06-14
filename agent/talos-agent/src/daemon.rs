//! The foreground daemon: load the engine, start the real-time monitor and the
//! ransomware-canary guard, publish the IPC endpoint, and serve client requests.
//!
//! On Windows this same body is what the (forthcoming) service control handler
//! runs; today it is launched directly with `talos-agent run`.

use std::sync::atomic::AtomicBool;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use scanner_core::{ransom_guard, realtime, Scanner};
use talos_ipc::frame::{read_msg, write_msg};
use talos_ipc::transport::{accept, bind};
use talos_ipc::{EndpointInfo, Envelope, Listener, Request, Response, Stream};

use crate::core::Shared;

/// Build state, start the worker threads, and run the IPC accept loop until the
/// shared `stop` flag is set — by a `Shutdown` IPC request, the Windows Service
/// control handler, or process termination.
pub fn run(stop: Arc<AtomicBool>) -> Result<()> {
    let (engine, hash_count, yara_files, _skipped) = scanner_core::bootstrap::load_engine(
        crate::embedded::HASHDB,
        crate::embedded::YARA_RULES,
        &crate::paths::store_dir(),
        None,
        None,
        false,
    )
    .context("loading detection engine")?;

    let roots = crate::paths::quick_scan_paths();
    let token = crate::paths::generate_token();
    let name = crate::paths::endpoint_name();
    let (listener, resolved_name) = bind(&name).context("binding the agent IPC socket")?;
    crate::paths::write_endpoint(&EndpointInfo {
        name: resolved_name,
        token: token.clone(),
    })
    .context("publishing the agent endpoint")?;

    let shared = Arc::new(Shared::new(
        Arc::new(engine),
        roots,
        crate::paths::default_quarantine_dir(),
        token,
        hash_count,
        yara_files,
        stop,
    ));

    eprintln!(
        "talos-agent {} — {hash_count} hash signature(s), {yara_files} YARA file(s); IPC at {name}",
        env!("CARGO_PKG_VERSION")
    );

    let realtime = spawn_realtime(Arc::clone(&shared));
    let canaries = spawn_canaries(Arc::clone(&shared));
    let scheduler = spawn_scheduler(Arc::clone(&shared));

    // Bring network protection up at boot so the endpoint is defended without a
    // client ever connecting (config-gated; both default ON).
    spawn_autostart(Arc::clone(&shared));

    serve(&listener, &shared);

    // A Shutdown request broke the accept loop; let the workers wind down.
    crate::paths::remove_endpoint();
    let _ = realtime.join();
    let _ = canaries.join();
    let _ = scheduler.join();
    Ok(())
}

/// IPC accept loop: non-blocking accept so it exits promptly once `shutdown` is
/// set, with one short-lived thread per connection (so a slow/stuck client can't
/// stall the loop, and well-behaved clients are served concurrently).
fn serve(listener: &Listener, shared: &Arc<Shared>) {
    while !shared.shutdown_requested() {
        match accept(listener) {
            Ok(Some(stream)) => {
                let shared = Arc::clone(shared);
                thread::spawn(move || handle_conn(stream, shared));
            }
            Ok(None) | Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

/// Authenticate and answer one client connection.
fn handle_conn(mut stream: Stream, shared: Arc<Shared>) {
    let envelope: Envelope = match read_msg(&mut stream) {
        Ok(e) => e,
        Err(_) => return,
    };
    let response = if !talos_ipc::token_matches(shared.token(), &envelope.token) {
        Response::Error {
            message: "unauthorized".to_string(),
        }
    } else {
        shared.handle(envelope.request)
    };
    let _ = write_msg(&mut stream, &response);
}

/// Real-time on-access monitor: scan each created/changed file, auto-quarantine
/// malicious ones.
fn spawn_realtime(shared: Arc<Shared>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let watch = match realtime::watch(shared.roots()) {
            Ok(w) => w,
            Err(e) => {
                shared.push_event(
                    talos_ipc::proto::severity::ERROR,
                    format!("real-time monitor init failed: {e}"),
                    None,
                );
                return;
            }
        };
        let engine = shared.engine();
        let scanner = Scanner::new(engine.as_ref());
        shared.push_event(
            talos_ipc::proto::severity::INFO,
            format!(
                "real-time monitor watching {} location(s)",
                shared.roots().len()
            ),
            None,
        );
        while !shared.shutdown_requested() {
            match watch.rx.recv_timeout(Duration::from_millis(500)) {
                Ok(path) => {
                    if shared.realtime_enabled() && !ransom_guard::is_canary(&path) {
                        shared.on_realtime_report(scanner.scan_file(&path));
                    }
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    })
}

/// Scheduled-scan background thread: reads `<data>/config.json` once per
/// minute and fires a `StartScan` when the configured cadence has elapsed.
/// The last-fire timestamp is persisted to `<data>/scheduler.state` so a
/// system reboot does not reset the cadence — a missed scan fires within one
/// minute of the agent starting.
fn spawn_scheduler(shared: Arc<Shared>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        // Restore the previous fire time from disk (0 if first run).
        let mut last_fire_unix = read_scheduled_unix();
        loop {
            // Sleep in 1-second ticks so shutdown is always responsive.
            for _ in 0..60u32 {
                if shared.shutdown_requested() {
                    return;
                }
                thread::sleep(Duration::from_secs(1));
            }
            if shared.shutdown_requested() {
                return;
            }
            // Re-read config every minute so a schedule change takes effect
            // without restarting the agent.
            let interval = match read_schedule_secs() {
                Some(s) => s,
                None => continue, // Schedule::Off
            };
            let now = scheduler_unix_now();
            if now.saturating_sub(last_fire_unix) >= interval {
                shared.push_event(
                    talos_ipc::proto::severity::INFO,
                    "scheduled scan: starting".to_string(),
                    None,
                );
                let _ = shared.handle(Request::StartScan {
                    paths: vec![],
                    quarantine: true,
                });
                last_fire_unix = now;
                write_scheduled_unix(now);
            }
        }
    })
}

/// Turn on the firewall and web/domain protection at startup unless the user
/// has opted out in `<data>/config.json`. Both default ON so a fresh install is
/// protected immediately. The `SetFirewall`/`SetWebProtection` handlers each
/// spawn their own worker thread, so this returns promptly.
fn spawn_autostart(shared: Arc<Shared>) {
    if config_flag("firewall_autostart", true) {
        shared.push_event(
            talos_ipc::proto::severity::INFO,
            "autostart: enabling firewall (baseline + threat feeds)".to_string(),
            None,
        );
        let _ = shared.handle(Request::SetFirewall { on: true });
    }
    if config_flag("web_autostart", true) {
        shared.push_event(
            talos_ipc::proto::severity::INFO,
            "autostart: enabling web/domain protection".to_string(),
            None,
        );
        let _ = shared.handle(Request::SetWebProtection { on: true });
    }
}

/// Read a boolean flag from `<data>/config.json`, falling back to `default`
/// when the file or key is absent/unreadable.
fn config_flag(key: &str, default: bool) -> bool {
    let path = crate::paths::data_dir().join("config.json");
    let Ok(text) = std::fs::read_to_string(path) else {
        return default;
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) else {
        return default;
    };
    val.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

/// Parse the `schedule` field from `<data>/config.json`, returning the
/// interval in seconds, or `None` when the schedule is Off or unreadable.
fn read_schedule_secs() -> Option<u64> {
    let path = crate::paths::data_dir().join("config.json");
    let text = std::fs::read_to_string(path).ok()?;
    let val: serde_json::Value = serde_json::from_str(&text).ok()?;
    match val.get("schedule").and_then(|s| s.as_str()) {
        Some("Daily") => Some(24 * 3600),
        Some("Weekly") => Some(7 * 24 * 3600),
        _ => None,
    }
}

fn scheduler_unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn scheduled_state_path() -> std::path::PathBuf {
    crate::paths::data_dir().join("scheduler.state")
}

fn read_scheduled_unix() -> u64 {
    std::fs::read_to_string(scheduled_state_path())
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn write_scheduled_unix(unix: u64) {
    let _ = std::fs::write(scheduled_state_path(), unix.to_string());
}

/// Ransomware canary guard: plant decoys and alarm if any is tampered.
fn spawn_canaries(shared: Arc<Shared>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let canaries = ransom_guard::deploy(shared.roots());
        if canaries.is_empty() {
            shared.push_event(
                talos_ipc::proto::severity::INFO,
                "ransomware guard: no writable folders to protect".to_string(),
                None,
            );
            return;
        }
        shared.push_event(
            talos_ipc::proto::severity::INFO,
            format!(
                "ransomware guard: {} canary file(s) planted",
                canaries.len()
            ),
            None,
        );
        while !shared.shutdown_requested() {
            let tampered = ransom_guard::check(&canaries);
            if !tampered.is_empty() {
                shared.on_canary_tamper(&tampered);
                let _ = ransom_guard::deploy(shared.roots()); // restore the decoys
            }
            // Sleep in slices so shutdown stays responsive.
            for _ in 0..15 {
                if shared.shutdown_requested() {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
        ransom_guard::cleanup(&canaries);
    })
}
