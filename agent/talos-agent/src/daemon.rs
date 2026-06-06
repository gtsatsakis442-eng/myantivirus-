//! The foreground daemon: load the engine, start the real-time monitor and the
//! ransomware-canary guard, publish the IPC endpoint, and serve client requests.
//!
//! On Windows this same body is what the (forthcoming) service control handler
//! runs; today it is launched directly with `talos-agent run`.

use std::sync::mpsc::RecvTimeoutError;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use scanner_core::{ransom_guard, realtime, Scanner};
use talos_ipc::frame::{read_msg, write_msg};
use talos_ipc::transport::bind_loopback;
use talos_ipc::{EndpointInfo, Envelope, Response};

use crate::core::Shared;

/// Build state, start the worker threads, and run the IPC accept loop until a
/// `Shutdown` request arrives (or the process is terminated).
pub fn run() -> Result<()> {
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
    let (listener, port) = bind_loopback().context("binding the agent IPC socket")?;
    crate::paths::write_endpoint(&EndpointInfo {
        port,
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
    ));

    eprintln!(
        "talos-agent {} — {hash_count} hash signature(s), {yara_files} YARA file(s); IPC on 127.0.0.1:{port}",
        env!("CARGO_PKG_VERSION")
    );

    let realtime = spawn_realtime(Arc::clone(&shared));
    let canaries = spawn_canaries(Arc::clone(&shared));

    serve(&listener, &shared);

    // A Shutdown request broke the accept loop; let the workers wind down.
    crate::paths::remove_endpoint();
    let _ = realtime.join();
    let _ = canaries.join();
    Ok(())
}

/// IPC accept loop: one authenticated request/response per connection.
fn serve(listener: &std::net::TcpListener, shared: &Arc<Shared>) {
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let envelope: Envelope = match read_msg(&mut stream) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let response = if envelope.token != shared.token() {
            Response::Error {
                message: "unauthorized".to_string(),
            }
        } else {
            shared.handle(envelope.request)
        };
        let _ = write_msg(&mut stream, &response);
        if shared.shutdown_requested() {
            break;
        }
    }
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
