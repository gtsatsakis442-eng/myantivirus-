//! Path resolution and the on-disk **endpoint file** that lets local clients
//! discover the running agent (loopback port + token).

use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use talos_ipc::EndpointInfo;

/// Per-machine data directory (definitions store, quarantine, agent endpoint).
pub fn data_dir() -> PathBuf {
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

/// Writable signatures store merged on top of the embedded baseline.
pub fn store_dir() -> PathBuf {
    data_dir().join("signatures")
}

/// Default quarantine vault.
pub fn default_quarantine_dir() -> PathBuf {
    data_dir().join("quarantine")
}

/// The file the agent writes so clients can find it: `<data>/agent.endpoint`.
pub fn endpoint_path() -> PathBuf {
    data_dir().join("agent.endpoint")
}

/// High-risk locations the agent watches/scans by default (existing paths only).
pub fn quick_scan_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if cfg!(windows) {
        push_env(&mut out, "USERPROFILE", &["Downloads"]);
        push_env(&mut out, "USERPROFILE", &["Desktop"]);
        push_env(&mut out, "TEMP", &[]);
        push_env(&mut out, "APPDATA", &[]);
        push_env(&mut out, "LOCALAPPDATA", &["Temp"]);
    } else {
        push_env(&mut out, "HOME", &["Downloads"]);
        push_env(&mut out, "HOME", &["Desktop"]);
        push_env(&mut out, "HOME", &[".cache"]);
        out.push(PathBuf::from("/tmp"));
    }
    out.retain(|p| p.exists());
    out.dedup();
    out
}

fn push_env(out: &mut Vec<PathBuf>, var: &str, sub: &[&str]) {
    if let Ok(base) = std::env::var(var) {
        let mut p = PathBuf::from(base);
        for s in sub {
            p.push(s);
        }
        out.push(p);
    }
}

/// Generate an unguessable per-session token for the loopback IPC channel.
///
/// This is a same-host shared secret kept in a private file (its confidentiality
/// comes from file permissions); the value just needs to be unpredictable to
/// other local users, so we derive it from high-resolution time, the pid, and an
/// ASLR-influenced stack address, hashed with SHA-256.
pub fn generate_token() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let probe = 0u8;
    let entropy = &probe as *const u8 as usize;
    let seed = format!("{nanos}:{pid}:{entropy}:talos-agent");
    scanner_core::hash_bytes(seed.as_bytes()).sha256
}

/// Persist the endpoint (port + token) for clients, with private permissions.
pub fn write_endpoint(info: &EndpointInfo) -> io::Result<()> {
    let path = endpoint_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string(info).map_err(io::Error::other)?;
    std::fs::write(&path, json)?;
    restrict_permissions(&path);
    Ok(())
}

/// Read the endpoint a running agent published; `None` if no agent is recorded.
pub fn read_endpoint() -> Option<EndpointInfo> {
    let text = std::fs::read_to_string(endpoint_path()).ok()?;
    serde_json::from_str(&text).ok()
}

/// Remove the endpoint file on shutdown (best effort).
pub fn remove_endpoint() {
    let _ = std::fs::remove_file(endpoint_path());
}

#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path) {
    // On Windows the file inherits ProgramData ACLs (admin-writable); tightening
    // to a SYSTEM/Administrators-only DACL is part of the named-pipe hardening.
}
