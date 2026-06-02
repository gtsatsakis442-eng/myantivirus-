//! Path resolution: where the installed app finds its content and stores data.

use std::path::PathBuf;

/// Per-machine data directory (writable definitions store, quarantine, logs).
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

/// Writable signatures store updated by the feed updater (`hashes/`, `yara/`).
/// The engine merges this on top of the built-in baseline.
pub fn store_dir() -> PathBuf {
    data_dir().join("signatures")
}

pub fn default_quarantine_dir() -> PathBuf {
    data_dir().join("quarantine")
}

/// High-risk locations for a Quick Scan (only existing paths are returned).
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

/// Root(s) for a Full Scan.
pub fn full_scan_roots() -> Vec<PathBuf> {
    if cfg!(windows) {
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        vec![PathBuf::from(format!("{drive}\\"))]
    } else {
        vec![PathBuf::from("/")]
    }
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
