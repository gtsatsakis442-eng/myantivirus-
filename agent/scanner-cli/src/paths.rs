//! Path resolution: where the installed app finds its content and stores data.

use std::path::PathBuf;

/// Directory containing the running executable, if determinable.
fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(PathBuf::from)
}

/// Base directory that holds the `signatures/` folder. Prefers the install
/// location (next to the exe); falls back to the current working directory.
fn content_base() -> PathBuf {
    if let Some(dir) = exe_dir() {
        if dir.join("signatures").is_dir() {
            return dir;
        }
    }
    PathBuf::from(".")
}

pub fn default_hashes() -> PathBuf {
    content_base()
        .join("signatures")
        .join("hashes")
        .join("baseline.hashdb")
}

pub fn default_rules() -> PathBuf {
    content_base().join("signatures").join("yara")
}

/// Per-machine data directory (quarantine store, logs).
pub fn data_dir() -> PathBuf {
    if let Ok(pd) = std::env::var("PROGRAMDATA") {
        return PathBuf::from(pd).join("Sentinel EPP");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("sentinel-epp");
    }
    std::env::temp_dir().join("sentinel-epp")
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
