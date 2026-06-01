//! Agent identity, enrollment, and persisted state for the enterprise console.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::paths;

/// Management/enrollment info, sourced from the environment (in production the
/// MSI provisions these into `HKLM\SOFTWARE\Sentinel EPP`; we read the mirrored
/// `SENTINEL_*` variables here so the console works cross-platform).
pub struct AgentInfo {
    pub version: String,
    pub tenant: Option<String>,
    pub server: Option<String>,
    pub update_ring: String,
}

impl AgentInfo {
    pub fn load() -> Self {
        let env = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            tenant: env("SENTINEL_TENANT"),
            server: env("SENTINEL_SERVER"),
            update_ring: env("SENTINEL_RING").unwrap_or_else(|| "stable".to_string()),
        }
    }

    pub fn managed(&self) -> bool {
        self.tenant.is_some()
    }
}

/// Persisted, machine-local agent state (shown on the dashboard).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentState {
    pub last_scan_unix: u64,
    pub last_files: u64,
    pub last_malicious: u64,
    pub last_suspicious: u64,
}

impl AgentState {
    fn default_path() -> PathBuf {
        paths::data_dir().join("state.json")
    }

    pub fn load() -> Self {
        Self::load_from(Self::default_path())
    }

    pub fn load_from(path: impl AsRef<Path>) -> Self {
        std::fs::read_to_string(path.as_ref())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save_to(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string());
        std::fs::write(path, text)
    }

    /// Record the result of a scan to the default state file (best effort).
    pub fn record_scan(files: u64, malicious: u64, suspicious: u64) {
        let state = AgentState {
            last_scan_unix: now_unix(),
            last_files: files,
            last_malicious: malicious,
            last_suspicious: suspicious,
        };
        let _ = state.save_to(Self::default_path());
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Cheap inventory counts for the dashboard (no rule compilation).
pub struct Inventory {
    pub hash_signatures: usize,
    pub yara_files: usize,
    pub quarantined: usize,
}

pub fn inventory() -> Inventory {
    let hash_signatures = scanner_core::HashSignatureDb::from_file(paths::default_hashes())
        .map(|d| d.len())
        .unwrap_or(0);

    let yara_files = std::fs::read_dir(paths::default_rules())
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .and_then(|x| x.to_str())
                        .map(|x| x.eq_ignore_ascii_case("yar") || x.eq_ignore_ascii_case("yara"))
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0);

    let quarantined = scanner_core::Quarantine::open(paths::default_quarantine_dir())
        .and_then(|q| q.list())
        .map(|items| items.len())
        .unwrap_or(0);

    Inventory {
        hash_signatures,
        yara_files,
        quarantined,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");

        let state = AgentState {
            last_scan_unix: 1_780_000_000,
            last_files: 42,
            last_malicious: 3,
            last_suspicious: 1,
        };
        state.save_to(&path).unwrap();

        let loaded = AgentState::load_from(&path);
        assert_eq!(loaded.last_files, 42);
        assert_eq!(loaded.last_malicious, 3);
        assert_eq!(loaded.last_suspicious, 1);
    }

    #[test]
    fn missing_state_is_default() {
        let loaded = AgentState::load_from("/nonexistent/path/state.json");
        assert_eq!(loaded.last_scan_unix, 0);
    }
}
