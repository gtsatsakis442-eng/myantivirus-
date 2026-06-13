//! Persisted user settings (`<data_dir>/config.json`).
//!
//! These are **real** knobs: [`crate::engine_glue`] reads them when building the
//! engine and the scan options, so changing a setting actually changes how the
//! next scan behaves (exclusions, archive scanning, heuristics, threads, …).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// How often a background scan should run. The scheduler that honours this runs
/// in the (Phase-2) service; today it is persisted and surfaced in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Schedule {
    #[default]
    Off,
    Daily,
    Weekly,
}

impl Schedule {
    pub fn label(self) -> &'static str {
        match self {
            Schedule::Off => "Off",
            Schedule::Daily => "Daily",
            Schedule::Weekly => "Weekly",
        }
    }
}

/// User-configurable settings. `#[serde(default)]` keeps old config files
/// forward-compatible as new fields are added.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TalosConfig {
    /// Max file size (MiB) loaded into memory for content/YARA inspection.
    pub max_size_mib: u64,
    /// Worker threads for directory scans (`0` = all CPU cores).
    pub threads: usize,
    /// Follow symbolic links while walking.
    pub follow_symlinks: bool,
    /// Inspect inside ZIP archives.
    pub scan_archives: bool,
    /// Run the static PE heuristic layer (packing / injection / W^X).
    pub heuristics: bool,
    /// Run the static behavioral capability layer (CAPA-style, MITRE-tagged).
    pub behavior: bool,
    /// Trusted paths to skip (files or folders).
    pub exclusions: Vec<String>,
    /// Dark vs. light appearance.
    pub dark_theme: bool,
    /// Scheduled-scan cadence.
    pub schedule: Schedule,
    /// Bring the OS-firewall protection up automatically when the agent starts
    /// (baseline malware ports + IPs, plus the threat-intel IP feeds).
    pub firewall_autostart: bool,
    /// Bring web/domain protection (URLhaus hosts-file sinkhole) up
    /// automatically when the agent starts.
    pub web_autostart: bool,
}

impl Default for TalosConfig {
    fn default() -> Self {
        Self {
            max_size_mib: 128,
            threads: 0,
            follow_symlinks: false,
            scan_archives: true,
            heuristics: true,
            behavior: true,
            exclusions: Vec::new(),
            dark_theme: true,
            schedule: Schedule::Off,
            firewall_autostart: true,
            web_autostart: true,
        }
    }
}

fn config_path() -> PathBuf {
    crate::engine_glue::data_dir().join("config.json")
}

impl TalosConfig {
    /// Load from disk, falling back to defaults if missing/unparseable.
    pub fn load() -> Self {
        std::fs::read_to_string(config_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Persist to disk (best-effort; errors are swallowed so the UI never dies).
    pub fn save(&self) {
        let path = config_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, json);
        }
    }

    /// Non-empty exclusion entries as paths.
    pub fn exclusion_paths(&self) -> Vec<PathBuf> {
        self.exclusions
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect()
    }
}
