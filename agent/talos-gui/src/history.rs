//! Activity log (`<data_dir>/activity.jsonl`) — a persisted, append-only feed of
//! scans, updates and quarantine actions, shown in the Activity view. This is
//! the local, on-device analogue of the "Detection History" / event log that
//! commercial suites surface.

use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// One activity record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub unix: u64,
    /// Coarse category: `"scan"`, `"update"`, `"quarantine"`.
    pub kind: String,
    /// Human-readable one-line summary.
    pub summary: String,
}

fn log_path() -> PathBuf {
    crate::engine_glue::data_dir().join("activity.jsonl")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Append an event (best-effort; never panics or blocks the UI meaningfully).
pub fn record(kind: &str, summary: impl Into<String>) {
    let event = Event {
        unix: now_unix(),
        kind: kind.to_string(),
        summary: summary.into(),
    };
    let path = log_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let (Ok(mut f), Ok(line)) = (
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path),
        serde_json::to_string(&event),
    ) {
        let _ = writeln!(f, "{line}");
    }
}

/// The most recent `limit` events, newest first.
pub fn recent(limit: usize) -> Vec<Event> {
    let text = match std::fs::read_to_string(log_path()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut events: Vec<Event> = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Event>(l).ok())
        .collect();
    events.reverse();
    events.truncate(limit);
    events
}
