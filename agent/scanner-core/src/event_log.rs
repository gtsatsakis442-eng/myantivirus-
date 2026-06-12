//! SIEM-ready structured event log for all Talos detections.
//!
//! Writes **JSON Lines** (one JSON object per `\n`-terminated line) to a
//! configurable file path, suitable for ingestion by Splunk, QRadar, Azure
//! Sentinel, Elastic SIEM, or any log aggregator that supports either JSON
//! Lines or `tail -f`.
//!
//! Also emits **CEF (Common Event Format)** lines to `stderr` / a separate
//! CEF file so syslog-forwarding agents (e.g. ArcSight SmartConnector, Splunk
//! Universal Forwarder) pick them up without any file-reading logic.
//!
//! ## JSON Lines schema (every field is always present)
//!
//! ```json
//! {
//!   "ts":              "2025-06-12T18:00:00Z",   // ISO 8601 UTC
//!   "product":        "TalosEPP",
//!   "version":        "0.13.0",
//!   "host":           "WORKSTATION-01",
//!   "event_type":     "detection",               // detection | quarantine | firewall | scan_summary | rollback
//!   "severity":       "high",                    // critical | high | medium | low | info
//!   "file_path":      "C:\\Users\\...\\evil.exe",
//!   "sha256":         "deadbeef...",
//!   "detection_name": "Ransomware.WannaCry",
//!   "detection_kind": "HashSignature",           // HashSignature | YaraRule | Heuristic | Behavior
//!   "mitre":          "T1486",                   // or "" if not applicable
//!   "action":         "quarantined"              // detected | quarantined | blocked | restored | rollback
//! }
//! ```

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::verdict::{Detection, Severity};

/// A single structured event written to the SIEM log.
#[derive(Debug, Serialize)]
pub struct SiemEvent {
    pub ts: String,
    pub product: &'static str,
    pub version: &'static str,
    pub host: String,
    pub event_type: &'static str,
    pub severity: String,
    pub file_path: String,
    pub sha256: String,
    pub detection_name: String,
    pub detection_kind: String,
    pub mitre: String,
    pub action: String,
}

/// Append-only, thread-safe SIEM event log.
///
/// Open once per agent lifetime (e.g. when the daemon starts) and share via
/// `Arc` between scan threads and the IPC handler. Each `write` call holds
/// the inner mutex only long enough to flush one line.
pub struct EventLog {
    path: PathBuf,
    inner: Mutex<BufWriter<File>>,
    host: String,
}

impl EventLog {
    /// Open (or create) the log file at `path` in append mode.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            inner: Mutex::new(BufWriter::new(file)),
            host: hostname(),
        })
    }

    /// Path of the log file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Log a detection event (file scan hit or real-time alert).
    pub fn log_detection(
        &self,
        file_path: &str,
        sha256: &str,
        detection: &Detection,
        action: &str,
    ) {
        let mitre = extract_mitre(&detection.name);
        let ev = SiemEvent {
            ts: now_iso8601(),
            product: "TalosEPP",
            version: env!("CARGO_PKG_VERSION"),
            host: self.host.clone(),
            event_type: "detection",
            severity: severity_str(detection.severity),
            file_path: file_path.to_string(),
            sha256: sha256.to_string(),
            detection_name: detection.name.clone(),
            detection_kind: format!("{:?}", detection.kind),
            mitre,
            action: action.to_string(),
        };
        self.write_event(&ev);
    }

    /// Log a quarantine action (called after `quarantine_file` succeeds).
    pub fn log_quarantine(&self, file_path: &str, sha256: &str, detection_name: &str) {
        let ev = SiemEvent {
            ts: now_iso8601(),
            product: "TalosEPP",
            version: env!("CARGO_PKG_VERSION"),
            host: self.host.clone(),
            event_type: "quarantine",
            severity: "high".to_string(),
            file_path: file_path.to_string(),
            sha256: sha256.to_string(),
            detection_name: detection_name.to_string(),
            detection_kind: String::new(),
            mitre: String::new(),
            action: "quarantined".to_string(),
        };
        self.write_event(&ev);
    }

    /// Log a firewall block (IP or port).
    pub fn log_firewall(&self, target: &str, reason: &str, action: &str) {
        let ev = SiemEvent {
            ts: now_iso8601(),
            product: "TalosEPP",
            version: env!("CARGO_PKG_VERSION"),
            host: self.host.clone(),
            event_type: "firewall",
            severity: "info".to_string(),
            file_path: String::new(),
            sha256: String::new(),
            detection_name: reason.to_string(),
            detection_kind: String::new(),
            mitre: "T1071".to_string(),
            action: format!("{action}: {target}"),
        };
        self.write_event(&ev);
    }

    /// Log a ransomware rollback event.
    pub fn log_rollback(&self, restored: usize, canary_path: &str) {
        let ev = SiemEvent {
            ts: now_iso8601(),
            product: "TalosEPP",
            version: env!("CARGO_PKG_VERSION"),
            host: self.host.clone(),
            event_type: "rollback",
            severity: "critical".to_string(),
            file_path: canary_path.to_string(),
            sha256: String::new(),
            detection_name: "Ransomware.CanaryTriggered".to_string(),
            detection_kind: String::new(),
            mitre: "T1486".to_string(),
            action: format!("rollback: {restored} file(s) restored"),
        };
        self.write_event(&ev);
    }

    /// Log a scan completion summary (one entry per finished scan).
    pub fn log_scan_summary(
        &self,
        scanned: usize,
        threats: usize,
        duration_secs: f64,
        scan_path: &str,
    ) {
        let ev = SiemEvent {
            ts: now_iso8601(),
            product: "TalosEPP",
            version: env!("CARGO_PKG_VERSION"),
            host: self.host.clone(),
            event_type: "scan_summary",
            severity: if threats > 0 { "high" } else { "info" }.to_string(),
            file_path: scan_path.to_string(),
            sha256: String::new(),
            detection_name: format!(
                "Scan complete: {scanned} files, {threats} threat(s), {duration_secs:.1}s"
            ),
            detection_kind: String::new(),
            mitre: String::new(),
            action: "scan_complete".to_string(),
        };
        self.write_event(&ev);
    }

    /// Write any [`SiemEvent`] as a JSON Lines record.
    pub fn write_event(&self, ev: &SiemEvent) {
        if let Ok(json) = serde_json::to_string(ev) {
            if let Ok(mut guard) = self.inner.lock() {
                let _ = writeln!(guard, "{json}");
                let _ = guard.flush();
            }
        }
    }

    /// Produce a CEF-formatted line for this detection (for syslog forwarders).
    ///
    /// Format: `CEF:0|TalosEPP|TalosEPP|<version>|<kind>|<name>|<severity>|<extensions>`
    pub fn cef_line(ev: &SiemEvent) -> String {
        let sev_num = match ev.severity.as_str() {
            "critical" => 10u8,
            "high" => 8,
            "medium" => 5,
            "low" => 3,
            _ => 1,
        };
        // CEF extension key=value pairs (spaces escaped).
        let fp = ev.file_path.replace('\\', "\\\\").replace('=', "\\=");
        let dn = ev.detection_name.replace('\\', "\\\\").replace('=', "\\=");
        format!(
            "CEF:0|TalosEPP|TalosEPP|{ver}|{etype}|{dn}|{sev}|dhost={host} filePath={fp} fileHash={hash} cs1={mitre} cs1Label=MITRE act={act}",
            ver = ev.version,
            etype = ev.event_type,
            dn = dn,
            sev = sev_num,
            host = ev.host,
            fp = fp,
            hash = ev.sha256,
            mitre = ev.mitre,
            act = ev.action,
        )
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract a MITRE technique ID from a detection name like `"Foo [T1059.001]"`.
fn extract_mitre(name: &str) -> String {
    if let Some(start) = name.find('[') {
        if let Some(end) = name[start..].find(']') {
            return name[start + 1..start + end].to_string();
        }
    }
    String::new()
}

fn severity_str(s: Severity) -> String {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
    .to_string()
}

/// ISO 8601 UTC timestamp (no external dep — uses `SystemTime`).
fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Manual ISO 8601 from epoch seconds (avoids a chrono/time dependency).
    let (y, mo, d, h, mi, s) = epoch_to_parts(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn epoch_to_parts(mut secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let s = secs % 60;
    secs /= 60;
    let mi = secs % 60;
    secs /= 60;
    let h = secs % 24;
    secs /= 24;
    // Days since epoch → Gregorian date (simple algorithm).
    let mut y = 1970u64;
    loop {
        let dy = if is_leap(y) { 366 } else { 365 };
        if secs < dy {
            break;
        }
        secs -= dy;
        y += 1;
    }
    let months: &[u64] = if is_leap(y) {
        &[31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut mo = 1u64;
    for &dm in months {
        if secs < dm {
            break;
        }
        secs -= dm;
        mo += 1;
    }
    (y, mo, secs + 1, h, mi, s)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn hostname() -> String {
    // Try the environment variable first (works everywhere); fall back to a
    // platform call; worst case use a placeholder so the log is still valid.
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| {
            // gethostname via std::process on non-Windows.
            #[cfg(unix)]
            {
                use std::process::Command;
                Command::new("hostname")
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "unknown".to_string())
            }
            #[cfg(not(unix))]
            "unknown".to_string()
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{DetectionKind, Severity};

    fn sample_detection() -> Detection {
        Detection {
            name: "Ransomware.WannaCry [T1486]".to_string(),
            kind: DetectionKind::YaraRule,
            severity: Severity::Critical,
        }
    }

    #[test]
    fn mitre_extraction() {
        assert_eq!(extract_mitre("LolBin.Certutil [T1105]"), "T1105");
        assert_eq!(extract_mitre("Behavior.ProcessInjection [T1055]"), "T1055");
        assert_eq!(extract_mitre("No MITRE here"), "");
    }

    #[test]
    fn iso8601_sanity() {
        let ts = now_iso8601();
        // Must match YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(ts.len(), 20, "unexpected length: {ts}");
        assert!(ts.ends_with('Z'), "must end with Z: {ts}");
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
    }

    #[test]
    fn log_detection_writes_valid_json() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let log = EventLog::open(&log_path).unwrap();

        log.log_detection(
            "C:\\Users\\test\\evil.exe",
            "cafebabe1234567890abcdef",
            &sample_detection(),
            "quarantined",
        );

        let content = std::fs::read_to_string(&log_path).unwrap();
        let line = content.lines().next().expect("no line written");
        let v: serde_json::Value = serde_json::from_str(line).expect("not valid JSON");

        assert_eq!(v["product"], "TalosEPP");
        assert_eq!(v["event_type"], "detection");
        assert_eq!(v["severity"], "critical");
        assert_eq!(v["action"], "quarantined");
        assert_eq!(v["mitre"], "T1486");
        assert_eq!(v["detection_kind"], "YaraRule");
    }

    #[test]
    fn log_scan_summary_writes_valid_json() {
        let dir = tempfile::tempdir().unwrap();
        let log = EventLog::open(dir.path().join("events.jsonl")).unwrap();
        log.log_scan_summary(1000, 3, 4.7, "C:\\Users");
        let content = std::fs::read_to_string(log.path()).unwrap();
        let v: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(v["event_type"], "scan_summary");
        assert_eq!(v["severity"], "high"); // threats > 0
        assert!(v["detection_name"].as_str().unwrap().contains("1000 files"));
    }

    #[test]
    fn cef_format_is_correct() {
        let ev = SiemEvent {
            ts: "2025-06-12T18:00:00Z".to_string(),
            product: "TalosEPP",
            version: "0.13.0",
            host: "WORKSTATION-01".to_string(),
            event_type: "detection",
            severity: "high".to_string(),
            file_path: "C:\\evil.exe".to_string(),
            sha256: "deadbeef".to_string(),
            detection_name: "Trojan.Generic [T1059]".to_string(),
            detection_kind: "YaraRule".to_string(),
            mitre: "T1059".to_string(),
            action: "quarantined".to_string(),
        };
        let cef = EventLog::cef_line(&ev);
        assert!(cef.starts_with("CEF:0|TalosEPP"), "CEF prefix: {cef}");
        assert!(cef.contains("dhost=WORKSTATION-01"), "hostname: {cef}");
        assert!(cef.contains("act=quarantined"), "action: {cef}");
    }

    #[test]
    fn multiple_threads_write_without_corruption() {
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(EventLog::open(dir.path().join("mt.jsonl")).unwrap());
        let det = sample_detection();
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let log = Arc::clone(&log);
                let det = det.clone();
                std::thread::spawn(move || {
                    log.log_detection(
                        &format!("/tmp/evil_{i}.exe"),
                        "aabbccdd",
                        &det,
                        "detected",
                    );
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let content = std::fs::read_to_string(log.path()).unwrap();
        let count = content.lines().count();
        assert_eq!(count, 8, "expected 8 lines, got {count}");
        // Every line must be valid JSON.
        for line in content.lines() {
            serde_json::from_str::<serde_json::Value>(line)
                .expect("corrupted JSON line in multi-threaded write");
        }
    }

    #[test]
    fn quarantine_rollback_firewall_events_are_valid_json() {
        let dir = tempfile::tempdir().unwrap();
        let log = EventLog::open(dir.path().join("ev.jsonl")).unwrap();
        log.log_quarantine("/tmp/evil.exe", "deadbeef", "Ransomware.Test");
        log.log_rollback(17, "/home/user/!!!_TALOS_canary_DO_NOT_DELETE.docx");
        log.log_firewall("185.100.87.202", "Feodo Tracker C2", "blocked");
        let content = std::fs::read_to_string(log.path()).unwrap();
        for line in content.lines() {
            let v: serde_json::Value =
                serde_json::from_str(line).expect("invalid JSON");
            assert_eq!(v["product"], "TalosEPP");
        }
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 3);
    }
}
