//! Glue between the GUI and `scanner-core`: embedded default content, install
//! paths, engine construction, and threaded scanning. Mirrors the CLI agent so
//! the GUI is a standalone, self-contained app.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::thread;

use scanner_core::{Disposition, Engine, Quarantine, ScanReport, ScanSummary, Scanner};

/// Baseline signatures embedded into the binary (works with no external files).
pub const HASHDB: &str = include_str!("../../../signatures/hashes/baseline.hashdb");
pub const YARA_RULES: &[(&str, &str)] = &[
    (
        "eicar.yar",
        include_str!("../../../signatures/yara/eicar.yar"),
    ),
    (
        "webshells.yar",
        include_str!("../../../signatures/yara/webshells.yar"),
    ),
    (
        "powershell.yar",
        include_str!("../../../signatures/yara/powershell.yar"),
    ),
];

/// Per-machine writable definitions store updated by the feed updater.
pub fn store_dir() -> PathBuf {
    data_dir().join("signatures")
}

/// Human-readable description of where the active signatures come from.
pub fn signatures_source() -> String {
    let store = store_dir();
    if store.join("hashes").is_dir() || store.join("yara").is_dir() {
        format!("built-in + local store · {}", store.display())
    } else {
        "built-in (embedded in app)".to_string()
    }
}

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

pub fn quarantine_dir() -> PathBuf {
    data_dir().join("quarantine")
}

/// High-risk locations for a Quick Scan (only existing paths).
pub fn quick_scan_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut push = |var: &str, sub: &[&str]| {
        if let Ok(base) = std::env::var(var) {
            let mut p = PathBuf::from(base);
            for s in sub {
                p.push(s);
            }
            out.push(p);
        }
    };
    if cfg!(windows) {
        push("USERPROFILE", &["Downloads"]);
        push("USERPROFILE", &["Desktop"]);
        push("TEMP", &[]);
        push("APPDATA", &[]);
        push("LOCALAPPDATA", &["Temp"]);
    } else {
        push("HOME", &["Downloads"]);
        push("HOME", &["Desktop"]);
        push("HOME", &[".cache"]);
        out.push(PathBuf::from("/tmp"));
    }
    out.retain(|p| p.exists());
    out.dedup();
    out
}

pub fn full_scan_roots() -> Vec<PathBuf> {
    if cfg!(windows) {
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        vec![PathBuf::from(format!("{drive}\\"))]
    } else {
        vec![PathBuf::from("/")]
    }
}

/// Build the engine, preferring external content, falling back to embedded.
pub fn load_engine() -> Result<(Engine, usize, usize), String> {
    let (engine, hashes, yara, _skipped) =
        scanner_core::bootstrap::load_engine(HASHDB, YARA_RULES, &store_dir(), None, None, false)
            .map_err(|e| e.to_string())?;
    Ok((engine, hashes, yara))
}

/// Cheap counts for the dashboard: (hash signatures, YARA files, quarantined).
pub fn inventory_counts() -> (usize, usize, usize) {
    let (hash_signatures, yara_files) =
        scanner_core::bootstrap::inventory(HASHDB, YARA_RULES.len(), &store_dir());
    let quarantined = Quarantine::open(quarantine_dir())
        .and_then(|q| q.list())
        .map(|i| i.len())
        .unwrap_or(0);
    (hash_signatures, yara_files, quarantined)
}

/// Spawn a background feed update; the receiver yields the final report.
pub fn start_update() -> Receiver<scanner_core::UpdateReport> {
    let (tx, rx) = mpsc::channel();
    let store = store_dir();
    thread::spawn(move || {
        let report = scanner_core::feeds::update(&store, &scanner_core::UpdateOptions::default());
        let _ = tx.send(report);
    });
    rx
}

/// Messages streamed from the background scan thread to the UI.
pub enum ScanMsg {
    Progress {
        scanned: u64,
        current: String,
    },
    Threat(Box<ScanReport>),
    Done {
        files: u64,
        malicious: u64,
        suspicious: u64,
        ms: u64,
        bytes: u64,
    },
    Failed(String),
}

/// Spawn a background scan of `targets`, returning a receiver of progress.
pub fn start_scan(targets: Vec<PathBuf>) -> Receiver<ScanMsg> {
    let (tx, rx) = mpsc::channel::<ScanMsg>();
    thread::spawn(move || {
        let (engine, _, _) = match load_engine() {
            Ok(v) => v,
            Err(e) => {
                let _ = tx.send(ScanMsg::Failed(e));
                return;
            }
        };
        let scanner = Scanner::new(&engine);
        let mut summary = ScanSummary::default();
        let started = std::time::Instant::now();
        let mut scanned: u64 = 0;

        // Scoped so the borrows held by `handle` end before we read `summary`.
        {
            let mut handle = |report: ScanReport| {
                summary.record(&report);
                if matches!(
                    report.disposition,
                    Disposition::Clean | Disposition::Malicious | Disposition::Suspicious
                ) {
                    scanned += 1;
                }
                if report.is_malicious() || report.is_suspicious() {
                    let _ = tx.send(ScanMsg::Threat(Box::new(report)));
                } else if scanned % 16 == 0 {
                    let _ = tx.send(ScanMsg::Progress {
                        scanned,
                        current: report.path,
                    });
                }
            };

            for target in &targets {
                if target.is_dir() {
                    scanner.scan_path(target, &mut handle);
                } else {
                    handle(scanner.scan_file(target));
                }
            }
        }

        let _ = tx.send(ScanMsg::Done {
            files: summary.files_scanned,
            malicious: summary.malicious,
            suspicious: summary.suspicious,
            ms: started.elapsed().as_millis() as u64,
            bytes: summary.bytes_scanned,
        });
    });
    rx
}

/// Quarantine the malicious reports; returns how many were isolated.
pub fn quarantine_reports(reports: &[ScanReport]) -> Result<usize, String> {
    let store = Quarantine::open(quarantine_dir()).map_err(|e| e.to_string())?;
    let mut count = 0;
    for r in reports {
        if !r.is_malicious() {
            continue;
        }
        if let Some(h) = &r.hashes {
            if store
                .quarantine_file(Path::new(&r.path), &h.sha256, r.size, r.detections.clone())
                .is_ok()
            {
                count += 1;
            }
        }
    }
    Ok(count)
}
