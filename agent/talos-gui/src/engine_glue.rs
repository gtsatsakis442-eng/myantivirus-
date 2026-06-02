//! Glue between the GUI and `scanner-core`: embedded default content, install
//! paths, engine construction, and threaded scanning. Mirrors the CLI agent so
//! the GUI is a standalone, self-contained app.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::thread;

use scanner_core::{
    Disposition, Engine, HashSignatureDb, Quarantine, ScanReport, ScanSummary, Scanner, YaraEngine,
};

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

fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(PathBuf::from)
}

fn content_base() -> PathBuf {
    // Prefer a writable, updatable definitions store (where an updater/admin
    // drops new signatures), then the install dir, then the CWD.
    if data_dir().join("signatures").is_dir() {
        return data_dir();
    }
    if let Some(dir) = exe_dir() {
        if dir.join("signatures").is_dir() {
            return dir;
        }
    }
    PathBuf::from(".")
}

/// Human-readable description of where the active signatures come from.
pub fn signatures_source() -> String {
    if data_dir().join("signatures").is_dir() {
        return format!("local store · {}", data_dir().join("signatures").display());
    }
    if let Some(dir) = exe_dir() {
        if dir.join("signatures").is_dir() {
            return format!("install dir · {}", dir.join("signatures").display());
        }
    }
    if std::path::Path::new("signatures").is_dir() {
        return "./signatures".to_string();
    }
    "built-in (embedded in app)".to_string()
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
    let hashes = if default_hashes().is_file() {
        HashSignatureDb::from_file(default_hashes()).map_err(|e| e.to_string())?
    } else {
        HashSignatureDb::from_str_db(HASHDB).map_err(|e| e.to_string())?
    };
    let hash_count = hashes.len();

    let engine = if default_rules().is_dir() {
        YaraEngine::from_dir(default_rules()).map_err(|e| e.to_string())?
    } else {
        YaraEngine::from_sources(YARA_RULES.iter().copied()).map_err(|e| e.to_string())?
    };
    let yara_files = engine.source_files();

    Ok((Engine::new(hashes, Some(engine)), hash_count, yara_files))
}

/// Cheap counts for the dashboard: (hash signatures, YARA files, quarantined).
pub fn inventory_counts() -> (usize, usize, usize) {
    let hash_signatures = if default_hashes().is_file() {
        HashSignatureDb::from_file(default_hashes())
            .map(|d| d.len())
            .unwrap_or(0)
    } else {
        HashSignatureDb::from_str_db(HASHDB)
            .map(|d| d.len())
            .unwrap_or(0)
    };
    let yara_files = if default_rules().is_dir() {
        std::fs::read_dir(default_rules())
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| {
                        e.path()
                            .extension()
                            .and_then(|x| x.to_str())
                            .map(|x| {
                                x.eq_ignore_ascii_case("yar") || x.eq_ignore_ascii_case("yara")
                            })
                            .unwrap_or(false)
                    })
                    .count()
            })
            .unwrap_or(0)
    } else {
        YARA_RULES.len()
    };
    let quarantined = Quarantine::open(quarantine_dir())
        .and_then(|q| q.list())
        .map(|i| i.len())
        .unwrap_or(0);
    (hash_signatures, yara_files, quarantined)
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
