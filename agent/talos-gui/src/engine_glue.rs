//! Glue between the GUI and `scanner-core`: embedded default content, install
//! paths, engine construction, and threaded scanning. Mirrors the CLI agent so
//! the GUI is a standalone, self-contained app.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use scanner_core::{
    Disposition, Engine, Quarantine, ScanOptions, ScanReport, ScanSummary, Scanner,
};

use crate::config::TalosConfig;
use crate::history;

/// Build [`ScanOptions`] from user settings so a scan honours the configured
/// size cap, symlink policy, archive inspection, exclusions and thread count.
fn scan_options(cfg: &TalosConfig) -> ScanOptions {
    ScanOptions {
        max_content_bytes: cfg.max_size_mib.saturating_mul(1024 * 1024),
        follow_symlinks: cfg.follow_symlinks,
        scan_archives: cfg.scan_archives,
        exclusions: cfg.exclusion_paths(),
        threads: cfg.threads,
        ..Default::default()
    }
}

/// Baseline signatures embedded into the binary (works with no external files).
pub const HASHDB: &str = concat!(
    include_str!("../../../signatures/hashes/baseline.hashdb"),
    "\n",
    include_str!("../../../signatures/hashes/talos.hashdb"),
);
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
        history::record(
            "update",
            format!(
                "Signature update — {} hashes, {} YARA file(s)",
                report.hashes_added, report.yara_files
            ),
        );
        let _ = tx.send(report);
    });
    rx
}

/// Result of an in-process firewall / web-protection action — used when no
/// privileged agent is present and the GUI applies the change itself (which
/// requires the GUI to be running elevated; otherwise the op reports the error).
pub enum AdminMsg {
    /// `blocked` is `Some(n)` when the action changes the rule/domain count
    /// (sync / flush / clear) and `None` when it leaves it unchanged.
    Firewall {
        on: bool,
        blocked: Option<usize>,
        note: String,
    },
    Web {
        on: bool,
        blocked: Option<usize>,
        note: String,
    },
    Failed(String),
}

fn spawn_admin(f: impl FnOnce() -> AdminMsg + Send + 'static) -> Receiver<AdminMsg> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx
}

/// Sync the abuse.ch Feodo C2 IP blocklist into the OS firewall (in-process).
pub fn start_firewall_sync() -> Receiver<AdminMsg> {
    spawn_admin(|| {
        match scanner_core::firewall::sync_c2_blocklist(scanner_core::firewall::default_feodo_url())
        {
            Ok(r) => {
                history::record(
                    "firewall",
                    format!(
                        "C2 firewall sync — {}/{} rule(s) applied",
                        r.applied, r.listed
                    ),
                );
                if r.applied == 0 && r.listed > 0 {
                    AdminMsg::Firewall {
                        on: false,
                        blocked: Some(0),
                        note: format!(
                            "Downloaded {} C2 IP(s) but applied 0 — run as Administrator/root (or install the agent).",
                            r.listed
                        ),
                    }
                } else {
                    AdminMsg::Firewall {
                        on: r.applied > 0,
                        blocked: Some(r.applied),
                        note: format!("Firewall on — {} C2 IP(s) blocked.", r.applied),
                    }
                }
            }
            Err(e) => AdminMsg::Failed(format!("Firewall sync failed: {e}")),
        }
    })
}

/// Remove all Talos firewall rules (in-process).
pub fn start_firewall_flush() -> Receiver<AdminMsg> {
    spawn_admin(|| match scanner_core::firewall::flush() {
        Ok(()) => {
            history::record("firewall", "Flushed all Talos firewall rules");
            AdminMsg::Firewall {
                on: false,
                blocked: Some(0),
                note: "Firewall off — all Talos rules removed.".to_string(),
            }
        }
        Err(e) => AdminMsg::Failed(format!("Firewall flush failed: {e}")),
    })
}

/// Block a single outbound IPv4 address (in-process).
pub fn start_firewall_block(ip: String) -> Receiver<AdminMsg> {
    spawn_admin(move || match scanner_core::firewall::block_ip(&ip) {
        Ok(()) => {
            history::record("firewall", format!("Blocked outbound {ip}"));
            AdminMsg::Firewall {
                on: true,
                blocked: None,
                note: format!("Blocked outbound traffic to {ip}."),
            }
        }
        Err(e) => AdminMsg::Failed(format!("Block failed: {e}")),
    })
}

/// Unblock a single outbound IPv4 address (in-process).
pub fn start_firewall_unblock(ip: String) -> Receiver<AdminMsg> {
    spawn_admin(move || match scanner_core::firewall::unblock_ip(&ip) {
        Ok(()) => {
            history::record("firewall", format!("Unblocked {ip}"));
            AdminMsg::Firewall {
                on: true,
                blocked: None,
                note: format!("Unblocked {ip}."),
            }
        }
        Err(e) => AdminMsg::Failed(format!("Unblock failed: {e}")),
    })
}

/// Sync the abuse.ch URLhaus domain blocklist into the hosts file (in-process).
pub fn start_web_sync() -> Receiver<AdminMsg> {
    spawn_admin(|| {
        match scanner_core::webprotect::sync_blocklist(
            scanner_core::webprotect::default_urlhaus_url(),
        ) {
            Ok(r) => {
                history::record(
                    "web",
                    format!("Web protection sync — {} domain(s) sinkholed", r.domains),
                );
                AdminMsg::Web {
                    on: true,
                    blocked: Some(r.domains),
                    note: format!("Web protection on — {} domain(s) sinkholed.", r.domains),
                }
            }
            Err(e) => AdminMsg::Failed(format!("Web protection sync failed: {e}")),
        }
    })
}

/// Remove the Talos-managed hosts-file block section (in-process).
pub fn start_web_clear() -> Receiver<AdminMsg> {
    spawn_admin(|| match scanner_core::webprotect::clear() {
        Ok(()) => {
            history::record("web", "Cleared web protection hosts entries");
            AdminMsg::Web {
                on: false,
                blocked: Some(0),
                note: "Web protection off — hosts entries removed.".to_string(),
            }
        }
        Err(e) => AdminMsg::Failed(format!("Web protection clear failed: {e}")),
    })
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
        /// True when the user stopped the scan early (partial results).
        stopped: bool,
    },
    Failed(String),
}

/// Path to the on-demand scan cache.
fn scan_cache_path() -> PathBuf {
    data_dir().join("scan-cache.json")
}

/// Spawn a background scan of `targets`, returning a receiver of progress plus
/// a stop flag — raise it (Scan view's Stop button) and the scan ends promptly
/// with partial results.
///
/// `use_cache` enables the incremental cache (clean, unchanged files are skipped
/// without being re-read). Quick/Custom scans pass `true`; a Full Scan passes
/// `false` so every file is re-read.
pub fn start_scan(targets: Vec<PathBuf>, use_cache: bool) -> (Receiver<ScanMsg>, Arc<AtomicBool>) {
    let (tx, rx) = mpsc::channel::<ScanMsg>();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_scan = stop.clone();
    thread::spawn(move || {
        let cfg = TalosConfig::load();
        let (mut engine, hash_count, yara_count) = match load_engine() {
            Ok(v) => v,
            Err(e) => {
                let _ = tx.send(ScanMsg::Failed(e));
                return;
            }
        };
        engine.set_heuristics(cfg.heuristics);
        engine.set_behavior(cfg.behavior);
        let mut options = scan_options(&cfg);
        options.cancel = Some(stop_scan.clone());

        // Incremental cache, keyed to the current definitions generation so any
        // signature/YARA/heuristics/version change invalidates it.
        let cache = if use_cache {
            let generation = scanner_core::cache::definitions_generation(
                hash_count,
                yara_count,
                cfg.heuristics,
                cfg.behavior,
                &store_dir(),
            );
            let path = scan_cache_path();
            let c = Arc::new(Mutex::new(scanner_core::cache::ScanCache::load(
                &path, generation,
            )));
            options.cache = Some(c.clone());
            Some((c, path))
        } else {
            None
        };

        let scanner = Scanner::with_options(&engine, options);
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
                if stop_scan.load(Ordering::Relaxed) {
                    break;
                }
                if target.is_dir() {
                    scanner.scan_path(target, &mut handle);
                } else {
                    handle(scanner.scan_file(target));
                }
            }
        }

        // Persist the refreshed cache (best-effort) for the next scan.
        if let Some((c, path)) = &cache {
            if let Ok(guard) = c.lock() {
                let _ = guard.save(path);
            }
        }

        let stopped = stop_scan.load(Ordering::Relaxed);
        let ms = started.elapsed().as_millis() as u64;
        history::record(
            "scan",
            format!(
                "Scan{} — {} files · {} malicious · {} suspicious · {} ms",
                if stopped { " (stopped early)" } else { "" },
                summary.files_scanned,
                summary.malicious,
                summary.suspicious,
                ms
            ),
        );
        let _ = tx.send(ScanMsg::Done {
            files: summary.files_scanned,
            malicious: summary.malicious,
            suspicious: summary.suspicious,
            ms,
            bytes: summary.bytes_scanned,
            stopped,
        });
    });
    (rx, stop)
}

/// Events streamed from the real-time monitor thread.
pub enum RealtimeMsg {
    Started(usize),
    Detection(Box<ScanReport>),
    /// A ransomware canary was encrypted/deleted — mass-encryption suspected.
    Ransomware(String),
    Error(String),
}

/// Handle to a running real-time monitor. Call [`RealtimeHandle::stop`] (or drop
/// it) to end monitoring.
pub struct RealtimeHandle {
    pub rx: Receiver<RealtimeMsg>,
    stop: Arc<AtomicBool>,
}

impl RealtimeHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for RealtimeHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Start user-mode on-access monitoring of `paths`: a background thread watches
/// for new/changed files and auto-scans each with the configured engine,
/// streaming any detections to the UI.
pub fn start_realtime(paths: Vec<PathBuf>) -> RealtimeHandle {
    let (tx, rx) = mpsc::channel::<RealtimeMsg>();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    thread::spawn(move || {
        let cfg = TalosConfig::load();
        let (mut engine, _, _) = match load_engine() {
            Ok(v) => v,
            Err(e) => {
                let _ = tx.send(RealtimeMsg::Error(e));
                return;
            }
        };
        engine.set_heuristics(cfg.heuristics);
        engine.set_behavior(cfg.behavior);
        let scanner = Scanner::with_options(&engine, scan_options(&cfg));
        let watch = match scanner_core::realtime::watch(&paths) {
            Ok(w) => w,
            Err(e) => {
                let _ = tx.send(RealtimeMsg::Error(e.to_string()));
                return;
            }
        };
        // Ransomware guard: plant canary decoys across the watched folders.
        let canaries = scanner_core::ransom_guard::deploy(&paths);
        let _ = tx.send(RealtimeMsg::Started(paths.len()));
        while !stop_thread.load(Ordering::Relaxed) {
            match watch.rx.recv_timeout(Duration::from_millis(300)) {
                Ok(path) => {
                    // A canary touched? Verify the content actually changed (our
                    // own deploy-write hashes the same), then alarm on tamper.
                    if scanner_core::ransom_guard::is_canary(&path) {
                        if let Some(c) = canaries.iter().find(|c| c.path == path) {
                            let tampered = std::fs::read(&c.path)
                                .map(|b| scanner_core::hash_bytes(&b).sha256 != c.sha256)
                                .unwrap_or(true);
                            if tampered {
                                history::record(
                                    "realtime",
                                    format!("RANSOMWARE: canary tampered — {}", c.path.display()),
                                );
                                let _ =
                                    tx.send(RealtimeMsg::Ransomware(c.path.display().to_string()));
                                let _ = scanner_core::ransom_guard::deploy(&paths);
                                // restore decoys
                            }
                        }
                        continue;
                    }
                    let report = scanner.scan_file(&path);
                    if report.is_malicious() {
                        // Immediate response: isolate the threat the moment it
                        // lands (the strongest user-mode action short of the
                        // Phase-2 kernel minifilter's pre-execution block).
                        let isolated = quarantine_one(&report);
                        history::record(
                            "realtime",
                            format!(
                                "Real-time: {} {}",
                                if isolated { "quarantined" } else { "detected" },
                                report.path
                            ),
                        );
                        let _ = tx.send(RealtimeMsg::Detection(Box::new(report)));
                    } else if report.is_suspicious() {
                        history::record(
                            "realtime",
                            format!("Real-time: suspicious {}", report.path),
                        );
                        let _ = tx.send(RealtimeMsg::Detection(Box::new(report)));
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        scanner_core::ransom_guard::cleanup(&canaries);
    });
    RealtimeHandle { rx, stop }
}

/// Spawn a background threat-intel lookup of `sha256` (across all providers).
pub fn start_intel(sha256: String) -> Receiver<Result<Vec<scanner_core::IntelReport>, String>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let r = scanner_core::lookup_hash(&sha256).map_err(|e| e.to_string());
        let _ = tx.send(r);
    });
    rx
}

/// Quarantine a single malicious report immediately (real-time response).
fn quarantine_one(report: &ScanReport) -> bool {
    if let (Ok(store), Some(h)) = (Quarantine::open(quarantine_dir()), report.hashes.as_ref()) {
        return store
            .quarantine_file(
                Path::new(&report.path),
                &h.sha256,
                report.size,
                report.detections.clone(),
            )
            .is_ok();
    }
    false
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
