//! The agent's shared state and request handling. One [`Shared`] is created by
//! the daemon and consulted by the real-time thread, the ransomware-canary
//! thread, and the IPC accept loop.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use scanner_core::{
    Engine, Quarantine, ScanOptions, ScanReport, ScanSummary, Scanner, DEFAULT_MAX_CONTENT_BYTES,
};
use talos_ipc::proto::{
    severity, Event, QuarantineItem, Request, Response, Status, PROTOCOL_VERSION,
};

/// This service's version string.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Cap on the in-memory activity log (older events roll off).
const EVENT_LOG_CAP: usize = 512;

/// Mutable scan/threat tallies behind a mutex.
#[derive(Default)]
struct Stats {
    last_scan_unix: u64,
    last_files: u64,
    last_malicious: u64,
    last_suspicious: u64,
    threats_blocked: u64,
}

/// A bounded, sequence-numbered ring of activity events.
struct EventLog {
    next_seq: u64,
    buf: VecDeque<Event>,
}

impl EventLog {
    fn new() -> Self {
        Self {
            next_seq: 1,
            buf: VecDeque::new(),
        }
    }

    fn push(&mut self, severity: &str, message: String, path: Option<String>) {
        let event = Event {
            seq: self.next_seq,
            unix: now_unix(),
            severity: severity.to_string(),
            message,
            path,
        };
        self.next_seq += 1;
        if self.buf.len() >= EVENT_LOG_CAP {
            self.buf.pop_front();
        }
        self.buf.push_back(event);
    }

    /// Events with `seq` greater than `since`, plus the next cursor to poll from.
    fn since(&self, since: u64) -> (Vec<Event>, u64) {
        let events = self.buf.iter().filter(|e| e.seq > since).cloned().collect();
        (events, self.next_seq)
    }
}

/// Everything the agent's threads share. Cloned via `Arc`.
pub struct Shared {
    engine: Arc<Engine>,
    quarantine_dir: PathBuf,
    roots: Vec<PathBuf>,
    token: String,
    started: Instant,
    realtime_on: AtomicBool,
    firewall_on: AtomicBool,
    /// Count of outbound IPs currently blocked by Talos firewall rules.
    firewall_blocked: AtomicUsize,
    /// Web/domain protection (URLhaus hosts-file sinkhole) state + domain count.
    web_on: AtomicBool,
    web_blocked: AtomicUsize,
    shutdown: Arc<AtomicBool>,
    /// True while an agent-initiated scan is running (anti-abuse: one at a time).
    scanning: AtomicBool,
    scan_seq: AtomicU64,
    hash_count: usize,
    yara_files: usize,
    stats: Mutex<Stats>,
    events: Mutex<EventLog>,
    /// Short-lived cache of the quarantine item count, so a status poll every
    /// couple of seconds doesn't re-list the vault each time.
    quarantine_cache: Mutex<Option<(Instant, usize)>>,
}

impl Shared {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        engine: Arc<Engine>,
        roots: Vec<PathBuf>,
        quarantine_dir: PathBuf,
        token: String,
        hash_count: usize,
        yara_files: usize,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            engine,
            quarantine_dir,
            roots,
            token,
            started: Instant::now(),
            realtime_on: AtomicBool::new(true),
            firewall_on: AtomicBool::new(false),
            firewall_blocked: AtomicUsize::new(0),
            web_on: AtomicBool::new(false),
            web_blocked: AtomicUsize::new(0),
            shutdown,
            scanning: AtomicBool::new(false),
            scan_seq: AtomicU64::new(0),
            hash_count,
            yara_files,
            stats: Mutex::new(Stats::default()),
            events: Mutex::new(EventLog::new()),
            quarantine_cache: Mutex::new(None),
        }
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    pub fn engine(&self) -> Arc<Engine> {
        Arc::clone(&self.engine)
    }

    pub fn realtime_enabled(&self) -> bool {
        self.realtime_on.load(Ordering::Relaxed)
    }

    pub fn set_realtime(&self, on: bool) {
        self.realtime_on.store(on, Ordering::Relaxed);
    }

    pub fn shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Append an activity event (used by every thread).
    pub fn push_event(&self, severity: &str, message: String, path: Option<String>) {
        if let Ok(mut log) = self.events.lock() {
            log.push(severity, message, path);
        }
    }

    /// React to a malicious file seen by the real-time monitor: auto-quarantine
    /// and record it.
    pub fn on_realtime_report(&self, report: ScanReport) {
        if !report.is_malicious() {
            return;
        }
        let names = detection_names(&report);
        let quarantined = quarantine_reports(&self.quarantine_dir, std::slice::from_ref(&report));
        if quarantined > 0 {
            self.push_event(
                severity::BLOCKED,
                format!("auto-quarantined: {names}"),
                Some(report.path.clone()),
            );
            self.bump_blocked(1);
        } else {
            self.push_event(
                severity::THREAT,
                format!("threat (could not quarantine): {names}"),
                Some(report.path.clone()),
            );
        }
    }

    /// React to a tampered ransomware canary.
    pub fn on_canary_tamper(&self, paths: &[PathBuf]) {
        let list = paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        self.push_event(
            severity::RANSOMWARE,
            format!("canary tampered — possible mass-encryption: {list}"),
            None,
        );
        self.bump_blocked(1);
    }

    fn bump_blocked(&self, n: u64) {
        if let Ok(mut s) = self.stats.lock() {
            s.threats_blocked += n;
        }
    }

    /// Handle one client request and produce a response.
    pub fn handle(self: &Arc<Self>, request: Request) -> Response {
        match request {
            Request::Ping => Response::Pong {
                version: VERSION.to_string(),
                protocol: PROTOCOL_VERSION,
            },
            Request::GetStatus => Response::Status(self.status()),
            Request::StartScan { paths, quarantine } => {
                let scan_id = self.spawn_scan(paths, quarantine);
                Response::ScanStarted { scan_id }
            }
            Request::ListQuarantine => self.list_quarantine(),
            Request::Restore { id } => self.restore(&id),
            Request::SetRealtime { on } => {
                self.set_realtime(on);
                self.push_event(
                    severity::INFO,
                    format!(
                        "real-time protection {}",
                        if on { "enabled" } else { "disabled" }
                    ),
                    None,
                );
                Response::Ack
            }
            Request::SetFirewall { on } => {
                self.spawn_firewall(on);
                Response::Ack
            }
            Request::FirewallBlock { ip } => {
                self.spawn_firewall_block(ip);
                Response::Ack
            }
            Request::FirewallUnblock { ip } => {
                self.spawn_firewall_unblock(ip);
                Response::Ack
            }
            Request::SetWebProtection { on } => {
                self.spawn_webprotect(on);
                Response::Ack
            }
            Request::GetEvents { since } => match self.events.lock() {
                Ok(log) => {
                    let (events, next) = log.since(since);
                    Response::Events { events, next }
                }
                Err(_) => Response::Error {
                    message: "event log unavailable".to_string(),
                },
            },
            Request::Shutdown => {
                self.shutdown.store(true, Ordering::SeqCst);
                self.push_event(severity::INFO, "shutdown requested".to_string(), None);
                Response::Ack
            }
        }
    }

    /// Quarantine item count with a short TTL cache (status is polled often).
    fn quarantined_count(&self) -> usize {
        const TTL: Duration = Duration::from_secs(3);
        let fresh = || {
            Quarantine::open(&self.quarantine_dir)
                .and_then(|q| q.list())
                .map_or(0, |items| items.len())
        };
        let Ok(mut cache) = self.quarantine_cache.lock() else {
            return fresh();
        };
        if let Some((at, n)) = *cache {
            if at.elapsed() < TTL {
                return n;
            }
        }
        let n = fresh();
        *cache = Some((Instant::now(), n));
        n
    }

    fn status(&self) -> Status {
        let quarantined = self.quarantined_count();
        let stats = self.stats.lock().ok();
        let (last_scan_unix, last_files, last_malicious, last_suspicious, threats_blocked) = stats
            .as_ref()
            .map(|s| {
                (
                    s.last_scan_unix,
                    s.last_files,
                    s.last_malicious,
                    s.last_suspicious,
                    s.threats_blocked,
                )
            })
            .unwrap_or_default();
        Status {
            version: VERSION.to_string(),
            realtime: self.realtime_on.load(Ordering::Relaxed),
            realtime_enforcing: false,
            firewall: self.firewall_on.load(Ordering::Relaxed),
            firewall_blocked: self.firewall_blocked.load(Ordering::Relaxed),
            web_protection: self.web_on.load(Ordering::Relaxed),
            web_blocked: self.web_blocked.load(Ordering::Relaxed),
            hash_signatures: self.hash_count,
            yara_files: self.yara_files,
            quarantined,
            last_scan_unix,
            last_files,
            last_malicious,
            last_suspicious,
            threats_blocked,
            uptime_secs: self.started.elapsed().as_secs(),
        }
    }

    fn list_quarantine(&self) -> Response {
        match Quarantine::open(&self.quarantine_dir).and_then(|q| q.list()) {
            Ok(items) => Response::Quarantine {
                items: items
                    .into_iter()
                    .map(|e| QuarantineItem {
                        id: e.id,
                        original_path: e.original_path,
                        detections: e.detections.iter().map(|d| d.name.clone()).collect(),
                    })
                    .collect(),
            },
            Err(e) => Response::Error {
                message: format!("quarantine: {e}"),
            },
        }
    }

    fn restore(&self, id: &str) -> Response {
        match Quarantine::open(&self.quarantine_dir) {
            Ok(store) => match store.restore(id, None) {
                Ok(path) => {
                    self.push_event(severity::INFO, format!("restored {}", path.display()), None);
                    Response::Ack
                }
                Err(e) => Response::Error {
                    message: format!("restore: {e}"),
                },
            },
            Err(e) => Response::Error {
                message: format!("quarantine: {e}"),
            },
        }
    }

    fn spawn_scan(self: &Arc<Self>, paths: Vec<String>, quarantine: bool) -> u64 {
        // Anti-abuse: only one agent-initiated scan at a time, so a local client
        // can't spawn unbounded scan threads by spamming StartScan.
        if self
            .scanning
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.push_event(
                severity::INFO,
                "scan request ignored — a scan is already running".to_string(),
                None,
            );
            return self.scan_seq.load(Ordering::Relaxed);
        }
        let scan_id = self.scan_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let me = Arc::clone(self);
        std::thread::spawn(move || me.run_scan(paths, quarantine, scan_id));
        scan_id
    }

    fn run_scan(self: Arc<Self>, paths: Vec<String>, quarantine: bool, scan_id: u64) {
        // Clear the `scanning` flag whenever this returns (including on panic).
        let _scan_guard = ScanResetGuard(&self.scanning);
        let targets: Vec<PathBuf> = if paths.is_empty() {
            crate::paths::quick_scan_paths()
        } else {
            paths.iter().map(PathBuf::from).collect()
        };
        self.push_event(
            severity::INFO,
            format!(
                "scan #{scan_id} started across {} location(s)",
                targets.len()
            ),
            None,
        );

        let options = ScanOptions {
            max_content_bytes: DEFAULT_MAX_CONTENT_BYTES,
            follow_symlinks: false,
            max_depth: None,
            threads: 0,
            ..Default::default()
        };
        let scanner = Scanner::with_options(self.engine.as_ref(), options);

        let mut summary = ScanSummary::default();
        let mut threats: Vec<ScanReport> = Vec::new();
        for target in &targets {
            if target.is_dir() {
                for report in scanner.scan_tree_parallel(target) {
                    summary.record(&report);
                    if report.is_malicious() {
                        threats.push(report);
                    }
                }
            } else if target.exists() {
                let report = scanner.scan_file(target);
                summary.record(&report);
                if report.is_malicious() {
                    threats.push(report);
                }
            }
        }

        let quarantined = if quarantine && !threats.is_empty() {
            quarantine_reports(&self.quarantine_dir, &threats)
        } else {
            0
        };
        for report in &threats {
            self.push_event(
                severity::THREAT,
                format!("threat: {}", detection_names(report)),
                Some(report.path.clone()),
            );
        }
        if let Ok(mut s) = self.stats.lock() {
            s.last_scan_unix = now_unix();
            s.last_files = summary.files_scanned;
            s.last_malicious = summary.malicious;
            s.last_suspicious = summary.suspicious;
            s.threats_blocked += quarantined as u64;
        }
        self.push_event(
            severity::INFO,
            format!(
                "scan #{scan_id} complete: {} scanned, {} malicious, {quarantined} quarantined",
                summary.files_scanned, summary.malicious
            ),
            None,
        );
    }

    fn spawn_firewall(self: &Arc<Self>, on: bool) {
        let me = Arc::clone(self);
        std::thread::spawn(move || {
            use scanner_core::firewall;
            if on {
                match firewall::sync_c2_blocklist(firewall::default_feodo_url()) {
                    Ok(report) => {
                        me.firewall_on.store(true, Ordering::Relaxed);
                        me.firewall_blocked
                            .fetch_add(report.applied, Ordering::Relaxed);
                        me.push_event(
                            severity::INFO,
                            format!(
                                "firewall: synced C2 blocklist — {} IP(s) blocked",
                                report.applied
                            ),
                            None,
                        );
                    }
                    Err(e) => {
                        me.push_event(severity::ERROR, format!("firewall sync failed: {e}"), None)
                    }
                }
            } else {
                match firewall::flush() {
                    Ok(()) => {
                        me.firewall_on.store(false, Ordering::Relaxed);
                        me.firewall_blocked.store(0, Ordering::Relaxed);
                        me.push_event(
                            severity::INFO,
                            "firewall: all Talos rules removed".to_string(),
                            None,
                        );
                    }
                    Err(e) => {
                        me.push_event(severity::ERROR, format!("firewall flush failed: {e}"), None)
                    }
                }
            }
        });
    }

    /// Block a single user-specified outbound IPv4 via the OS firewall.
    fn spawn_firewall_block(self: &Arc<Self>, ip: String) {
        let me = Arc::clone(self);
        std::thread::spawn(move || {
            use scanner_core::firewall;
            match firewall::block_ip(&ip) {
                Ok(()) => {
                    me.firewall_on.store(true, Ordering::Relaxed);
                    me.firewall_blocked.fetch_add(1, Ordering::Relaxed);
                    me.push_event(
                        severity::BLOCKED,
                        format!("firewall: blocked outbound {ip}"),
                        None,
                    );
                }
                Err(e) => me.push_event(
                    severity::ERROR,
                    format!("firewall: could not block {ip}: {e}"),
                    None,
                ),
            }
        });
    }

    /// Remove the firewall rule for a single user-specified outbound IPv4.
    fn spawn_firewall_unblock(self: &Arc<Self>, ip: String) {
        let me = Arc::clone(self);
        std::thread::spawn(move || {
            use scanner_core::firewall;
            match firewall::unblock_ip(&ip) {
                Ok(()) => {
                    let prev = me.firewall_blocked.load(Ordering::Relaxed);
                    me.firewall_blocked
                        .store(prev.saturating_sub(1), Ordering::Relaxed);
                    me.push_event(severity::INFO, format!("firewall: unblocked {ip}"), None);
                }
                Err(e) => me.push_event(
                    severity::ERROR,
                    format!("firewall: could not unblock {ip}: {e}"),
                    None,
                ),
            }
        });
    }

    /// Sync (on) or clear (off) the URLhaus malicious-domain hosts-file sinkhole.
    fn spawn_webprotect(self: &Arc<Self>, on: bool) {
        let me = Arc::clone(self);
        std::thread::spawn(move || {
            use scanner_core::webprotect;
            if on {
                match webprotect::sync_blocklist(webprotect::default_urlhaus_url()) {
                    Ok(report) => {
                        me.web_on.store(true, Ordering::Relaxed);
                        me.web_blocked.store(report.domains, Ordering::Relaxed);
                        me.push_event(
                            severity::INFO,
                            format!(
                                "web protection: {} malicious domain(s) blocked",
                                report.domains
                            ),
                            None,
                        );
                    }
                    Err(e) => me.push_event(
                        severity::ERROR,
                        format!("web protection sync failed: {e}"),
                        None,
                    ),
                }
            } else {
                match webprotect::clear() {
                    Ok(()) => {
                        me.web_on.store(false, Ordering::Relaxed);
                        me.web_blocked.store(0, Ordering::Relaxed);
                        me.push_event(
                            severity::INFO,
                            "web protection: domain blocklist cleared".to_string(),
                            None,
                        );
                    }
                    Err(e) => me.push_event(
                        severity::ERROR,
                        format!("web protection clear failed: {e}"),
                        None,
                    ),
                }
            }
        });
    }
}

/// Comma-separated detection names for an event message.
fn detection_names(report: &ScanReport) -> String {
    let names: Vec<&str> = report.detections.iter().map(|d| d.name.as_str()).collect();
    if names.is_empty() {
        "unknown".to_string()
    } else {
        names.join(", ")
    }
}

/// Quarantine each malicious report into `dir`; returns how many were stored.
fn quarantine_reports(dir: &Path, reports: &[ScanReport]) -> usize {
    let Ok(store) = Quarantine::open(dir) else {
        return 0;
    };
    let mut count = 0;
    for report in reports {
        let Some(hashes) = &report.hashes else {
            continue;
        };
        if store
            .quarantine_file(
                Path::new(&report.path),
                &hashes.sha256,
                report.size,
                report.detections.clone(),
            )
            .is_ok()
        {
            count += 1;
        }
    }
    count
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Clears the `scanning` flag on drop, so a scan thread always releases it even
/// if it panics.
struct ScanResetGuard<'a>(&'a AtomicBool);

impl Drop for ScanResetGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scanner_core::{Engine, HashSignatureDb};

    fn test_shared() -> Arc<Shared> {
        let engine = Arc::new(Engine::hash_only(HashSignatureDb::default()));
        let dir = std::env::temp_dir().join(format!("talos-agent-test-{}", std::process::id()));
        Arc::new(Shared::new(
            engine,
            Vec::new(),
            dir,
            "test-token".to_string(),
            1,
            3,
            Arc::new(AtomicBool::new(false)),
        ))
    }

    #[test]
    fn ping_reports_version_and_protocol() {
        let shared = test_shared();
        match shared.handle(Request::Ping) {
            Response::Pong { version, protocol } => {
                assert!(!version.is_empty());
                assert_eq!(protocol, PROTOCOL_VERSION);
            }
            other => panic!("expected pong, got {other:?}"),
        }
    }

    #[test]
    fn realtime_toggle_is_reflected_in_status() {
        let shared = test_shared();
        assert!(shared.realtime_enabled());
        let _ = shared.handle(Request::SetRealtime { on: false });
        match shared.handle(Request::GetStatus) {
            Response::Status(s) => assert!(!s.realtime),
            other => panic!("expected status, got {other:?}"),
        }
    }

    #[test]
    fn events_are_returned_after_their_cursor() {
        let shared = test_shared();
        shared.push_event(severity::INFO, "one".to_string(), None);
        shared.push_event(severity::INFO, "two".to_string(), None);
        match shared.handle(Request::GetEvents { since: 0 }) {
            Response::Events { events, next } => {
                assert_eq!(events.len(), 2);
                assert_eq!(next, 3);
                // Polling from the last seq returns nothing new.
                let last = events.last().unwrap().seq;
                match shared.handle(Request::GetEvents { since: last }) {
                    Response::Events { events, .. } => assert!(events.is_empty()),
                    other => panic!("expected events, got {other:?}"),
                }
            }
            other => panic!("expected events, got {other:?}"),
        }
    }

    #[test]
    fn shutdown_sets_the_flag() {
        let shared = test_shared();
        assert!(!shared.shutdown_requested());
        let _ = shared.handle(Request::Shutdown);
        assert!(shared.shutdown_requested());
    }

    #[test]
    fn start_scan_returns_an_incrementing_id() {
        let shared = test_shared();
        let first = match shared.handle(Request::StartScan {
            paths: vec!["/nonexistent/talos/path".to_string()],
            quarantine: false,
        }) {
            Response::ScanStarted { scan_id } => scan_id,
            other => panic!("expected scan_started, got {other:?}"),
        };
        assert_eq!(first, 1);
    }
}
