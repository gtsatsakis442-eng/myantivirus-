//! ML-ready telemetry storage — the Telemetry Data Engine (Module 3).
//!
//! Every scan operation, verdict, intel response and heuristic flag is logged to
//! a local, queryable **SQLite** store (WAL mode) so it can serve as the training
//! dataset for predictive baseline learning. The design has one hard rule:
//!
//! > **The high-speed scan threads must never block on disk I/O.**
//!
//! So ingest is split from persistence:
//!
//! * Producers ([`TelemetrySink`], cloned into each scan thread) push records
//!   onto a **bounded, non-blocking** channel via `try_send`. If the buffer is
//!   momentarily full the record is **dropped** (and counted) rather than
//!   blocking the scanner — telemetry is best-effort and protection correctness
//!   never depends on it.
//! * A single **background worker** owns the SQLite connection, **batches**
//!   records, and commits them in one transaction (atomic, WAL-durable).
//!
//! Reads use independent connections (WAL permits concurrent readers), so the
//! analytics/query side never contends with the writer.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::error::{Result, ScanError};

/// How many records to accumulate before forcing a transaction commit.
const BATCH_SIZE: usize = 128;
/// Max time a record waits in the batch before being flushed.
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);
/// Default bounded-channel capacity (records buffered before drop-on-full).
pub const DEFAULT_CAPACITY: usize = 8192;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn db_err(e: rusqlite::Error) -> ScanError {
    ScanError::Telemetry(e.to_string())
}

/// Final disposition recorded for an artifact. Mirrors the engine's verdicts
/// plus the Module 2 suppression outcome, so the dataset distinguishes a true
/// benign from a *suppressed* false positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictStatus {
    #[default]
    Clean,
    Suspicious,
    Malicious,
    Benign,
    SuppressedFalsePositive,
}

impl VerdictStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            VerdictStatus::Clean => "clean",
            VerdictStatus::Suspicious => "suspicious",
            VerdictStatus::Malicious => "malicious",
            VerdictStatus::Benign => "benign",
            VerdictStatus::SuppressedFalsePositive => "suppressed_false_positive",
        }
    }

    /// Parse a stored verdict label back into a [`VerdictStatus`]. Named to
    /// avoid colliding with `std::str::FromStr::from_str`.
    pub fn from_label(s: &str) -> Option<Self> {
        Some(match s {
            "clean" => VerdictStatus::Clean,
            "suspicious" => VerdictStatus::Suspicious,
            "malicious" => VerdictStatus::Malicious,
            "benign" => VerdictStatus::Benign,
            "suppressed_false_positive" => VerdictStatus::SuppressedFalsePositive,
            _ => return None,
        })
    }
}

/// File-identity columns captured for every observation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileMetadata {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    /// Shannon entropy of the file content (0.0–8.0); a packing/encryption signal.
    pub entropy: f64,
}

/// One row of telemetry. `ts` and `endpoint_id` are stamped by the sink at
/// enqueue time, so callers leave them at their defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TelemetryRecord {
    pub ts: u64,
    pub endpoint_id: String,
    /// Process-tree lineage, root-first (ancestor image paths).
    pub process_lineage: Vec<String>,
    pub file: FileMetadata,
    /// Heuristic / behavioral rule ids that fired (e.g. MITRE-tagged names).
    pub heuristic_triggers: Vec<String>,
    pub verdict: VerdictStatus,
}

impl TelemetryRecord {
    /// A record carrying just a file + verdict; fill the rest with the setters.
    pub fn new(file: FileMetadata, verdict: VerdictStatus) -> Self {
        Self {
            verdict,
            file,
            ..Default::default()
        }
    }

    pub fn with_lineage(mut self, lineage: Vec<String>) -> Self {
        self.process_lineage = lineage;
        self
    }

    pub fn with_triggers(mut self, triggers: Vec<String>) -> Self {
        self.heuristic_triggers = triggers;
        self
    }
}

enum Msg {
    Record(Box<TelemetryRecord>),
    Stop,
}

/// A cheap, cloneable producer handle. Clone one into every scan thread; sending
/// is non-blocking and lock-free from the producer's side.
#[derive(Clone)]
pub struct TelemetrySink {
    tx: SyncSender<Msg>,
    dropped: Arc<AtomicU64>,
    endpoint_id: Arc<str>,
}

impl TelemetrySink {
    /// Enqueue a record. Returns `true` if buffered, `false` if the buffer was
    /// full and the record was dropped (never blocks the caller).
    pub fn record(&self, mut rec: TelemetryRecord) -> bool {
        if rec.ts == 0 {
            rec.ts = now_unix();
        }
        if rec.endpoint_id.is_empty() {
            rec.endpoint_id = self.endpoint_id.to_string();
        }
        match self.tx.try_send(Msg::Record(Box::new(rec))) {
            Ok(()) => true,
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Number of records dropped so far due to a full buffer (back-pressure).
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Owns the background writer thread and the SQLite store. Drop or [`stop`] to
/// flush remaining records and join the worker.
///
/// [`stop`]: TelemetryEngine::stop
pub struct TelemetryEngine {
    db_path: PathBuf,
    stop_tx: SyncSender<Msg>,
    handle: Option<JoinHandle<()>>,
}

impl TelemetryEngine {
    /// Open (or create) the store at `db_path` and start the writer thread.
    /// `endpoint_id` is stamped on every record from sinks of this engine.
    pub fn start(
        db_path: impl AsRef<Path>,
        endpoint_id: impl Into<String>,
    ) -> Result<(Self, TelemetrySink)> {
        Self::start_with_capacity(db_path, endpoint_id, DEFAULT_CAPACITY)
    }

    pub fn start_with_capacity(
        db_path: impl AsRef<Path>,
        endpoint_id: impl Into<String>,
        capacity: usize,
    ) -> Result<(Self, TelemetrySink)> {
        let db_path = db_path.as_ref().to_path_buf();
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ScanError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        // Open + configure on this thread so schema/WAL errors surface from start().
        let conn = open_db(&db_path)?;
        let (tx, rx) = sync_channel::<Msg>(capacity.max(1));
        let handle = thread::Builder::new()
            .name("talos-telemetry".to_string())
            .spawn(move || worker(conn, rx))
            .map_err(|e| ScanError::Telemetry(format!("spawn writer: {e}")))?;

        let sink = TelemetrySink {
            tx: tx.clone(),
            dropped: Arc::new(AtomicU64::new(0)),
            endpoint_id: Arc::from(endpoint_id.into()),
        };
        let engine = Self {
            db_path,
            stop_tx: tx,
            handle: Some(handle),
        };
        Ok((engine, sink))
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Flush remaining records and join the writer thread. Idempotent.
    pub fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            // Blocking send is fine here: shutdown *wants* to wait for capacity.
            let _ = self.stop_tx.send(Msg::Stop);
            let _ = handle.join();
        }
    }
}

impl Drop for TelemetryEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

fn open_db(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).map_err(db_err)?;
    // WAL: concurrent readers never block the single writer; NORMAL sync trades a
    // crash-window of the last commit for far higher throughput (telemetry, not
    // the source of truth for protection).
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(db_err)?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(db_err)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS telemetry (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            ts                 INTEGER NOT NULL,
            endpoint_id        TEXT    NOT NULL,
            process_lineage    TEXT    NOT NULL,
            file_path          TEXT    NOT NULL,
            file_size          INTEGER NOT NULL,
            sha256             TEXT    NOT NULL,
            entropy            REAL    NOT NULL,
            heuristic_triggers TEXT    NOT NULL,
            verdict            TEXT    NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_telemetry_ts      ON telemetry(ts);
         CREATE INDEX IF NOT EXISTS idx_telemetry_verdict ON telemetry(verdict);
         CREATE INDEX IF NOT EXISTS idx_telemetry_sha     ON telemetry(sha256);",
    )
    .map_err(db_err)?;
    Ok(conn)
}

fn worker(mut conn: Connection, rx: Receiver<Msg>) {
    let mut batch: Vec<TelemetryRecord> = Vec::with_capacity(BATCH_SIZE);
    loop {
        match rx.recv_timeout(FLUSH_INTERVAL) {
            Ok(Msg::Record(r)) => {
                batch.push(*r);
                if batch.len() >= BATCH_SIZE {
                    let _ = flush(&mut conn, &mut batch);
                }
            }
            Ok(Msg::Stop) => {
                let _ = flush(&mut conn, &mut batch);
                break;
            }
            Err(RecvTimeoutError::Timeout) => {
                let _ = flush(&mut conn, &mut batch);
            }
            Err(RecvTimeoutError::Disconnected) => {
                let _ = flush(&mut conn, &mut batch);
                break;
            }
        }
    }
}

fn flush(conn: &mut Connection, batch: &mut Vec<TelemetryRecord>) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let tx = conn.transaction().map_err(db_err)?;
    {
        let mut stmt = tx
            .prepare_cached(
                "INSERT INTO telemetry
                 (ts, endpoint_id, process_lineage, file_path, file_size, sha256, entropy, heuristic_triggers, verdict)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )
            .map_err(db_err)?;
        for r in batch.iter() {
            let lineage = serde_json::to_string(&r.process_lineage).unwrap_or_else(|_| "[]".into());
            let triggers =
                serde_json::to_string(&r.heuristic_triggers).unwrap_or_else(|_| "[]".into());
            stmt.execute(rusqlite::params![
                r.ts as i64,
                r.endpoint_id,
                lineage,
                r.file.path,
                r.file.size as i64,
                r.file.sha256,
                r.file.entropy,
                triggers,
                r.verdict.as_str(),
            ])
            .map_err(db_err)?;
        }
    }
    tx.commit().map_err(db_err)?;
    batch.clear();
    Ok(())
}

// ---------------------------------------------------------------------------
// Read / analytics side — independent connections (WAL allows concurrent reads)
// ---------------------------------------------------------------------------

/// Total number of telemetry rows persisted.
pub fn query_count(db_path: impl AsRef<Path>) -> Result<u64> {
    let conn = Connection::open(db_path).map_err(db_err)?;
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM telemetry", [], |row| row.get(0))
        .map_err(db_err)?;
    Ok(n as u64)
}

/// Row counts grouped by verdict, for at-a-glance dataset composition.
pub fn query_verdict_counts(db_path: impl AsRef<Path>) -> Result<Vec<(String, u64)>> {
    let conn = Connection::open(db_path).map_err(db_err)?;
    let mut stmt = conn
        .prepare("SELECT verdict, COUNT(*) FROM telemetry GROUP BY verdict ORDER BY verdict")
        .map_err(db_err)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        })
        .map_err(db_err)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(db_err)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(path: &str, sha: &str, verdict: VerdictStatus) -> TelemetryRecord {
        TelemetryRecord::new(
            FileMetadata {
                path: path.to_string(),
                size: 1024,
                sha256: sha.to_string(),
                entropy: 7.2,
            },
            verdict,
        )
    }

    #[test]
    fn verdict_status_round_trips() {
        for v in [
            VerdictStatus::Clean,
            VerdictStatus::Suspicious,
            VerdictStatus::Malicious,
            VerdictStatus::Benign,
            VerdictStatus::SuppressedFalsePositive,
        ] {
            assert_eq!(VerdictStatus::from_label(v.as_str()), Some(v));
        }
        assert_eq!(VerdictStatus::from_label("nonsense"), None);
    }

    #[test]
    fn records_persist_and_are_queryable() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("telemetry.db");

        let (mut engine, sink) = TelemetryEngine::start(&db, "endpoint-01").unwrap();
        sink.record(rec("C:/a.exe", "aa", VerdictStatus::Malicious));
        sink.record(rec(
            "C:/b.dll",
            "bb",
            VerdictStatus::SuppressedFalsePositive,
        ));
        sink.record(rec("C:/c.txt", "cc", VerdictStatus::Clean));
        sink.record(rec("C:/d.exe", "dd", VerdictStatus::Malicious));
        engine.stop(); // flush + join

        assert_eq!(query_count(&db).unwrap(), 4);
        let counts = query_verdict_counts(&db).unwrap();
        let malicious = counts.iter().find(|(v, _)| v == "malicious").unwrap().1;
        assert_eq!(malicious, 2);
        assert!(counts
            .iter()
            .any(|(v, n)| v == "suppressed_false_positive" && *n == 1));
    }

    #[test]
    fn stamps_ts_and_endpoint_id() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let (mut engine, sink) = TelemetryEngine::start(&db, "host-XYZ").unwrap();
        sink.record(rec("/tmp/x", "ff", VerdictStatus::Benign));
        engine.stop();

        let conn = Connection::open(&db).unwrap();
        let (eid, ts): (String, i64) = conn
            .query_row("SELECT endpoint_id, ts FROM telemetry LIMIT 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(eid, "host-XYZ");
        assert!(ts > 0, "ts should be stamped");
    }

    #[test]
    fn lineage_and_triggers_stored_as_json() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let (mut engine, sink) = TelemetryEngine::start(&db, "h").unwrap();
        let r = rec("/x", "ab", VerdictStatus::Suspicious)
            .with_lineage(vec!["explorer.exe".into(), "app.exe".into()])
            .with_triggers(vec!["Behavior.Injection [T1055]".into()]);
        sink.record(r);
        engine.stop();

        let conn = Connection::open(&db).unwrap();
        let (lineage, triggers): (String, String) = conn
            .query_row(
                "SELECT process_lineage, heuristic_triggers FROM telemetry LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let lin: Vec<String> = serde_json::from_str(&lineage).unwrap();
        let trg: Vec<String> = serde_json::from_str(&triggers).unwrap();
        assert_eq!(lin, vec!["explorer.exe", "app.exe"]);
        assert_eq!(trg, vec!["Behavior.Injection [T1055]"]);
    }

    #[test]
    fn wal_mode_is_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let (engine, _sink) = TelemetryEngine::start(&db, "h").unwrap();
        let mode: String = Connection::open(&db)
            .unwrap()
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
        drop(engine);
    }

    #[test]
    fn full_buffer_drops_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        // Capacity 1 + a verdict that makes the worker slow is hard to force
        // deterministically; instead assert record() returns promptly and that
        // dropped() is observable when we vastly outpace a tiny buffer.
        let (mut engine, sink) = TelemetryEngine::start_with_capacity(&db, "h", 1).unwrap();
        let start = std::time::Instant::now();
        let mut dropped_any = false;
        for i in 0..5000 {
            let enqueued = sink.record(rec("/x", "ab", VerdictStatus::Clean));
            if !enqueued {
                dropped_any = true;
            }
            let _ = i;
        }
        // The loop must not have blocked for long even if the writer is behind.
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "producer must not block on a full buffer"
        );
        engine.stop();
        // Either everything fit through (fast writer) or some were dropped — both
        // are valid; if dropped, the counter must be non-zero and consistent.
        if dropped_any {
            assert!(sink.dropped() > 0);
        }
    }
}
