//! File-processing pipeline: traverse a path and scan each regular file.
//!
//! Robustness rules (the pipeline must never panic or abort a whole scan
//! because of one bad file):
//! * Symlinks are not followed by default (avoids loops and scope escape).
//! * Only regular files are scanned (devices/sockets/FIFOs are skipped).
//! * Files above `max_content_bytes` are hashed by streaming but not loaded
//!   into memory for YARA — so we never OOM on a huge file.
//! * Any I/O error becomes an `Error` report; traversal continues.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, UNIX_EPOCH};

use rayon::prelude::*;
use walkdir::WalkDir;

use crate::archive::{self, ArchiveLimits};
use crate::cache::ScanCache;
use crate::engine::Engine;
use crate::hashing::{hash_bytes, hash_reader, FileHashes};
use crate::report::ScanReport;
use crate::verdict::{Detection, Disposition};

/// Default cap for loading a whole file into memory for content inspection.
pub const DEFAULT_MAX_CONTENT_BYTES: u64 = 128 * 1024 * 1024; // 128 MiB

/// Tunables for a scan run.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Files larger than this are hashed (streamed) but not YARA-scanned.
    pub max_content_bytes: u64,
    /// Whether to follow symbolic links during traversal and stat.
    pub follow_symlinks: bool,
    /// Optional recursion depth limit.
    pub max_depth: Option<usize>,
    /// Worker threads for parallel directory scans (`0` = all available cores).
    pub threads: usize,
    /// Paths to skip. A file is excluded if it equals, or lives under, any of
    /// these (user-configured trusted folders/files).
    pub exclusions: Vec<PathBuf>,
    /// Whether to look inside ZIP archives. Disable for faster, shallower scans.
    pub scan_archives: bool,
    /// Cooperative cancellation: raise this flag (from another thread) and the
    /// scan stops promptly — traversal halts and queued files are not scanned.
    /// Files already in flight finish, so partial results stay consistent.
    pub cancel: Option<Arc<AtomicBool>>,
    /// Optional incremental cache: clean files unchanged since a previous scan
    /// (same size+mtime, same definitions generation) are served from here
    /// without being re-read. Shared across worker threads.
    pub cache: Option<Arc<Mutex<ScanCache>>>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_content_bytes: DEFAULT_MAX_CONTENT_BYTES,
            follow_symlinks: false,
            max_depth: None,
            threads: 0,
            exclusions: Vec::new(),
            scan_archives: true,
            cancel: None,
            cache: None,
        }
    }
}

/// Drives the engine across the filesystem.
pub struct Scanner<'e> {
    engine: &'e Engine,
    options: ScanOptions,
}

impl<'e> Scanner<'e> {
    pub fn new(engine: &'e Engine) -> Self {
        Self {
            engine,
            options: ScanOptions::default(),
        }
    }

    pub fn with_options(engine: &'e Engine, options: ScanOptions) -> Self {
        Self { engine, options }
    }

    /// True if `path` equals or lives under any configured exclusion.
    fn is_excluded(&self, path: &Path) -> bool {
        let ex = &self.options.exclusions;
        !ex.is_empty() && ex.iter().any(|e| path == e || path.starts_with(e))
    }

    /// True when a caller-provided cancel flag has been raised.
    fn cancelled(&self) -> bool {
        self.options
            .cancel
            .as_ref()
            .is_some_and(|c| c.load(Ordering::Relaxed))
    }

    /// Scan a single path. Always returns a report (never panics).
    pub fn scan_file(&self, path: &Path) -> ScanReport {
        self.scan_file_with(path, None)
    }

    /// Scan a single path, optionally reusing a caller-provided YARA scanner.
    fn scan_file_with(
        &self,
        path: &Path,
        yara_scanner: Option<&mut yara_x::Scanner<'_>>,
    ) -> ScanReport {
        let start = Instant::now();

        // User-configured exclusions (trusted paths) are skipped outright.
        if self.is_excluded(path) {
            let size = fs::symlink_metadata(path).map(|m| m.len()).unwrap_or(0);
            return ScanReport::skipped(path, size, start);
        }

        let meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => return ScanReport::errored(path, 0, e.to_string(), start),
        };
        let ftype = meta.file_type();

        if ftype.is_symlink() && !self.options.follow_symlinks {
            return ScanReport::skipped(path, meta.len(), start);
        }

        // Resolve to a regular-file check (following the link only if allowed).
        let is_regular = if ftype.is_symlink() {
            fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
        } else {
            ftype.is_file()
        };
        if !is_regular {
            return ScanReport::skipped(path, meta.len(), start);
        }

        let (size, mtime_ns) = match fs::metadata(path) {
            Ok(m) => (m.len(), mtime_ns(&m)),
            Err(_) => (meta.len(), mtime_ns(&meta)),
        };

        // Incremental cache: a file unchanged (same size+mtime) since it was
        // scanned clean under the current definitions is served without being
        // re-read — the big win on repeat/scheduled scans.
        if let Some(cache) = &self.options.cache {
            if let Some(key) = path.to_str() {
                if let Some(hashes) = cache
                    .lock()
                    .ok()
                    .and_then(|c| c.get_clean(key, size, mtime_ns))
                {
                    return ScanReport::completed(path, size, hashes, Vec::new(), true, start);
                }
            }
        }

        // Choose the content path (load into memory) or hash-only (stream).
        let (hashes, content_inspected, content): (FileHashes, bool, Option<Vec<u8>>) =
            if size <= self.options.max_content_bytes {
                match fs::read(path) {
                    Ok(buf) => {
                        let h = hash_bytes(&buf);
                        (h, true, Some(buf))
                    }
                    Err(e) => return ScanReport::errored(path, size, e.to_string(), start),
                }
            } else {
                match fs::File::open(path).and_then(hash_reader) {
                    Ok((h, _)) => (h, false, None),
                    Err(e) => return ScanReport::errored(path, size, e.to_string(), start),
                }
            };

        let mut detections =
            match self
                .engine
                .evaluate_with(&hashes, content.as_deref(), yara_scanner)
            {
                Ok(d) => d,
                Err(e) => return ScanReport::errored(path, size, e.to_string(), start),
            };

        // If the file is a ZIP, scan its entries and fold any findings into this
        // report (so an infected archive is flagged as the archive that it is).
        if self.options.scan_archives {
            if let Some(bytes) = content.as_deref() {
                if archive::looks_like_zip(bytes) {
                    scan_archive_entries(self.engine, bytes, &mut detections);
                }
            }
        }

        let report =
            ScanReport::completed(path, size, hashes, detections, content_inspected, start);

        // Cache only clean, fully-inspected files — flagged files are always
        // re-evaluated, and hash-only (oversized) files are not cached.
        if report.disposition == Disposition::Clean && report.content_inspected {
            if let (Some(cache), Some(key), Some(h)) =
                (&self.options.cache, path.to_str(), report.hashes.as_ref())
            {
                if let Ok(mut c) = cache.lock() {
                    c.put_clean(key, size, mtime_ns, h.clone());
                }
            }
        }
        report
    }

    /// Walk `root` recursively, invoking `sink` for each report (streaming, so
    /// memory stays bounded even on huge trees).
    pub fn scan_path<F: FnMut(ScanReport)>(&self, root: &Path, mut sink: F) {
        let mut walker = WalkDir::new(root).follow_links(self.options.follow_symlinks);
        if let Some(depth) = self.options.max_depth {
            walker = walker.max_depth(depth);
        }
        for entry in walker.into_iter() {
            if self.cancelled() {
                break;
            }
            match entry {
                Ok(e) => {
                    if e.file_type().is_dir() {
                        continue;
                    }
                    sink(self.scan_file(e.path()));
                }
                Err(err) => {
                    let path = err
                        .path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<unknown>".to_string());
                    sink(ScanReport::walk_error(path, err.to_string()));
                }
            }
        }
    }

    /// Convenience wrapper that collects all reports into a `Vec`.
    pub fn scan_tree(&self, root: &Path) -> Vec<ScanReport> {
        let mut reports = Vec::new();
        self.scan_path(root, |r| reports.push(r));
        reports
    }

    /// Walk `root` and scan files **in parallel** across worker threads.
    ///
    /// This is the high-throughput path for large trees: traversal is done once
    /// (cheap), then files are scanned concurrently (`options.threads` workers,
    /// or all cores when `0`). The engine is shared immutably across threads;
    /// each YARA scan uses its own scanner, so there is no contention.
    pub fn scan_tree_parallel(&self, root: &Path) -> Vec<ScanReport> {
        let mut walker = WalkDir::new(root).follow_links(self.options.follow_symlinks);
        if let Some(depth) = self.options.max_depth {
            walker = walker.max_depth(depth);
        }

        let mut files: Vec<PathBuf> = Vec::new();
        let mut reports: Vec<ScanReport> = Vec::new();
        for entry in walker.into_iter() {
            if self.cancelled() {
                break;
            }
            match entry {
                Ok(e) => {
                    if !e.file_type().is_dir() {
                        files.push(e.into_path());
                    }
                }
                Err(err) => {
                    let path = err
                        .path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<unknown>".to_string());
                    reports.push(ScanReport::walk_error(path, err.to_string()));
                }
            }
        }

        // One reusable YARA scanner per worker thread (via `map_init`) — this is
        // what makes bulk scans fast: no per-file scanner construction. Once the
        // cancel flag is raised, remaining queued files are filtered out.
        let scan = || -> Vec<ScanReport> {
            files
                .par_iter()
                .filter(|_| !self.cancelled())
                .map_init(
                    || self.engine.new_yara_scanner(),
                    |scanner, path| self.scan_file_with(path, scanner.as_mut()),
                )
                .collect()
        };

        // `threads == 0` uses Rayon's global pool (all cores); otherwise run on a
        // bounded local pool so the agent can cap its CPU footprint.
        let scanned = if self.options.threads == 0 {
            scan()
        } else {
            match rayon::ThreadPoolBuilder::new()
                .num_threads(self.options.threads)
                .build()
            {
                Ok(pool) => pool.install(scan),
                Err(_) => scan(),
            }
        };

        reports.extend(scanned);
        reports
    }
}

/// Modification time of `meta` as nanoseconds since the Unix epoch (0 if
/// unavailable), the cheap change-detector for the incremental cache.
fn mtime_ns(meta: &fs::Metadata) -> u128 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Scan each entry of a ZIP buffer and append entry-attributed detections.
/// Nested archives are not recursed (each entry is evaluated as opaque bytes),
/// which together with [`ArchiveLimits`] bounds zip-bomb exposure.
fn scan_archive_entries(engine: &Engine, data: &[u8], detections: &mut Vec<Detection>) {
    let limits = ArchiveLimits::default();
    let _ = archive::for_each_zip_entry(data, &limits, |name, bytes, _truncated| {
        let hashes = hash_bytes(bytes);
        if let Ok(entry_detections) = engine.evaluate(&hashes, Some(bytes)) {
            for mut d in entry_detections {
                // Attribute the finding to the entry, e.g. "evil.exe → Rule".
                d.name = format!("{name} \u{2192} {}", d.name);
                detections.push(d);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Engine, HashSignatureDb, YaraEngine};
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

    #[test]
    fn infected_zip_is_flagged_with_entry_attribution() {
        let mut zip_bytes = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut zip_bytes));
            zw.start_file("payload/eicar.com", SimpleFileOptions::default())
                .unwrap();
            zw.write_all(EICAR).unwrap();
            zw.start_file("notes.txt", SimpleFileOptions::default())
                .unwrap();
            zw.write_all(b"benign").unwrap();
            zw.finish().unwrap();
        }

        let dir = tempfile::tempdir().unwrap();
        let zpath = dir.path().join("bundle.zip");
        std::fs::write(&zpath, &zip_bytes).unwrap();

        let yara = YaraEngine::from_sources([(
            "eicar",
            r#"rule Eicar { strings: $s = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" condition: $s }"#,
        )])
        .unwrap();
        let engine = Engine::new(HashSignatureDb::new(), Some(yara));
        let scanner = Scanner::new(&engine);

        let report = scanner.scan_file(&zpath);
        assert!(
            report.is_malicious(),
            "zip containing EICAR must be flagged"
        );
        assert!(
            report
                .detections
                .iter()
                .any(|d| d.name.contains("eicar.com") && d.name.contains("Eicar")),
            "detection should be attributed to the entry: {:?}",
            report.detections
        );
    }

    #[test]
    fn parallel_scan_finds_threats() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("eicar.com"), EICAR).unwrap();
        std::fs::write(dir.path().join("a.txt"), b"benign a").unwrap();
        std::fs::write(dir.path().join("b.txt"), b"benign b").unwrap();

        let yara = YaraEngine::from_sources([(
            "eicar",
            r#"rule Eicar { strings: $s = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" condition: $s }"#,
        )])
        .unwrap();
        let engine = Engine::new(HashSignatureDb::new(), Some(yara));
        let scanner = Scanner::new(&engine);

        let reports = scanner.scan_tree_parallel(dir.path());
        assert_eq!(reports.len(), 3, "all three files reported");
        assert_eq!(
            reports.iter().filter(|r| r.is_malicious()).count(),
            1,
            "only EICAR is malicious"
        );
    }

    fn eicar_engine() -> Engine {
        let yara = YaraEngine::from_sources([(
            "eicar",
            r#"rule Eicar { strings: $s = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" condition: $s }"#,
        )])
        .unwrap();
        Engine::new(HashSignatureDb::new(), Some(yara))
    }

    #[test]
    fn excluded_path_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let evil = dir.path().join("eicar.com");
        std::fs::write(&evil, EICAR).unwrap();

        let engine = eicar_engine();
        let opts = ScanOptions {
            exclusions: vec![evil.clone()],
            ..Default::default()
        };
        let scanner = Scanner::with_options(&engine, opts);

        let report = scanner.scan_file(&evil);
        assert!(
            !report.is_malicious(),
            "an excluded file must not be flagged"
        );
        assert_eq!(report.disposition, crate::Disposition::Skipped);
    }

    #[test]
    fn cancel_flag_stops_the_scan() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..32 {
            std::fs::write(dir.path().join(format!("f{i}.txt")), b"data").unwrap();
        }
        let engine = eicar_engine();
        let cancel = Arc::new(AtomicBool::new(true)); // raised before the scan starts
        let opts = ScanOptions {
            cancel: Some(cancel),
            ..Default::default()
        };
        let scanner = Scanner::with_options(&engine, opts);

        let mut streamed = 0;
        scanner.scan_path(dir.path(), |_| streamed += 1);
        assert_eq!(streamed, 0, "a raised flag stops streaming traversal");
        assert!(
            scanner.scan_tree_parallel(dir.path()).is_empty(),
            "a raised flag stops the parallel path too"
        );
    }

    #[test]
    fn cache_hit_short_circuits_the_real_scan() {
        let dir = tempfile::tempdir().unwrap();
        let evil = dir.path().join("eicar.com");
        std::fs::write(&evil, EICAR).unwrap();
        let meta = std::fs::metadata(&evil).unwrap();
        let mtns = mtime_ns(&meta);

        let engine = eicar_engine();
        // Pre-seed the cache asserting this exact (size, mtime) was clean. If the
        // scanner honours the cache it returns Clean *without* reading the file —
        // proving the read/scan was skipped (the file is really malicious).
        let mut cache = crate::cache::ScanCache::new(1);
        cache.put_clean(
            evil.to_str().unwrap(),
            meta.len(),
            mtns,
            crate::hashing::hash_bytes(b"placeholder"),
        );
        let opts = ScanOptions {
            cache: Some(Arc::new(Mutex::new(cache))),
            ..Default::default()
        };
        let scanner = Scanner::with_options(&engine, opts);
        assert!(
            !scanner.scan_file(&evil).is_malicious(),
            "a cache hit must skip the (malicious) re-scan"
        );

        // Control: with no cache the same file is really scanned and flagged.
        assert!(Scanner::new(&engine).scan_file(&evil).is_malicious());
    }

    #[test]
    fn clean_file_populates_then_serves_from_cache() {
        let dir = tempfile::tempdir().unwrap();
        let ok = dir.path().join("benign.txt");
        std::fs::write(&ok, b"nothing to see here").unwrap();

        let engine = eicar_engine();
        let cache = Arc::new(Mutex::new(crate::cache::ScanCache::new(1)));
        let opts = ScanOptions {
            cache: Some(cache.clone()),
            ..Default::default()
        };
        let scanner = Scanner::with_options(&engine, opts);

        assert!(!scanner.scan_file(&ok).is_malicious());
        assert_eq!(cache.lock().unwrap().len(), 1, "clean file is now cached");
        // Second pass is a cache hit and still reports clean.
        assert_eq!(
            scanner.scan_file(&ok).disposition,
            crate::Disposition::Clean
        );
    }

    #[test]
    fn archive_scanning_can_be_disabled() {
        let mut zip_bytes = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut zip_bytes));
            zw.start_file("eicar.com", SimpleFileOptions::default())
                .unwrap();
            zw.write_all(EICAR).unwrap();
            zw.finish().unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let zpath = dir.path().join("bundle.zip");
        std::fs::write(&zpath, &zip_bytes).unwrap();

        let engine = eicar_engine();
        let opts = ScanOptions {
            scan_archives: false,
            ..Default::default()
        };
        let scanner = Scanner::with_options(&engine, opts);
        assert!(
            !scanner.scan_file(&zpath).is_malicious(),
            "with archive scanning off, the zip interior is not inspected"
        );

        // Sanity: default options (archives on) still catch it.
        let scanner_on = Scanner::new(&engine);
        assert!(scanner_on.scan_file(&zpath).is_malicious());
    }
}
