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
use std::path::Path;
use std::time::Instant;

use walkdir::WalkDir;

use crate::engine::Engine;
use crate::hashing::{hash_bytes, hash_reader, FileHashes};
use crate::report::ScanReport;

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
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_content_bytes: DEFAULT_MAX_CONTENT_BYTES,
            follow_symlinks: false,
            max_depth: None,
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

    /// Scan a single path. Always returns a report (never panics).
    pub fn scan_file(&self, path: &Path) -> ScanReport {
        let start = Instant::now();

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

        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(meta.len());

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

        match self.engine.evaluate(&hashes, content.as_deref()) {
            Ok(detections) => {
                ScanReport::completed(path, size, hashes, detections, content_inspected, start)
            }
            Err(e) => ScanReport::errored(path, size, e.to_string(), start),
        }
    }

    /// Walk `root` recursively, invoking `sink` for each report (streaming, so
    /// memory stays bounded even on huge trees).
    pub fn scan_path<F: FnMut(ScanReport)>(&self, root: &Path, mut sink: F) {
        let mut walker = WalkDir::new(root).follow_links(self.options.follow_symlinks);
        if let Some(depth) = self.options.max_depth {
            walker = walker.max_depth(depth);
        }
        for entry in walker.into_iter() {
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
}
