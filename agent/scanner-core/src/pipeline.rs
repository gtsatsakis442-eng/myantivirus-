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

use crate::archive::{self, ArchiveLimits};
use crate::engine::Engine;
use crate::hashing::{hash_bytes, hash_reader, FileHashes};
use crate::report::ScanReport;
use crate::verdict::Detection;

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

        let mut detections = match self.engine.evaluate(&hashes, content.as_deref()) {
            Ok(d) => d,
            Err(e) => return ScanReport::errored(path, size, e.to_string(), start),
        };

        // If the file is a ZIP, scan its entries and fold any findings into this
        // report (so an infected archive is flagged as the archive that it is).
        if let Some(bytes) = content.as_deref() {
            if archive::looks_like_zip(bytes) {
                scan_archive_entries(self.engine, bytes, &mut detections);
            }
        }

        ScanReport::completed(path, size, hashes, detections, content_inspected, start)
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
}
