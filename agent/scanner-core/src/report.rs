//! Scan reports — the structured, serializable result of scanning an artifact.
//!
//! `ScanReport` is also the **client-side telemetry record**: it is exactly
//! what the agent would (after redaction/pseudonymization) forward to the
//! cloud. See docs/07-telemetry-flow.md.

use std::path::Path;
use std::time::Instant;

use serde::Serialize;

use crate::hashing::FileHashes;
use crate::verdict::{Detection, Disposition, Severity};

/// The outcome of scanning a single artifact.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub path: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<FileHashes>,
    pub disposition: Disposition,
    pub detections: Vec<Detection>,
    /// `false` when the file exceeded the in-memory cap and only the hash layer
    /// ran (YARA/content inspection skipped).
    pub content_inspected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub duration_ms: u64,
}

impl ScanReport {
    pub fn is_malicious(&self) -> bool {
        self.disposition == Disposition::Malicious
    }

    pub fn is_suspicious(&self) -> bool {
        self.disposition == Disposition::Suspicious
    }

    /// Highest severity among detections, if any.
    pub fn top_severity(&self) -> Option<Severity> {
        self.detections.iter().map(|d| d.severity).max()
    }

    pub(crate) fn completed(
        path: &Path,
        size: u64,
        hashes: FileHashes,
        detections: Vec<Detection>,
        content_inspected: bool,
        start: Instant,
    ) -> Self {
        let disposition = Disposition::classify(&detections);
        Self {
            path: path.display().to_string(),
            size,
            hashes: Some(hashes),
            disposition,
            detections,
            content_inspected,
            error: None,
            duration_ms: ms(start),
        }
    }

    pub(crate) fn skipped(path: &Path, size: u64, start: Instant) -> Self {
        Self {
            path: path.display().to_string(),
            size,
            hashes: None,
            disposition: Disposition::Skipped,
            detections: Vec::new(),
            content_inspected: false,
            error: None,
            duration_ms: ms(start),
        }
    }

    pub(crate) fn errored(path: &Path, size: u64, message: String, start: Instant) -> Self {
        Self {
            path: path.display().to_string(),
            size,
            hashes: None,
            disposition: Disposition::Error,
            detections: Vec::new(),
            content_inspected: false,
            error: Some(message),
            duration_ms: ms(start),
        }
    }

    pub(crate) fn walk_error(path: String, message: String) -> Self {
        Self {
            path,
            size: 0,
            hashes: None,
            disposition: Disposition::Error,
            detections: Vec::new(),
            content_inspected: false,
            error: Some(message),
            duration_ms: 0,
        }
    }
}

/// Aggregate counters over a directory scan.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanSummary {
    pub files_scanned: u64,
    pub malicious: u64,
    pub suspicious: u64,
    pub skipped: u64,
    pub errors: u64,
    pub bytes_scanned: u64,
    pub duration_ms: u64,
}

impl ScanSummary {
    /// Fold one report into the running totals.
    pub fn record(&mut self, report: &ScanReport) {
        match report.disposition {
            Disposition::Clean => {
                self.files_scanned += 1;
                self.bytes_scanned += report.size;
            }
            Disposition::Malicious => {
                self.files_scanned += 1;
                self.bytes_scanned += report.size;
                self.malicious += 1;
            }
            Disposition::Suspicious => {
                self.files_scanned += 1;
                self.bytes_scanned += report.size;
                self.suspicious += 1;
            }
            Disposition::Skipped => self.skipped += 1,
            Disposition::Error => self.errors += 1,
        }
    }
}

fn ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}
