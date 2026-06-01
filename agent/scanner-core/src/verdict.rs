//! Verdict primitives: severity, detections, and disposition.

use serde::{Deserialize, Serialize};

/// Relative severity of a detection. Drives response policy downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Parse a severity from a YARA `severity` metadata string.
    /// Unknown / missing values fall back to `High` (conservative for a match).
    pub fn from_meta(s: &str) -> Severity {
        match s.trim().to_ascii_lowercase().as_str() {
            "low" => Severity::Low,
            "medium" | "med" => Severity::Medium,
            "critical" | "crit" => Severity::Critical,
            _ => Severity::High,
        }
    }
}

/// Which engine produced a detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionKind {
    /// Exact match against the known-bad hash database.
    HashSignature,
    /// Match of a compiled YARA rule.
    YaraRule,
}

/// A single finding against an artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    /// Signature family or YARA rule identifier.
    pub name: String,
    pub kind: DetectionKind,
    pub severity: Severity,
}

/// The outcome of scanning one artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    /// No detections.
    Clean,
    /// One or more detections.
    Malicious,
    /// Intentionally not scanned (e.g., symlink, non-regular file).
    Skipped,
    /// Could not be scanned due to an error.
    Error,
}
