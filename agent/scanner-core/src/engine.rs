//! The combined detection engine: hash signatures + optional YARA.

use crate::error::Result;
use crate::hashing::FileHashes;
use crate::signatures::HashSignatureDb;
use crate::verdict::{Detection, DetectionKind, Severity};
use crate::yara_engine::YaraEngine;

/// Holds the loaded detection content and fuses the two layers into a verdict.
pub struct Engine {
    hashes: HashSignatureDb,
    yara: Option<YaraEngine>,
}

impl Engine {
    pub fn new(hashes: HashSignatureDb, yara: Option<YaraEngine>) -> Self {
        Self { hashes, yara }
    }

    /// Engine with only the hash layer loaded.
    pub fn hash_only(hashes: HashSignatureDb) -> Self {
        Self { hashes, yara: None }
    }

    pub fn hash_db(&self) -> &HashSignatureDb {
        &self.hashes
    }

    pub fn yara(&self) -> Option<&YaraEngine> {
        self.yara.as_ref()
    }

    /// Evaluate content that has already been hashed.
    ///
    /// `content` is `None` when the file was too large to load into memory; in
    /// that case only the (streamed) hash layer runs. Hash matches are treated
    /// as `Critical` — an exact match against known-bad is high-confidence.
    pub fn evaluate(&self, hashes: &FileHashes, content: Option<&[u8]>) -> Result<Vec<Detection>> {
        let mut detections = Vec::new();

        if let Some(name) = self.hashes.lookup(&hashes.sha256) {
            detections.push(Detection {
                name: name.to_string(),
                kind: DetectionKind::HashSignature,
                severity: Severity::Critical,
            });
        }

        if let Some(bytes) = content {
            if let Some(engine) = self.yara.as_ref() {
                detections.extend(engine.scan(bytes)?);
            }
            // Static heuristics (L2) run on PE content; no-op for other files.
            detections.extend(crate::heuristics::analyze(bytes));
        }

        Ok(detections)
    }
}
