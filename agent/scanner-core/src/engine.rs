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
    heuristics: bool,
    behavior: bool,
}

impl Engine {
    pub fn new(hashes: HashSignatureDb, yara: Option<YaraEngine>) -> Self {
        Self {
            hashes,
            yara,
            heuristics: true,
            behavior: true,
        }
    }

    /// Engine with only the hash layer loaded.
    pub fn hash_only(hashes: HashSignatureDb) -> Self {
        Self {
            hashes,
            yara: None,
            heuristics: true,
            behavior: true,
        }
    }

    /// Enable or disable the static heuristic layer (L2). Hash and YARA layers
    /// are unaffected. Returns `self` for builder-style configuration.
    pub fn with_heuristics(mut self, on: bool) -> Self {
        self.heuristics = on;
        self
    }

    /// Toggle the static heuristic layer in place.
    pub fn set_heuristics(&mut self, on: bool) {
        self.heuristics = on;
    }

    /// Toggle the static behavioral capability layer (L2.5) in place.
    pub fn set_behavior(&mut self, on: bool) {
        self.behavior = on;
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
        self.evaluate_inner(hashes, content, None)
    }

    /// Like [`Engine::evaluate`] but reuses a caller-provided YARA scanner — used
    /// by the parallel scan path, which keeps one scanner per worker thread.
    pub(crate) fn evaluate_with(
        &self,
        hashes: &FileHashes,
        content: Option<&[u8]>,
        yara_scanner: Option<&mut yara_x::Scanner<'_>>,
    ) -> Result<Vec<Detection>> {
        self.evaluate_inner(hashes, content, yara_scanner)
    }

    /// A reusable YARA scanner over the loaded rules, if YARA is enabled.
    pub(crate) fn new_yara_scanner(&self) -> Option<yara_x::Scanner<'_>> {
        self.yara.as_ref().map(|y| y.scanner())
    }

    fn evaluate_inner(
        &self,
        hashes: &FileHashes,
        content: Option<&[u8]>,
        yara_scanner: Option<&mut yara_x::Scanner<'_>>,
    ) -> Result<Vec<Detection>> {
        let mut detections = Vec::new();

        if let Some(name) = self.hashes.lookup(&hashes.sha256) {
            detections.push(Detection {
                name: name.to_string(),
                kind: DetectionKind::HashSignature,
                severity: Severity::Critical,
            });
        }

        if let Some(bytes) = content {
            match yara_scanner {
                // Reuse the provided scanner (parallel path).
                Some(scanner) => detections.extend(crate::yara_engine::scan_with(scanner, bytes)?),
                // Otherwise build a one-off scanner via the engine.
                None => {
                    if let Some(engine) = self.yara.as_ref() {
                        detections.extend(engine.scan(bytes)?);
                    }
                }
            }
            // Static heuristics (L2) run on PE content; no-op for other files.
            if self.heuristics {
                detections.extend(crate::heuristics::analyze(bytes));
            }
            // Static behavioral capability analysis (L2.5); no-op for non-PE.
            if self.behavior {
                detections.extend(crate::behavior::analyze(bytes));
            }
        }

        Ok(detections)
    }
}
