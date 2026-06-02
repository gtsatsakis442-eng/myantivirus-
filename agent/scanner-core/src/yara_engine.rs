//! YARA detection layer, backed by `yara-x` (VirusTotal's pure-Rust YARA).
//!
//! Using the pure-Rust engine avoids a libyara C build dependency, which keeps
//! cross-platform CI simple.

use std::path::Path;

use walkdir::WalkDir;
use yara_x::{Compiler, Rules};

use crate::error::{Result, ScanError};
use crate::verdict::{Detection, DetectionKind, Severity};

/// A compiled set of YARA rules ready to scan buffers.
pub struct YaraEngine {
    rules: Rules,
    source_files: usize,
}

impl YaraEngine {
    /// Compile rules from `(origin, source)` pairs. `origin` is only used to
    /// produce a readable error if compilation fails.
    pub fn from_sources<I, S1, S2>(sources: I) -> Result<Self>
    where
        I: IntoIterator<Item = (S1, S2)>,
        S1: AsRef<str>,
        S2: AsRef<str>,
    {
        let mut compiler = Compiler::new();
        let mut source_files = 0usize;
        for (origin, src) in sources {
            compiler
                .add_source(src.as_ref())
                .map_err(|e| ScanError::Yara(format!("{}: {e}", origin.as_ref())))?;
            source_files += 1;
        }
        let rules = compiler.build();
        Ok(Self {
            rules,
            source_files,
        })
    }

    /// Compile every `*.yar` / `*.yara` file found recursively under `dir`.
    /// Files are compiled in sorted path order for deterministic builds.
    pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        let mut sources: Vec<(String, String)> = Vec::new();
        for entry in WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let is_yara = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"))
                .unwrap_or(false);
            if !is_yara {
                continue;
            }
            let text = std::fs::read_to_string(path).map_err(|source| ScanError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            sources.push((path.display().to_string(), text));
        }
        sources.sort_by(|a, b| a.0.cmp(&b.0));
        Self::from_sources(sources)
    }

    /// Like [`YaraEngine::from_sources`], but **skips** sources that fail to
    /// compile (unsupported features, duplicate rule names, …), returning the
    /// engine plus the skipped origins. This lets the engine ingest large
    /// third-party rulesets without one bad rule breaking everything.
    pub fn from_sources_lenient<I, S1, S2>(sources: I) -> (Self, Vec<String>)
    where
        I: IntoIterator<Item = (S1, S2)>,
        S1: AsRef<str>,
        S2: AsRef<str>,
    {
        let mut compiler = Compiler::new();
        let mut source_files = 0usize;
        let mut skipped = Vec::new();
        for (origin, src) in sources {
            // Validate the source in isolation, then add it to the real compiler.
            let mut probe = Compiler::new();
            if probe.add_source(src.as_ref()).is_err() || compiler.add_source(src.as_ref()).is_err()
            {
                skipped.push(origin.as_ref().to_string());
                continue;
            }
            source_files += 1;
        }
        let rules = compiler.build();
        (
            Self {
                rules,
                source_files,
            },
            skipped,
        )
    }

    /// Compile every `*.yar`/`*.yara` under `dir`, skipping files that fail to
    /// compile. Returns the engine plus skipped file paths.
    pub fn from_dir_lenient(dir: impl AsRef<Path>) -> (Self, Vec<String>) {
        let dir = dir.as_ref();
        let mut sources: Vec<(String, String)> = Vec::new();
        if dir.is_dir() {
            for entry in WalkDir::new(dir)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry.path();
                let is_yara = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"))
                    .unwrap_or(false);
                if is_yara {
                    if let Ok(text) = std::fs::read_to_string(path) {
                        sources.push((path.display().to_string(), text));
                    }
                }
            }
            sources.sort_by(|a, b| a.0.cmp(&b.0));
        }
        Self::from_sources_lenient(sources)
    }

    /// Number of source files that were compiled into this rule set.
    pub fn source_files(&self) -> usize {
        self.source_files
    }

    /// A reusable scanner over the compiled rules. Reusing one scanner across
    /// many files (e.g. one per worker thread) avoids the per-file cost of
    /// constructing a scanner — the main lever for fast bulk scans.
    pub(crate) fn scanner(&self) -> yara_x::Scanner<'_> {
        yara_x::Scanner::new(&self.rules)
    }

    /// Scan an in-memory buffer, returning one detection per matching rule.
    /// A rule's `severity` metadata string (if present) sets the severity.
    pub fn scan(&self, data: &[u8]) -> Result<Vec<Detection>> {
        let mut scanner = self.scanner();
        scan_with(&mut scanner, data)
    }
}

/// Run a (reusable) compiled scanner over `data` and map matches to detections.
pub(crate) fn scan_with(scanner: &mut yara_x::Scanner<'_>, data: &[u8]) -> Result<Vec<Detection>> {
    let results = scanner
        .scan(data)
        .map_err(|e| ScanError::Yara(e.to_string()))?;

    let mut detections = Vec::new();
    for rule in results.matching_rules() {
        let mut severity = Severity::High;
        for (key, value) in rule.metadata() {
            if key.eq_ignore_ascii_case("severity") {
                if let yara_x::MetaValue::String(s) = value {
                    severity = Severity::from_meta(s);
                }
            }
        }
        detections.push(Detection {
            name: rule.identifier().to_string(),
            kind: DetectionKind::YaraRule,
            severity,
        });
    }
    Ok(detections)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

    const RULE: &str = r#"
rule Eicar_Test_File {
    meta:
        severity = "low"
    strings:
        $s = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    condition:
        $s
}
"#;

    #[test]
    fn compiles_and_matches() {
        let engine = YaraEngine::from_sources([("inline", RULE)]).unwrap();
        assert_eq!(engine.source_files(), 1);

        let hits = engine.scan(EICAR).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "Eicar_Test_File");
        assert_eq!(hits[0].kind, DetectionKind::YaraRule);
        assert_eq!(hits[0].severity, Severity::Low);

        assert!(engine.scan(b"totally benign content").unwrap().is_empty());
    }

    #[test]
    fn compile_error_is_reported() {
        let err = YaraEngine::from_sources([("bad", "rule X { condition: nonsense_token }")]);
        assert!(matches!(err, Err(ScanError::Yara(_))));
    }
}
