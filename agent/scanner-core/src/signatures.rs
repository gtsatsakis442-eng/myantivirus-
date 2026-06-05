//! Hash-signature database (known-bad SHA-256 → family name).
//!
//! Database format (one signature per line):
//! ```text
//! # comment lines start with '#'
//! <sha256-hex>  <family name with spaces allowed>
//! ```
//! Parsing is strict: a malformed hash aborts the load with a line number, so a
//! corrupt or truncated database is caught at startup rather than silently
//! degrading detection (integrity matters — see docs/03-secure-updates.md).

use std::collections::HashMap;
use std::path::Path;

use crate::error::{Result, ScanError};

/// In-memory set of known-bad SHA-256 digests.
#[derive(Debug, Default, Clone)]
pub struct HashSignatureDb {
    /// lowercase sha256 hex -> family name
    entries: HashMap<String, String>,
}

impl HashSignatureDb {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a database from an in-memory string.
    pub fn from_str_db(text: &str) -> Result<Self> {
        let mut db = HashSignatureDb::new();
        for (idx, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(2, char::is_whitespace);
            let hash = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
            let name = parts.next().map(str::trim).unwrap_or("").to_string();

            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(ScanError::SignatureDb(format!(
                    "line {}: invalid SHA-256 '{}' (expected 64 hex chars)",
                    idx + 1,
                    hash
                )));
            }
            let name = if name.is_empty() {
                "Unnamed.Signature".to_string()
            } else {
                name
            };
            db.entries.insert(hash, name);
        }
        Ok(db)
    }

    /// Load a database from a file on disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ScanError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_str_db(&text)
    }

    /// Look up a SHA-256 (any case); returns the family name on a hit.
    pub fn lookup(&self, sha256_hex: &str) -> Option<&str> {
        self.entries
            .get(&sha256_hex.to_ascii_lowercase())
            .map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Merge entries from a database string, **skipping** malformed lines
    /// (used for large external feeds where strictness is undesirable).
    /// Returns the number of new signatures added.
    pub fn extend_lenient(&mut self, text: &str) -> usize {
        let mut added = 0;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(2, char::is_whitespace);
            let hash = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let name = parts
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("Unnamed.Signature")
                .to_string();
            if self.entries.insert(hash, name).is_none() {
                added += 1;
            }
        }
        added
    }

    /// Merge every `*.hashdb` file in `dir` (lenient). A missing dir is empty.
    pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        let mut db = HashSignatureDb::new();
        if !dir.is_dir() {
            return Ok(db);
        }
        let rd = std::fs::read_dir(dir).map_err(|source| ScanError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let mut files: Vec<_> = rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.extension()
                    .and_then(|x| x.to_str())
                    .map(|x| x.eq_ignore_ascii_case("hashdb"))
                    .unwrap_or(false)
            })
            .collect();
        files.sort();
        for f in files {
            if let Ok(text) = std::fs::read_to_string(&f) {
                db.extend_lenient(&text);
            }
        }
        Ok(db)
    }

    /// Merge another database into this one (other wins on key collisions).
    pub fn merge(&mut self, other: HashSignatureDb) {
        self.entries.extend(other.entries);
    }
}

/// Keep only characters safe for a one-token family label.
fn sanitize_family(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'))
        .collect()
}

/// Turn NDJSON scan reports (the output of `scan --json`) into hash-signature
/// database text — the **feedback loop** that grows the database from real
/// scans.
///
/// Extracts the SHA-256 of every **malicious** report (and **suspicious** too
/// when `include_suspicious`), labelled by its first detection name or, failing
/// that, `family`. Returns `(unique_count, hashdb_text)` in our
/// `<sha256>  Family` format; duplicates within the input are merged.
///
/// Only the hash + label are taken — file paths and other telemetry are ignored,
/// so a shared log reveals no local paths. The caller is responsible for vetting
/// that the entries are genuinely malicious before shipping them (a hash
/// signature is exact-match and permanent).
pub fn ingest_reports(ndjson: &str, include_suspicious: bool, family: &str) -> (usize, String) {
    use serde_json::Value;

    let mut out = String::new();
    let mut seen = std::collections::HashSet::new();
    for line in ndjson.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let disp = v.get("disposition").and_then(Value::as_str).unwrap_or("");
        if disp != "malicious" && !(include_suspicious && disp == "suspicious") {
            continue;
        }
        let sha = match v.pointer("/hashes/sha256").and_then(Value::as_str) {
            Some(s) => s.trim().to_ascii_lowercase(),
            None => continue,
        };
        if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        if !seen.insert(sha.clone()) {
            continue;
        }
        let label = v
            .pointer("/detections/0/name")
            .and_then(Value::as_str)
            .map(sanitize_family)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| family.to_string());
        out.push_str(&sha);
        out.push_str("  ");
        out.push_str(&label);
        out.push('\n');
    }
    (seen.len(), out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    #[test]
    fn parses_and_looks_up() {
        let db =
            HashSignatureDb::from_str_db(&format!("# header\n\n{EICAR_SHA256}  Eicar.Test.File\n"))
                .unwrap();
        assert_eq!(db.len(), 1);
        // Case-insensitive lookup.
        assert_eq!(
            db.lookup(&EICAR_SHA256.to_uppercase()),
            Some("Eicar.Test.File")
        );
        assert_eq!(db.lookup("deadbeef"), None);
    }

    #[test]
    fn rejects_malformed_hash() {
        let err = HashSignatureDb::from_str_db("nothex  Bad").unwrap_err();
        assert!(matches!(err, ScanError::SignatureDb(_)));
    }

    #[test]
    fn unnamed_signature_gets_placeholder() {
        let db = HashSignatureDb::from_str_db(EICAR_SHA256).unwrap();
        assert_eq!(db.lookup(EICAR_SHA256), Some("Unnamed.Signature"));
    }

    #[test]
    fn ingest_extracts_malicious_hashes_only_by_default() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let log = format!(
            "{{\"path\":\"/x/evil\",\"disposition\":\"malicious\",\"hashes\":{{\"sha256\":\"{EICAR_SHA256}\"}},\"detections\":[{{\"name\":\"Eicar.Test.File\"}}]}}\n\
             {{\"path\":\"/x/ok\",\"disposition\":\"clean\",\"hashes\":{{\"sha256\":\"{a}\"}}}}\n\
             {{\"path\":\"/x/susp\",\"disposition\":\"suspicious\",\"hashes\":{{\"sha256\":\"{b}\"}}}}\n"
        );
        let (n, text) = ingest_reports(&log, false, "Talos.Ingested");
        assert_eq!(n, 1, "only the malicious entry by default");
        assert!(text.contains(&format!("{EICAR_SHA256}  Eicar.Test.File")));
        // duplicates within input are merged; suspicious included on request.
        let (n2, _) = ingest_reports(&log, true, "Talos.Ingested");
        assert_eq!(n2, 2);
    }
}
