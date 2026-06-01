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
}
