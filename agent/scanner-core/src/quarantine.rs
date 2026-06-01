//! Quarantine vault: isolate, list, restore, and purge detected files.
//!
//! Quarantined files are "defanged" by XOR-transforming their bytes with a
//! fixed key. This is **not** encryption — it just ensures the stored sample
//! cannot accidentally execute or be re-scanned/re-detected, while preserving
//! the exact bytes so a false positive can be restored. The original file is
//! removed from its location only after the vault copy is safely written.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{Result, ScanError};
use crate::verdict::Detection;

/// XOR key used to defang stored samples (NOT a security control).
const DEFANG_KEY: u8 = 0x5A;

/// A record of one quarantined artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub sha256: String,
    pub size: u64,
    pub quarantined_at_unix: u64,
    pub detections: Vec<Detection>,
}

/// A simple, file-backed quarantine store rooted at a directory.
pub struct Quarantine {
    root: PathBuf,
}

impl Quarantine {
    /// Open (creating if needed) a quarantine store at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let vault = root.join("vault");
        fs::create_dir_all(&vault).map_err(|source| ScanError::Io {
            path: vault.clone(),
            source,
        })?;
        Ok(Self { root })
    }

    fn manifest_path(&self) -> PathBuf {
        self.root.join("manifest.json")
    }

    fn blob_path(&self, id: &str) -> PathBuf {
        self.root.join("vault").join(format!("{id}.qbin"))
    }

    /// All current entries (empty if the store is fresh).
    pub fn list(&self) -> Result<Vec<QuarantineEntry>> {
        let path = self.manifest_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let text = fs::read_to_string(&path).map_err(|source| ScanError::Io {
            path: path.clone(),
            source,
        })?;
        if text.trim().is_empty() {
            return Ok(Vec::new());
        }
        serde_json::from_str(&text)
            .map_err(|e| ScanError::Quarantine(format!("corrupt manifest: {e}")))
    }

    fn save(&self, entries: &[QuarantineEntry]) -> Result<()> {
        let text = serde_json::to_string_pretty(entries)
            .map_err(|e| ScanError::Quarantine(e.to_string()))?;
        // Write to a temp file then rename, so the manifest is never half-written.
        let tmp = self.manifest_path().with_extension("json.tmp");
        fs::write(&tmp, text).map_err(|source| ScanError::Io {
            path: tmp.clone(),
            source,
        })?;
        fs::rename(&tmp, self.manifest_path()).map_err(|source| ScanError::Io {
            path: self.manifest_path(),
            source,
        })
    }

    /// Isolate `path` into the vault. Removes the original on success.
    pub fn quarantine_file(
        &self,
        path: &Path,
        sha256: &str,
        size: u64,
        detections: Vec<Detection>,
    ) -> Result<QuarantineEntry> {
        let mut bytes = fs::read(path).map_err(|source| ScanError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        defang(&mut bytes);

        let id = new_id(sha256);
        let blob = self.blob_path(&id);
        fs::write(&blob, &bytes).map_err(|source| ScanError::Io {
            path: blob.clone(),
            source,
        })?;

        let entry = QuarantineEntry {
            id,
            original_path: path.display().to_string(),
            sha256: sha256.to_string(),
            size,
            quarantined_at_unix: now_unix(),
            detections,
        };

        let mut entries = self.list()?;
        entries.push(entry.clone());
        self.save(&entries)?;

        // Remove the original only after the vault copy + manifest are persisted.
        fs::remove_file(path).map_err(|source| ScanError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(entry)
    }

    /// Restore a quarantined file to `dest` (or its original path if `None`).
    /// Returns the path the file was restored to.
    pub fn restore(&self, id: &str, dest: Option<&Path>) -> Result<PathBuf> {
        let mut entries = self.list()?;
        let pos = entries
            .iter()
            .position(|e| e.id == id)
            .ok_or_else(|| ScanError::Quarantine(format!("no quarantine entry with id '{id}'")))?;
        let entry = entries[pos].clone();

        let blob = self.blob_path(id);
        let mut bytes = fs::read(&blob).map_err(|source| ScanError::Io {
            path: blob.clone(),
            source,
        })?;
        defang(&mut bytes); // XOR is its own inverse.

        let target = dest
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(&entry.original_path));
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|source| ScanError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        fs::write(&target, &bytes).map_err(|source| ScanError::Io {
            path: target.clone(),
            source,
        })?;

        let _ = fs::remove_file(&blob);
        entries.remove(pos);
        self.save(&entries)?;
        Ok(target)
    }

    /// Permanently delete one quarantined entry and its stored blob.
    pub fn purge(&self, id: &str) -> Result<()> {
        let mut entries = self.list()?;
        let pos = entries
            .iter()
            .position(|e| e.id == id)
            .ok_or_else(|| ScanError::Quarantine(format!("no quarantine entry with id '{id}'")))?;
        let _ = fs::remove_file(self.blob_path(id));
        entries.remove(pos);
        self.save(&entries)
    }

    /// Delete every quarantined entry; returns how many were removed.
    pub fn purge_all(&self) -> Result<usize> {
        let entries = self.list()?;
        for e in &entries {
            let _ = fs::remove_file(self.blob_path(&e.id));
        }
        let n = entries.len();
        self.save(&[])?;
        Ok(n)
    }
}

fn defang(data: &mut [u8]) {
    for b in data.iter_mut() {
        *b ^= DEFANG_KEY;
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn new_id(sha256: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let prefix = &sha256[..sha256.len().min(16)];
    format!("{prefix}-{millis}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{DetectionKind, Severity};

    fn det() -> Detection {
        Detection {
            name: "Test.Malware".to_string(),
            kind: DetectionKind::HashSignature,
            severity: Severity::Critical,
        }
    }

    #[test]
    fn quarantine_then_restore_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let q = Quarantine::open(tmp.path().join("q")).unwrap();

        let victim = tmp.path().join("evil.bin");
        let original = b"malicious payload bytes";
        fs::write(&victim, original).unwrap();

        let entry = q
            .quarantine_file(
                &victim,
                "deadbeefdeadbeef0011",
                original.len() as u64,
                vec![det()],
            )
            .unwrap();
        assert!(!victim.exists(), "original removed after quarantine");
        assert_eq!(q.list().unwrap().len(), 1);

        let blob = q.blob_path(&entry.id);
        assert!(blob.exists());
        assert_ne!(
            fs::read(&blob).unwrap(),
            original,
            "stored blob is defanged"
        );

        let restored = q.restore(&entry.id, None).unwrap();
        assert_eq!(restored, victim);
        assert_eq!(fs::read(&victim).unwrap(), original, "restored bytes match");
        assert!(q.list().unwrap().is_empty());
    }

    #[test]
    fn purge_removes_entry_and_blob() {
        let tmp = tempfile::tempdir().unwrap();
        let q = Quarantine::open(tmp.path().join("q")).unwrap();
        let victim = tmp.path().join("evil.bin");
        fs::write(&victim, b"x").unwrap();
        let entry = q
            .quarantine_file(&victim, "abcdef0123456789", 1, vec![det()])
            .unwrap();

        q.purge(&entry.id).unwrap();
        assert!(q.list().unwrap().is_empty());
        assert!(!q.blob_path(&entry.id).exists());
    }
}
