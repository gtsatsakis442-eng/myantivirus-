//! Canary-based ransomware detection (**user-mode**).
//!
//! Ransomware encrypts files in bulk. Talos plants small **decoy ("canary")
//! files** in watched folders; if any canary is **modified or deleted**, a
//! mass-encryption run is almost certainly underway, and the agent raises an
//! alarm (and can stop real-time / quarantine the culprit).
//!
//! This is a real, widely-used technique — but it is *detection + response*,
//! not the kernel **behavioural rollback** (file-I/O filter + Volume Shadow
//! Copy) that fully restores encrypted data; that remains Phase 2 (docs/01).

use std::path::{Path, PathBuf};

use crate::hashing::hash_bytes;

/// A decoy file sorted to the top of a directory (ransomware often encrypts in
/// directory order), with a name that discourages humans from touching it.
const CANARY_NAME: &str = "!!!_TALOS_canary_DO_NOT_DELETE.docx";

/// A planted decoy and the digest it must keep to be considered untouched.
#[derive(Debug, Clone)]
pub struct Canary {
    pub path: PathBuf,
    pub sha256: String,
}

/// True if `path` is one of Talos's canary files (by name).
pub fn is_canary(path: &Path) -> bool {
    path.file_name().and_then(|n| n.to_str()) == Some(CANARY_NAME)
}

/// Plant a canary in each existing directory in `dirs`; returns those created.
pub fn deploy(dirs: &[PathBuf]) -> Vec<Canary> {
    let content = canary_content();
    let sha256 = hash_bytes(&content).sha256;
    let mut out = Vec::new();
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        let path = dir.join(CANARY_NAME);
        if std::fs::write(&path, &content).is_ok() {
            out.push(Canary {
                path,
                sha256: sha256.clone(),
            });
        }
    }
    out
}

/// Return the canaries that have been **tampered** — modified (digest changed)
/// or removed. A non-empty result is a strong ransomware signal.
pub fn check(canaries: &[Canary]) -> Vec<PathBuf> {
    canaries
        .iter()
        .filter(|c| match std::fs::read(&c.path) {
            Ok(bytes) => hash_bytes(&bytes).sha256 != c.sha256,
            Err(_) => true, // missing/unreadable -> treat as tampered
        })
        .map(|c| c.path.clone())
        .collect()
}

/// Remove the planted canaries (best-effort).
pub fn cleanup(canaries: &[Canary]) {
    for c in canaries {
        let _ = std::fs::remove_file(&c.path);
    }
}

/// Innocuous, fixed decoy content (a tiny placeholder "document").
fn canary_content() -> Vec<u8> {
    b"Talos EPP ransomware canary. This file is a decoy used to detect \
      mass-encryption. Do not modify or delete it.\n"
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_check_and_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let canaries = deploy(&[dir.path().to_path_buf()]);
        assert_eq!(canaries.len(), 1);
        assert!(is_canary(&canaries[0].path));
        // Untouched -> nothing tampered.
        assert!(check(&canaries).is_empty());
        // Simulate ransomware encrypting the canary.
        std::fs::write(&canaries[0].path, b"ENCRYPTED-GIBBERISH").unwrap();
        assert_eq!(check(&canaries), vec![canaries[0].path.clone()]);
        // Deletion is also tamper.
        std::fs::remove_file(&canaries[0].path).unwrap();
        assert_eq!(check(&canaries).len(), 1);
    }

    #[test]
    fn skips_nonexistent_dirs() {
        assert!(deploy(&[PathBuf::from("/no/such/dir/xyz")]).is_empty());
    }
}
