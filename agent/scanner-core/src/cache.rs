//! Incremental scan cache — skip re-reading files that are unchanged since a
//! previous scan and were clean then. This is the difference between a repeat
//! (or scheduled) scan taking minutes versus seconds on a large tree.
//!
//! **Correctness first.** An entry is trusted only when *both* hold:
//!   1. the file's `(size, mtime)` are unchanged, and
//!   2. the cache's **definitions generation** matches the engine's current
//!      detection content.
//!
//! Any change to detection content — a signature/YARA update, a heuristic or
//! behavioral toggle, or a new binary version — bumps the generation and
//! invalidates the *entire* cache, so a file that was clean under the old
//! definitions but is detectable under the new ones is always re-evaluated.
//! Only **clean, fully-inspected** results are cached; anything flagged is
//! re-evaluated every time. The worst case of the `(size, mtime)` heuristic is
//! that a Full Scan (which bypasses the cache) is always available.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::hashing::FileHashes;

/// One cached clean file: validated by `(size, mtime_ns)`, plus the digests so
/// a faithful report can be rebuilt without touching the disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    size: u64,
    mtime_ns: u128,
    hashes: FileHashes,
}

/// A persistent map of known-clean files, valid for one definitions generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCache {
    generation: u64,
    entries: HashMap<String, CacheEntry>,
}

impl ScanCache {
    /// An empty cache for `generation`.
    pub fn new(generation: u64) -> Self {
        Self {
            generation,
            entries: HashMap::new(),
        }
    }

    /// Load the cache at `path` for the current `generation`. A missing,
    /// unreadable, corrupt, or different-generation file yields an empty (fresh)
    /// cache — never a stale one, so we can't serve an out-of-date "clean".
    pub fn load(path: &Path, generation: u64) -> Self {
        match fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<ScanCache>(&bytes) {
                Ok(c) if c.generation == generation => c,
                _ => Self::new(generation),
            },
            Err(_) => Self::new(generation),
        }
    }

    /// Persist atomically (write a sibling temp file, then rename into place).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec(self).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, &json)?;
        fs::rename(&tmp, path)
    }

    /// The cached digests for `key` iff its `(size, mtime_ns)` are unchanged.
    pub fn get_clean(&self, key: &str, size: u64, mtime_ns: u128) -> Option<FileHashes> {
        self.entries
            .get(key)
            .filter(|e| e.size == size && e.mtime_ns == mtime_ns)
            .map(|e| e.hashes.clone())
    }

    /// Record (or refresh) a clean file's metadata + digests.
    pub fn put_clean(&mut self, key: &str, size: u64, mtime_ns: u128, hashes: FileHashes) {
        self.entries.insert(
            key.to_string(),
            CacheEntry {
                size,
                mtime_ns,
                hashes,
            },
        );
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Compute a definitions-generation id from everything that can change a
/// verdict. Any difference — the loaded signature/YARA counts, the heuristic or
/// behavioral toggles, the newest signature-store file, or the binary version —
/// produces a new id, invalidating the cache so unchanged-but-now-detectable
/// files are re-evaluated.
pub fn definitions_generation(
    hash_count: usize,
    yara_count: usize,
    heuristics: bool,
    behavior: bool,
    store_dir: &Path,
) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    env!("CARGO_PKG_VERSION").hash(&mut h);
    hash_count.hash(&mut h);
    yara_count.hash(&mut h);
    heuristics.hash(&mut h);
    behavior.hash(&mut h);
    newest_mtime_ns(store_dir).hash(&mut h);
    h.finish()
}

/// Newest modification time (ns since epoch) among files in the signature
/// store's `hashes/` and `yara/` subdirectories — bumps when `talos update`
/// rewrites the local definitions.
fn newest_mtime_ns(store_dir: &Path) -> u128 {
    let mut newest = 0u128;
    for sub in ["hashes", "yara"] {
        if let Ok(rd) = fs::read_dir(store_dir.join(sub)) {
            for entry in rd.flatten() {
                if let Ok(t) = entry.metadata().and_then(|m| m.modified()) {
                    if let Ok(d) = t.duration_since(UNIX_EPOCH) {
                        newest = newest.max(d.as_nanos());
                    }
                }
            }
        }
    }
    newest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_changes_with_any_input() {
        let dir = tempfile::tempdir().unwrap();
        let base = definitions_generation(100, 5, true, true, dir.path());
        assert_eq!(
            base,
            definitions_generation(100, 5, true, true, dir.path()),
            "stable for identical inputs"
        );
        assert_ne!(base, definitions_generation(101, 5, true, true, dir.path()));
        assert_ne!(base, definitions_generation(100, 6, true, true, dir.path()));
        assert_ne!(
            base,
            definitions_generation(100, 5, false, true, dir.path())
        );
        assert_ne!(
            base,
            definitions_generation(100, 5, true, false, dir.path())
        );
    }

    #[test]
    fn hit_requires_matching_size_and_mtime() {
        let mut c = ScanCache::new(1);
        let h = crate::hashing::hash_bytes(b"payload");
        c.put_clean("/a", 10, 100, h.clone());
        assert_eq!(c.get_clean("/a", 10, 100), Some(h));
        assert!(c.get_clean("/a", 11, 100).is_none(), "size change → miss");
        assert!(c.get_clean("/a", 10, 101).is_none(), "mtime change → miss");
        assert!(c.get_clean("/b", 10, 100).is_none(), "unknown path → miss");
    }

    #[test]
    fn load_rejects_a_stale_generation() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("scan-cache.json");
        let mut c = ScanCache::new(7);
        c.put_clean("/a", 1, 2, crate::hashing::hash_bytes(b"y"));
        c.save(&p).unwrap();
        assert_eq!(ScanCache::load(&p, 7).len(), 1, "same generation is kept");
        assert!(
            ScanCache::load(&p, 8).is_empty(),
            "a different generation invalidates the whole cache"
        );
    }
}
