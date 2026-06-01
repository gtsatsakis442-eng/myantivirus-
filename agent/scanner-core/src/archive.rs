//! Archive inspection — extract entries from ZIP files so the engine can scan
//! what's *inside* (malware very commonly ships inside archives).
//!
//! Hardened against zip bombs: per-entry and total decompressed sizes are
//! capped, the entry count is capped, and nested archives are NOT recursed
//! (a nested archive is just scanned as an opaque file by the outer layers).

use std::io::{Cursor, Read};

use crate::error::{Result, ScanError};

/// Limits applied while expanding an archive (zip-bomb protection).
#[derive(Debug, Clone)]
pub struct ArchiveLimits {
    pub max_entries: usize,
    pub max_entry_bytes: u64,
    pub max_total_bytes: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_entry_bytes: 64 * 1024 * 1024,  // 64 MiB per entry
            max_total_bytes: 512 * 1024 * 1024, // 512 MiB decompressed total
        }
    }
}

/// Cheap magic-byte check for a local ZIP header (`PK\x03\x04`, plus the
/// empty-archive `PK\x05\x06` and spanned `PK\x07\x08` markers).
pub fn looks_like_zip(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..2] == b"PK" && matches!(data[2], 0x03 | 0x05 | 0x07)
}

/// Call `f(entry_name, entry_bytes, truncated)` for each *file* entry in the
/// ZIP, honoring [`ArchiveLimits`]. `truncated` is true when the entry was
/// larger than the per-entry cap and only a prefix was read.
///
/// Returns the number of entries passed to `f`.
pub fn for_each_zip_entry<F>(data: &[u8], limits: &ArchiveLimits, mut f: F) -> Result<usize>
where
    F: FnMut(&str, &[u8], bool),
{
    let mut zip =
        zip::ZipArchive::new(Cursor::new(data)).map_err(|e| ScanError::Archive(e.to_string()))?;

    let count = zip.len().min(limits.max_entries);
    let mut total: u64 = 0;
    let mut scanned = 0usize;

    for i in 0..count {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| ScanError::Archive(e.to_string()))?;
        if !entry.is_file() {
            continue;
        }
        if total >= limits.max_total_bytes {
            break;
        }

        let declared = entry.size();
        let cap = limits.max_entry_bytes.min(limits.max_total_bytes - total);
        let mut buf = Vec::with_capacity(declared.min(cap) as usize);
        // `take(cap)` bounds how much we will decompress, regardless of the
        // (attacker-controlled) declared size — this is the zip-bomb guard.
        entry
            .by_ref()
            .take(cap)
            .read_to_end(&mut buf)
            .map_err(|e| ScanError::Archive(e.to_string()))?;

        let truncated = buf.len() as u64 >= cap && declared > cap;
        total += buf.len() as u64;
        let name = entry.name().to_string();
        drop(entry);

        f(&name, &buf, truncated);
        scanned += 1;
    }

    Ok(scanned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
            for (name, data) in entries {
                zw.start_file(*name, SimpleFileOptions::default()).unwrap();
                zw.write_all(data).unwrap();
            }
            zw.finish().unwrap();
        }
        buf
    }

    #[test]
    fn detects_zip_and_iterates_entries() {
        let zip_bytes = make_zip(&[("a.txt", b"hello"), ("b/c.bin", b"world!!")]);
        assert!(looks_like_zip(&zip_bytes));

        let mut seen = Vec::new();
        let n = for_each_zip_entry(&zip_bytes, &ArchiveLimits::default(), |name, bytes, _| {
            seen.push((name.to_string(), bytes.to_vec()));
        })
        .unwrap();
        assert_eq!(n, 2);
        assert!(seen.iter().any(|(n, b)| n == "a.txt" && b == b"hello"));
        assert!(seen.iter().any(|(n, b)| n == "b/c.bin" && b == b"world!!"));
    }

    #[test]
    fn per_entry_cap_truncates() {
        let big = vec![b'A'; 4096];
        let zip_bytes = make_zip(&[("big.bin", &big)]);
        let limits = ArchiveLimits {
            max_entry_bytes: 100,
            ..Default::default()
        };
        let mut got = Vec::new();
        for_each_zip_entry(&zip_bytes, &limits, |_, bytes, truncated| {
            got.push((bytes.len(), truncated));
        })
        .unwrap();
        assert_eq!(got, vec![(100, true)]);
    }

    #[test]
    fn non_zip_is_an_error() {
        assert!(!looks_like_zip(b"not a zip"));
        assert!(for_each_zip_entry(b"not a zip", &ArchiveLimits::default(), |_, _, _| {}).is_err());
    }
}
