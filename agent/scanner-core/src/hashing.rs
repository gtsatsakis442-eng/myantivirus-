//! Streaming, multi-algorithm file hashing.
//!
//! Hashes are computed in a single pass over the input. The streaming variant
//! reads in fixed chunks so arbitrarily large files are handled with bounded
//! memory — important for a scanner that must never OOM on a multi-GB file.

use std::io::Read;

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Read buffer size for streamed hashing (64 KiB balances syscalls vs. memory).
const CHUNK: usize = 64 * 1024;

/// The set of digests computed for a file, as lowercase hex strings.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileHashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

/// Compute all digests by streaming `reader` to EOF.
///
/// Returns the digests and the total number of bytes read.
pub fn hash_reader<R: Read>(mut reader: R) -> std::io::Result<(FileHashes, u64)> {
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut total: u64 = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let slice = &buf[..n];
        md5.update(slice);
        sha1.update(slice);
        sha256.update(slice);
        total += n as u64;
    }

    Ok((finalize(md5, sha1, sha256), total))
}

/// Compute all digests for an in-memory buffer (single pass, no extra I/O).
pub fn hash_bytes(data: &[u8]) -> FileHashes {
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    md5.update(data);
    sha1.update(data);
    sha256.update(data);
    finalize(md5, sha1, sha256)
}

fn finalize(md5: Md5, sha1: Sha1, sha256: Sha256) -> FileHashes {
    FileHashes {
        md5: hex::encode(md5.finalize()),
        sha1: hex::encode(sha1.finalize()),
        sha256: hex::encode(sha256.finalize()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // EICAR standard anti-virus test string (harmless; the industry test vector).
    const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

    #[test]
    fn known_eicar_digests() {
        let h = hash_bytes(EICAR);
        assert_eq!(h.md5, "44d88612fea8a8f36de82e1278abb02f");
        assert_eq!(h.sha1, "3395856ce81f2b7382dee72602f798b642f14140");
        assert_eq!(
            h.sha256,
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let (streamed, n) = hash_reader(EICAR).unwrap();
        assert_eq!(n, EICAR.len() as u64);
        assert_eq!(streamed, hash_bytes(EICAR));
    }

    #[test]
    fn empty_input() {
        let h = hash_bytes(b"");
        // Well-known empty-input digests.
        assert_eq!(
            h.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
