//! Sentinel EPP — user-mode scanning engine (Phase 1 MVP).
//!
//! This crate provides the file-processing pipeline and two detection layers:
//! an exact **hash-signature** database and a **YARA** rule engine. It is
//! deliberately platform-agnostic so it can be developed and tested on Linux
//! while production targets Windows (see docs/06-implementation-roadmap.md).
//!
//! ```no_run
//! use scanner_core::{Engine, HashSignatureDb, Scanner, YaraEngine};
//! use std::path::Path;
//!
//! let hashes = HashSignatureDb::from_file("signatures/hashes/baseline.hashdb")?;
//! let yara = YaraEngine::from_dir("signatures/yara")?;
//! let engine = Engine::new(hashes, Some(yara));
//! let scanner = Scanner::new(&engine);
//! for report in scanner.scan_tree(Path::new("/some/dir")) {
//!     if report.is_malicious() {
//!         println!("{}: {:?}", report.path, report.detections);
//!     }
//! }
//! # Ok::<(), scanner_core::ScanError>(())
//! ```

pub mod engine;
pub mod error;
pub mod hashing;
pub mod heuristics;
pub mod pipeline;
pub mod quarantine;
pub mod report;
pub mod signatures;
pub mod verdict;
pub mod yara_engine;

pub use engine::Engine;
pub use error::{Result, ScanError};
pub use hashing::{hash_bytes, hash_reader, FileHashes};
pub use pipeline::{ScanOptions, Scanner, DEFAULT_MAX_CONTENT_BYTES};
pub use quarantine::{Quarantine, QuarantineEntry};
pub use report::{ScanReport, ScanSummary};
pub use signatures::HashSignatureDb;
pub use verdict::{Detection, DetectionKind, Disposition, Severity};
pub use yara_engine::YaraEngine;
