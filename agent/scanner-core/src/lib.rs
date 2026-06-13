//! Talos EPP — user-mode scanning engine (Phase 1 MVP).
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
//!
//! Hardening: this crate forbids `unsafe` code — all memory-unsafe operations
//! live in audited dependencies (`goblin`, `yara-x`), never in our logic.
#![forbid(unsafe_code)]

pub mod archive;
pub mod behavior;
pub mod bootstrap;
pub mod cache;
pub mod engine;
pub mod error;
pub mod event_log;
pub mod feeds;
pub mod firewall;
pub mod hashing;
pub mod heuristics;
pub mod intel;
pub mod lolbin;
pub mod pipeline;
pub mod quarantine;
pub mod ransom_guard;
pub mod realtime;
pub mod remediation;
pub mod report;
pub mod signatures;
pub mod verdict;
pub mod webprotect;
pub mod yara_engine;

pub use archive::ArchiveLimits;
pub use cache::ScanCache;
pub use engine::Engine;
pub use error::{Result, ScanError};
pub use event_log::{EventLog, SiemEvent};
pub use feeds::{UpdateOptions, UpdateReport};
pub use firewall::{
    FeedConfig, FeedFormat, FirewallReport, BASELINE_BLOCKS, BASELINE_PORTS, KNOWN_FEEDS,
};
pub use hashing::{hash_bytes, hash_reader, FileHashes};
pub use intel::{lookup_hash, IntelReport};
pub use lolbin::analyze as analyze_lolbins;
pub use pipeline::{ScanOptions, Scanner, DEFAULT_MAX_CONTENT_BYTES};
pub use quarantine::{Quarantine, QuarantineEntry};
pub use realtime::Watch;
pub use remediation::{
    BaselineEntry, ContextRisk, ModuleIdentity, ProcessContext, Remediation, TrustBaseline,
    TrustTier,
};
pub use report::{ScanReport, ScanSummary};
pub use signatures::HashSignatureDb;
pub use verdict::{Detection, DetectionKind, Disposition, Severity};
pub use yara_engine::YaraEngine;
