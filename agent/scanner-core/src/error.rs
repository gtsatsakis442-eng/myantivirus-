//! Error types for the scanning engine.

use std::path::PathBuf;
use thiserror::Error;

/// Errors raised while loading content or scanning.
#[derive(Debug, Error)]
pub enum ScanError {
    /// An I/O failure tied to a specific path (open, read, metadata).
    #[error("I/O error for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The hash signature database could not be parsed.
    #[error("signature database error: {0}")]
    SignatureDb(String),

    /// YARA rule compilation or scanning failed.
    #[error("YARA error: {0}")]
    Yara(String),

    /// A quarantine operation (isolate/restore/purge) failed.
    #[error("quarantine error: {0}")]
    Quarantine(String),

    /// An archive could not be opened or read.
    #[error("archive error: {0}")]
    Archive(String),

    /// A signature update (feed fetch / parse) failed.
    #[error("update error: {0}")]
    Update(String),

    /// A telemetry-store operation (open / schema / persist / query) failed.
    #[error("telemetry error: {0}")]
    Telemetry(String),
}

/// Convenience result alias used throughout the engine.
pub type Result<T> = std::result::Result<T, ScanError>;
