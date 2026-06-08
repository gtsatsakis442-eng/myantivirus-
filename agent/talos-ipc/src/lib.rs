//! Talos EPP local IPC: protocol + framing + transport shared by the **agent
//! service** (server) and the **GUI / CLI** (clients).
//!
//! ## Transport
//!
//! A **loopback TCP** socket (`127.0.0.1`, ephemeral port) guarded by a
//! per-session **token** that the agent writes to a private file. Both ends use
//! the same `std::net` code path, so it behaves identically on Windows and Linux
//! and is fully testable. Hardening to OS **named pipes / Unix sockets with
//! ACLs** is a follow-up — the wire protocol below does not change when that
//! lands.
//!
//! ## Framing
//!
//! Each message is a 4-byte big-endian length prefix followed by that many bytes
//! of JSON. A client sends one [`Envelope`] (token + [`Request`]) and reads one
//! [`Response`].
#![forbid(unsafe_code)]

pub mod client;
pub mod frame;
pub mod proto;
pub mod transport;

pub use proto::{Envelope, Event, QuarantineItem, Request, Response, Status, PROTOCOL_VERSION};
pub use transport::EndpointInfo;

/// Constant-time comparison of the session token, so the auth check doesn't leak
/// how many leading characters matched via its timing. Both values are the
/// fixed-length hex SHA-256 token.
pub fn token_matches(expected: &str, provided: &str) -> bool {
    let a = expected.as_bytes();
    let b = provided.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::token_matches;

    #[test]
    fn token_match_is_exact() {
        assert!(token_matches("abc123", "abc123"));
        assert!(!token_matches("abc123", "abc124"));
        assert!(!token_matches("abc123", "abc12"));
        assert!(!token_matches("", "x"));
        assert!(token_matches("", ""));
    }
}
