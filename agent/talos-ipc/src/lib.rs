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
