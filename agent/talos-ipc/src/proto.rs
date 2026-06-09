//! The request/response protocol between Talos clients and the agent service.

use serde::{Deserialize, Serialize};

/// Wire protocol version. Bumped on incompatible changes so a client can detect
/// a mismatched agent (see [`Response::Pong`]).
pub const PROTOCOL_VERSION: u32 = 1;

/// What a client puts on the wire: the shared secret token plus one request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub token: String,
    pub request: Request,
}

/// A command from a client (GUI / CLI) to the agent service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Liveness/handshake check.
    Ping,
    /// Current protection status (counts, toggles, last scan).
    GetStatus,
    /// Start an on-demand scan. Empty `paths` means the Quick-Scan locations.
    StartScan {
        paths: Vec<String>,
        quarantine: bool,
    },
    /// List quarantined items.
    ListQuarantine,
    /// Restore a quarantined item to its original location by id.
    Restore { id: String },
    /// Turn the real-time on-access monitor on or off.
    SetRealtime { on: bool },
    /// Sync (on) the abuse.ch C2 blocklist, or flush (off) all Talos firewall rules.
    SetFirewall { on: bool },
    /// Block a specific outbound IPv4 address via the OS firewall (user-added).
    FirewallBlock { ip: String },
    /// Remove the firewall rule for a specific outbound IPv4 address.
    FirewallUnblock { ip: String },
    /// Enable (sync the URLhaus malicious-domain blocklist into the hosts file)
    /// or disable (clear it) web/domain protection.
    SetWebProtection { on: bool },
    /// Fetch activity events with `seq` greater than `since`.
    GetEvents { since: u64 },
    /// Ask the agent to stop (used by tooling/tests).
    Shutdown,
}

/// The agent's reply to a [`Request`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    /// Reply to [`Request::Ping`].
    Pong { version: String, protocol: u32 },
    /// Reply to [`Request::GetStatus`].
    Status(Status),
    /// A scan was accepted and is running in the background.
    ScanStarted { scan_id: u64 },
    /// Reply to [`Request::ListQuarantine`].
    Quarantine { items: Vec<QuarantineItem> },
    /// Reply to [`Request::GetEvents`]: events plus the next cursor to poll from.
    Events { events: Vec<Event>, next: u64 },
    /// Generic success for a command with no payload.
    Ack,
    /// The command failed (or the token was rejected).
    Error { message: String },
}

/// A snapshot of the agent's protection state, shown on the dashboard.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    pub realtime: bool,
    pub realtime_enforcing: bool,
    pub firewall: bool,
    /// Number of outbound IPs currently blocked by Talos firewall rules.
    #[serde(default)]
    pub firewall_blocked: usize,
    /// Web/domain protection (URLhaus hosts-file sinkhole) on, and how many
    /// domains are currently blocked.
    #[serde(default)]
    pub web_protection: bool,
    #[serde(default)]
    pub web_blocked: usize,
    pub hash_signatures: usize,
    pub yara_files: usize,
    pub quarantined: usize,
    pub last_scan_unix: u64,
    pub last_files: u64,
    pub last_malicious: u64,
    pub last_suspicious: u64,
    pub threats_blocked: u64,
    pub uptime_secs: u64,
}

/// A quarantined item, flattened for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: String,
    pub detections: Vec<String>,
}

/// Well-known [`Event::severity`] tags.
pub mod severity {
    pub const INFO: &str = "info";
    pub const THREAT: &str = "threat";
    pub const BLOCKED: &str = "blocked";
    pub const RANSOMWARE: &str = "ransomware";
    pub const ERROR: &str = "error";
}

/// An activity event in the agent's rolling log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub unix: u64,
    pub severity: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}
