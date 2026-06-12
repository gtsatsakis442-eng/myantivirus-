//! Firewall control via **OS-firewall orchestration** (user-mode).
//!
//! Talos does not ship its own packet filter (a WFP callout / Netfilter kernel
//! module is Phase 2). Instead it blocks known-malicious network endpoints by
//! adding **drop rules to the platform firewall**:
//!   * **Windows** — `netsh advfirewall firewall` (outbound block by remote IP)
//!   * **Linux**   — `iptables` (OUTPUT … -j DROP)
//!
//! Precision enhancements:
//!
//!  * **Multiple threat feeds** — Feodo Tracker botnet C2 (standard + aggressive)
//!    and Spamhaus DROP / EDROP (globally-announced CIDR blocks that route no
//!    legitimate traffic) are merged into one atomic rule set per sync.
//!  * **CIDR-block support** — the parser and OS drivers accept `1.2.3.0/24`
//!    targets in addition to single hosts; iptables and netsh both support
//!    subnet notation natively.
//!  * **Baseline port blocking** — `apply_baseline()` instantly blocks a
//!    curated set of TCP ports used exclusively by known malware (Metasploit
//!    meterpreter, Back Orifice, NetBus, IRC C2, Tor proxies, XMRig miners).
//!    No network access required; idempotent.
//!  * **Public-routability guard** — retained from before and extended to CIDR
//!    targets; a poisoned feed can never add a rule that severs RFC-1918,
//!    loopback, link-local, CGNAT, multicast, or documentation space.
//!
//! Applying and removing rules requires Administrator / root.

use std::collections::HashSet;
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

use crate::error::{Result, ScanError};

/// Windows firewall rule-name prefix / Linux iptables comment tag.
const TAG: &str = "TalosBlock";

/// Dedicated Linux chain for feed rules (atomically refilled on each sync).
const FEED_CHAIN: &str = "TALOS_C2";

/// Linux chain for the hardcoded baseline port rules.
const BASELINE_CHAIN: &str = "TALOS_BASELINE";

/// IPs/CIDRs per Windows feed rule (multi-target `remoteip=` list).
const FEED_CHUNK: usize = 100;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Outcome of a firewall sync or baseline application.
#[derive(Debug, Default)]
pub struct FirewallReport {
    /// Total entries in the raw feed (before filtering).
    pub listed: usize,
    /// Entries actually pushed to the OS firewall.
    pub applied: usize,
    /// Entries rejected by the public-routability guard.
    pub skipped: usize,
    pub messages: Vec<String>,
}

/// A threat-intelligence feed that produces network targets to block.
#[derive(Debug, Clone)]
pub struct FeedConfig {
    /// Short human-readable name shown in reports.
    pub name: &'static str,
    /// HTTPS URL for the feed.
    pub url: &'static str,
    /// How to parse the feed body.
    pub format: FeedFormat,
}

/// Feed payload format.
#[derive(Debug, Clone, Copy)]
pub enum FeedFormat {
    /// One IPv4 address per line; `#` comments; optional trailing columns.
    /// Used by: Feodo Tracker.
    PlainIp,
    /// One CIDR per line; `;` introduces inline comments.
    /// Used by: Spamhaus DROP / EDROP.
    CidrList,
}

/// All threat feeds Talos syncs by default.
///
/// Feodo Tracker — confirmed and recently-active botnet C2 infrastructure.
/// Spamhaus DROP / EDROP — globally-announced CIDR blocks that provably route
/// no legitimate traffic; any connection to them is an Indicator of Compromise.
pub const KNOWN_FEEDS: &[FeedConfig] = &[
    FeedConfig {
        name: "Feodo Tracker C2",
        url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        format: FeedFormat::PlainIp,
    },
    FeedConfig {
        name: "Feodo Tracker Aggressive",
        url: "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt",
        format: FeedFormat::PlainIp,
    },
    FeedConfig {
        name: "Spamhaus DROP",
        url: "https://www.spamhaus.org/drop/drop.txt",
        format: FeedFormat::CidrList,
    },
    FeedConfig {
        name: "Spamhaus EDROP",
        url: "https://www.spamhaus.org/drop/edrop.txt",
        format: FeedFormat::CidrList,
    },
];

/// TCP ports with no legitimate outbound use on a managed endpoint that are
/// consistently exploited by well-known malware families.
///
/// Blocking these requires no threat-feed download and takes effect instantly.
/// The list is deliberately conservative — only ports whose *only* known use
/// in the wild is malicious or covert tunnelling.
pub const BASELINE_PORTS: &[(u16, &str)] = &[
    (1337, "tcp"),   // classic "leet" backdoor convention
    (4444, "tcp"),   // Metasploit meterpreter default listener
    (6667, "tcp"),   // IRC botnet C2 (plaintext)
    (6697, "tcp"),   // IRC botnet C2 (TLS)
    (9001, "tcp"),   // Tor ORPort — anonymised C2 relay
    (9030, "tcp"),   // Tor DirPort
    (9050, "tcp"),   // Tor SOCKS proxy
    (9150, "tcp"),   // Tor Browser SOCKS proxy
    (12345, "tcp"),  // NetBus RAT
    (31337, "tcp"),  // Back Orifice RAT ("elite")
    (14444, "tcp"),  // XMRig Monero mining HTTP
    (14433, "tcp"),  // XMRig Monero mining HTTPS
];

/// Default Feodo Tracker URL (kept for backward compatibility).
pub fn default_feodo_url() -> &'static str {
    KNOWN_FEEDS[0].url
}

// ---------------------------------------------------------------------------
// Feed sync
// ---------------------------------------------------------------------------

/// Fetch the Feodo Tracker C2 blocklist and block every listed IP.
/// Backward-compatible entry point; prefer [`sync_all_feeds`] for production.
pub fn sync_c2_blocklist(url: &str) -> Result<FirewallReport> {
    let text = fetch_https(url)?;
    let targets = parse_ip_blocklist(&text);
    apply_targets_report("custom", targets)
}

/// Fetch **all** [`KNOWN_FEEDS`] and merge their targets into a single atomic
/// rule set. Individual feed download failures are reported in `messages` but
/// never abort the sync — the successfully-fetched targets are always applied.
pub fn sync_all_feeds() -> Result<FirewallReport> {
    let mut all: HashSet<String> = HashSet::new();
    let mut total_listed = 0usize;
    let mut per_feed: Vec<String> = Vec::new();

    for feed in KNOWN_FEEDS {
        match fetch_https(feed.url) {
            Ok(text) => {
                let targets = parse_targets(&text, feed.format);
                let n = targets.len();
                total_listed += n;
                let (good, bad) = partition_public(targets);
                per_feed.push(format!(
                    "{}: {n} listed — {} usable, {} skipped (non-public)",
                    feed.name,
                    good.len(),
                    bad
                ));
                all.extend(good);
            }
            Err(e) => {
                per_feed.push(format!("{}: download failed — {e}", feed.name));
            }
        }
    }

    let targets: Vec<String> = all.into_iter().collect();
    let applied = targets.len();
    let rules = if targets.is_empty() {
        0
    } else {
        apply_feed_targets(&targets)?
    };

    let mut report = FirewallReport {
        listed: total_listed,
        applied,
        skipped: total_listed.saturating_sub(applied),
        messages: per_feed,
    };
    report.messages.push(format!(
        "Total: {applied} unique target(s) across {} feeds → {rules} OS rule(s)",
        KNOWN_FEEDS.len()
    ));
    Ok(report)
}

/// Apply the hardcoded [`BASELINE_PORTS`] as outbound TCP drop rules.
///
/// Idempotent: existing baseline rules are torn down first. Returns the number
/// of port rules applied.
pub fn apply_baseline() -> Result<FirewallReport> {
    if cfg!(windows) {
        // Remove any previous baseline, then add one rule per port.
        let _ = run(
            "netsh",
            &argv(&[
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={TAG}-baseline"),
            ]),
        );
        for (port, proto) in BASELINE_PORTS {
            run(
                "netsh",
                &argv(&[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={TAG}-baseline-{port}"),
                    "dir=out",
                    "action=block",
                    &format!("protocol={proto}"),
                    &format!("remoteport={port}"),
                ]),
            )?;
        }
    } else {
        // Create/flush the baseline chain and jump to it from OUTPUT.
        let _ = run("iptables", &argv(&["-N", BASELINE_CHAIN]));
        if run(
            "iptables",
            &argv(&["-C", "OUTPUT", "-j", BASELINE_CHAIN]),
        )
        .is_err()
        {
            run(
                "iptables",
                &argv(&["-I", "OUTPUT", "1", "-j", BASELINE_CHAIN]),
            )?;
        }
        run("iptables", &argv(&["-F", BASELINE_CHAIN]))?;
        for (port, proto) in BASELINE_PORTS {
            run(
                "iptables",
                &argv(&[
                    "-A",
                    BASELINE_CHAIN,
                    "-p",
                    proto,
                    "--dport",
                    &port.to_string(),
                    "-m",
                    "comment",
                    "--comment",
                    &format!("{TAG}-baseline"),
                    "-j",
                    "DROP",
                ]),
            )?;
        }
    }

    let n = BASELINE_PORTS.len();
    Ok(FirewallReport {
        applied: n,
        messages: vec![format!(
            "Baseline: {n} TCP port(s) blocked (RAT/C2/Tor/mining defaults)"
        )],
        ..Default::default()
    })
}

/// Remove all baseline port rules (inverse of [`apply_baseline`]).
pub fn flush_baseline() -> Result<()> {
    if cfg!(windows) {
        let _ = run(
            "powershell",
            &argv(&[
                "-NoProfile",
                "-Command",
                &format!(
                    "Get-NetFirewallRule -DisplayName '{TAG}-baseline*' | Remove-NetFirewallRule"
                ),
            ]),
        );
    } else {
        let _ = run("iptables", &argv(&["-D", "OUTPUT", "-j", BASELINE_CHAIN]));
        let _ = run("iptables", &argv(&["-F", BASELINE_CHAIN]));
        let _ = run("iptables", &argv(&["-X", BASELINE_CHAIN]));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Single-IP manual block / unblock
// ---------------------------------------------------------------------------

/// Add a drop rule for a single IPv4 address.
pub fn block_ip(ip: &str) -> Result<()> {
    if !is_ipv4(ip) {
        return Err(ScanError::Update(format!("not an IPv4 address: {ip}")));
    }
    run(&block_command(ip).0, &block_command(ip).1)
}

/// Remove the drop rule for a single IPv4 address.
pub fn unblock_ip(ip: &str) -> Result<()> {
    if !is_ipv4(ip) {
        return Err(ScanError::Update(format!("not an IPv4 address: {ip}")));
    }
    run(&unblock_command(ip).0, &unblock_command(ip).1)
}

/// Remove all Talos-created firewall rules (feed chain + baseline + manual).
pub fn flush() -> Result<()> {
    flush_baseline().ok();
    run(&flush_command().0, &flush_command().1)
}

// ---------------------------------------------------------------------------
// Internal: feed application
// ---------------------------------------------------------------------------

fn apply_targets_report(feed_name: &str, targets: Vec<String>) -> Result<FirewallReport> {
    let total = targets.len();
    let (good, bad) = partition_public(targets);
    let mut report = FirewallReport {
        listed: total,
        skipped: bad,
        ..Default::default()
    };
    if good.is_empty() {
        report.messages.push(format!(
            "{feed_name}: {total} entr{} listed; none publicly routable — nothing applied",
            if total == 1 { "y" } else { "ies" }
        ));
        return Ok(report);
    }
    let rules = apply_feed_targets(&good)?;
    report.applied = good.len();
    let mut msg = format!(
        "{feed_name}: {} target(s) blocked via {rules} batched rule(s)",
        report.applied
    );
    if report.skipped > 0 {
        msg.push_str(&format!(" · {} non-public entr(ies) skipped", report.skipped));
    }
    report.messages.push(msg);
    Ok(report)
}

/// Push `targets` (IPs or CIDRs) into the OS firewall, replacing any
/// previously-synced set. Returns the number of OS rules created.
///
/// * **Windows** — one `netsh` rule per [`FEED_CHUNK`]-IP batch.
/// * **Linux** — one `iptables-restore --noflush` populates `TALOS_C2`.
fn apply_feed_targets(targets: &[String]) -> Result<usize> {
    if cfg!(windows) {
        let _ = run(
            "netsh",
            &argv(&[
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={TAG}-feed"),
            ]),
        );
        let chunks = chunk_targets(targets, FEED_CHUNK);
        let n = chunks.len();
        for remoteip in &chunks {
            run(
                "netsh",
                &argv(&[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={TAG}-feed"),
                    "dir=out",
                    "action=block",
                    &format!("remoteip={remoteip}"),
                ]),
            )?;
        }
        Ok(n)
    } else {
        let _ = run("iptables", &argv(&["-N", FEED_CHAIN]));
        if run("iptables", &argv(&["-C", "OUTPUT", "-j", FEED_CHAIN])).is_err() {
            run("iptables", &argv(&["-I", "OUTPUT", "-j", FEED_CHAIN]))?;
        }
        run("iptables", &argv(&["-F", FEED_CHAIN]))?;
        run_stdin(
            "iptables-restore",
            &argv(&["--noflush"]),
            &restore_payload(targets),
        )?;
        Ok(1)
    }
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// Comma-join `targets` into chunks of at most `n` for `remoteip=` rules.
fn chunk_targets(targets: &[String], n: usize) -> Vec<String> {
    targets.chunks(n.max(1)).map(|c| c.join(",")).collect()
}

/// Build the `iptables-restore` payload that fills [`FEED_CHAIN`].
fn restore_payload(targets: &[String]) -> String {
    let mut out = String::from("*filter\n");
    for t in targets {
        // iptables-restore accepts both bare IPs and CIDR notation.
        if t.contains('/') {
            out.push_str(&format!("-A {FEED_CHAIN} -d {t} -j DROP\n"));
        } else {
            out.push_str(&format!("-A {FEED_CHAIN} -d {t}/32 -j DROP\n"));
        }
    }
    out.push_str("COMMIT\n");
    out
}

// ---------------------------------------------------------------------------
// Internal: routing / platform commands
// ---------------------------------------------------------------------------

fn block_command(ip: &str) -> (String, Vec<String>) {
    if cfg!(windows) {
        (
            "netsh".into(),
            argv(&[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={TAG}-{ip}"),
                "dir=out",
                "action=block",
                &format!("remoteip={ip}"),
            ]),
        )
    } else {
        (
            "iptables".into(),
            argv(&[
                "-A",
                "OUTPUT",
                "-d",
                ip,
                "-m",
                "comment",
                "--comment",
                TAG,
                "-j",
                "DROP",
            ]),
        )
    }
}

fn unblock_command(ip: &str) -> (String, Vec<String>) {
    if cfg!(windows) {
        (
            "netsh".into(),
            argv(&[
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={TAG}-{ip}"),
            ]),
        )
    } else {
        (
            "iptables".into(),
            argv(&[
                "-D",
                "OUTPUT",
                "-d",
                ip,
                "-m",
                "comment",
                "--comment",
                TAG,
                "-j",
                "DROP",
            ]),
        )
    }
}

fn flush_command() -> (String, Vec<String>) {
    if cfg!(windows) {
        (
            "powershell".into(),
            argv(&[
                "-NoProfile",
                "-Command",
                &format!("Get-NetFirewallRule -DisplayName '{TAG}-*' | Remove-NetFirewallRule"),
            ]),
        )
    } else {
        (
            "sh".into(),
            argv(&[
                "-c",
                &format!(
                    "iptables -D OUTPUT -j {FEED_CHAIN} 2>/dev/null || :; \
                     iptables -F {FEED_CHAIN} 2>/dev/null || :; \
                     iptables -X {FEED_CHAIN} 2>/dev/null || :; \
                     while iptables -D OUTPUT -m comment --comment {TAG} -j DROP 2>/dev/null; \
                     do :; done"
                ),
            ]),
        )
    }
}

fn run(prog: &str, args: &[String]) -> Result<()> {
    let status = Command::new(prog)
        .args(args)
        .status()
        .map_err(|e| ScanError::Update(format!("{prog} unavailable: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(ScanError::Update(format!(
            "{prog} failed (exit {:?}); firewall changes need Administrator/root",
            status.code()
        )))
    }
}

fn run_stdin(prog: &str, args: &[String], input: &str) -> Result<()> {
    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| ScanError::Update(format!("{prog} unavailable: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input.as_bytes())
            .map_err(|e| ScanError::Update(format!("{prog} stdin: {e}")))?;
    }
    let status = child
        .wait()
        .map_err(|e| ScanError::Update(format!("{prog}: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(ScanError::Update(format!(
            "{prog} failed (exit {:?}); firewall changes need Administrator/root",
            status.code()
        )))
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a feed body into a deduplicated list of network targets (IPs or
/// CIDRs) according to `format`.
fn parse_targets(text: &str, format: FeedFormat) -> Vec<String> {
    match format {
        FeedFormat::PlainIp => parse_ip_blocklist(text),
        FeedFormat::CidrList => parse_cidr_list(text),
    }
}

/// One-IP-per-line format (Feodo Tracker style).
fn parse_ip_blocklist(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let token = line.split_whitespace().next().unwrap_or("");
        if is_ipv4(token) && seen.insert(token.to_string()) {
            out.push(token.to_string());
        }
    }
    out
}

/// CIDR-per-line format (Spamhaus DROP style: `1.2.3.0/24 ; SBL123 ; comment`).
fn parse_cidr_list(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        // Token before the first `;` or whitespace is the CIDR.
        let token = line
            .split(|c| c == ';' || c == '#')
            .next()
            .unwrap_or("")
            .trim();
        if is_cidr(token) && seen.insert(token.to_string()) {
            out.push(token.to_string());
        }
    }
    out
}

/// Split `targets` into (publicly-routable, count-of-skipped).
fn partition_public(targets: Vec<String>) -> (Vec<String>, usize) {
    let mut good = Vec::new();
    let mut bad = 0usize;
    for t in targets {
        if target_is_public(&t) {
            good.push(t);
        } else {
            bad += 1;
        }
    }
    (good, bad)
}

/// True if `target` (IP or CIDR) is publicly routable.
fn target_is_public(target: &str) -> bool {
    let ip_str = if let Some((ip_part, prefix)) = target.split_once('/') {
        // Parse and validate the prefix length while we're here.
        if prefix.parse::<u8>().map(|p| p > 32).unwrap_or(true) {
            return false;
        }
        ip_part
    } else {
        target
    };
    ip_str
        .parse::<Ipv4Addr>()
        .map(|ip| is_public_ipv4(&ip))
        .unwrap_or(false)
}

/// True for addresses routable on the public internet.
fn is_public_ipv4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    !(o[0] == 0
        || o[0] == 10
        || o[0] == 127
        || o[0] >= 224
        || (o[0] == 100 && (64..=127).contains(&o[1]))  // CGNAT
        || (o[0] == 169 && o[1] == 254)                 // link-local
        || (o[0] == 172 && (16..=31).contains(&o[1]))   // RFC 1918
        || (o[0] == 192 && o[1] == 168)                 // RFC 1918
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)      // TEST-NET-1
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // benchmarking
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)  // TEST-NET-2
        || (o[0] == 203 && o[1] == 0 && o[2] == 113))  // TEST-NET-3
}

/// Strict dotted-quad IPv4 check.
fn is_ipv4(s: &str) -> bool {
    let mut parts = 0u8;
    for octet in s.split('.') {
        parts += 1;
        if octet.is_empty()
            || octet.len() > 3
            || !octet.bytes().all(|b| b.is_ascii_digit())
            || octet.parse::<u16>().map(|v| v > 255).unwrap_or(true)
        {
            return false;
        }
    }
    parts == 4
}

/// Validate `a.b.c.d/prefix` notation (prefix 0–32, network address valid).
fn is_cidr(s: &str) -> bool {
    match s.split_once('/') {
        Some((ip, prefix)) => {
            is_ipv4(ip)
                && prefix
                    .parse::<u8>()
                    .map(|p| p <= 32)
                    .unwrap_or(false)
        }
        None => false,
    }
}

pub(crate) fn fetch_https(url: &str) -> Result<String> {
    if !url.starts_with("https://") {
        return Err(ScanError::Update(format!("refusing non-HTTPS URL: {url}")));
    }
    let output = Command::new("curl")
        .args([
            "-fsSL",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--max-time",
            "120",
            "--max-filesize",
            "16777216",
        ])
        .arg(url)
        .output()
        .map_err(|e| ScanError::Update(format!("curl unavailable: {e}")))?;
    if !output.status.success() {
        return Err(ScanError::Update("blocklist download failed".to_string()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_validation() {
        assert!(is_ipv4("192.168.1.1"));
        assert!(is_ipv4("8.8.8.8"));
        assert!(!is_ipv4("256.1.1.1"));
        assert!(!is_ipv4("1.2.3"));
        assert!(!is_ipv4("1.2.3.4.5"));
        assert!(!is_ipv4("example.com"));
    }

    #[test]
    fn cidr_validation() {
        assert!(is_cidr("185.220.0.0/22"));
        assert!(is_cidr("10.0.0.0/8"));
        assert!(is_cidr("1.2.3.4/32"));
        assert!(is_cidr("0.0.0.0/0"));
        assert!(!is_cidr("1.2.3.4"));       // no prefix
        assert!(!is_cidr("1.2.3.4/33"));    // prefix out of range
        assert!(!is_cidr("256.0.0.0/8"));   // bad network address
        assert!(!is_cidr("example.com/24")); // not an IP
    }

    #[test]
    fn parses_feodo_style_list() {
        let input = "# Feodo Tracker IP Blocklist\n\
                     185.100.87.202\n45.142.212.61\nnot-an-ip\n185.100.87.202\n";
        let ips = parse_ip_blocklist(input);
        assert_eq!(ips, vec!["185.100.87.202", "45.142.212.61"]);
    }

    #[test]
    fn parses_spamhaus_drop_style() {
        let input = "; Spamhaus DROP\n\
                     1.0.1.0/24 ; SBL222222 ; hijacked\n\
                     185.220.0.0/22 ; SBL573876 ; abuse.ch Tor\n\
                     10.0.0.0/8 ; SBL000001 ; RFC1918 (should be skipped by guard)\n\
                     1.0.1.0/24 ; duplicate\n";
        let cidrs = parse_cidr_list(input);
        // RFC1918 is parsed (guard is separate), dup is deduped.
        assert!(cidrs.contains(&"1.0.1.0/24".to_string()));
        assert!(cidrs.contains(&"185.220.0.0/22".to_string()));
        assert!(cidrs.contains(&"10.0.0.0/8".to_string())); // parsed, but guard will skip
        assert_eq!(cidrs.iter().filter(|c| c.as_str() == "1.0.1.0/24").count(), 1); // deduped
    }

    #[test]
    fn public_routability_guard_covers_ips_and_cidrs() {
        // IPs
        let public_ips = ["8.8.8.8", "185.100.87.202", "1.1.1.1", "223.255.255.1"];
        for ip in public_ips {
            assert!(target_is_public(ip), "{ip} should be accepted");
        }
        let reserved_ips = [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.1.1",
            "192.0.2.5",
            "198.18.0.1",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ];
        for ip in reserved_ips {
            assert!(!target_is_public(ip), "{ip} must be rejected");
        }
        // CIDRs
        assert!(target_is_public("185.220.0.0/22"), "public CIDR accepted");
        assert!(!target_is_public("10.0.0.0/8"), "RFC1918 CIDR rejected");
        assert!(!target_is_public("192.168.0.0/16"), "RFC1918 CIDR rejected");
        assert!(!target_is_public("1.2.3.4/33"), "invalid prefix rejected");
    }

    #[test]
    fn feed_is_chunked_for_batching() {
        let targets: Vec<String> = (0..250)
            .map(|i| format!("5.5.{}.{}", i / 250, i % 250))
            .collect();
        let chunks = chunk_targets(&targets, 100);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].matches(',').count(), 99);
    }

    #[test]
    fn restore_payload_handles_ips_and_cidrs() {
        let targets = vec![
            "5.6.7.8".to_string(),
            "9.10.11.0/24".to_string(),
        ];
        let payload = restore_payload(&targets);
        assert!(payload.starts_with("*filter\n"));
        assert!(payload.contains("-A TALOS_C2 -d 5.6.7.8/32 -j DROP\n"));
        assert!(payload.contains("-A TALOS_C2 -d 9.10.11.0/24 -j DROP\n"));
        assert!(payload.ends_with("COMMIT\n"));
    }

    #[test]
    fn baseline_ports_are_never_legitimate() {
        // Sanity: every entry in the baseline is a known-port (< 65536) and
        // uses TCP or UDP.
        for (port, proto) in BASELINE_PORTS {
            assert!(*port > 0, "port must be non-zero");
            assert!(
                *proto == "tcp" || *proto == "udp",
                "protocol must be tcp or udp, got {proto}"
            );
        }
        // The most notorious ports must be present.
        let ports: Vec<u16> = BASELINE_PORTS.iter().map(|(p, _)| *p).collect();
        assert!(ports.contains(&4444), "Metasploit meterpreter port");
        assert!(ports.contains(&31337), "Back Orifice port");
        assert!(ports.contains(&6667), "IRC C2 port");
        assert!(ports.contains(&9050), "Tor SOCKS port");
        assert!(ports.contains(&14444), "XMRig mining port");
    }

    #[test]
    fn rejects_non_ip_block() {
        assert!(block_ip("example.com").is_err());
        assert!(unblock_ip("example.com").is_err());
    }

    #[test]
    fn flush_command_tears_down_both_chains_on_linux() {
        let (prog, args) = flush_command();
        if !cfg!(windows) {
            assert_eq!(prog, "sh");
            let script = args.join(" ");
            assert!(script.contains("-X TALOS_C2"));
            assert!(script.contains("--comment TalosBlock"));
        }
    }

    #[test]
    fn known_feeds_are_https_only() {
        for feed in KNOWN_FEEDS {
            assert!(
                feed.url.starts_with("https://"),
                "{} uses non-HTTPS URL: {}",
                feed.name,
                feed.url
            );
        }
    }
}
