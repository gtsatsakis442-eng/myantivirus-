//! Firewall control via **OS-firewall orchestration** (user-mode).
//!
//! Talos does not ship its own packet filter (a WFP callout / Netfilter kernel
//! module is Phase 2). Instead it blocks known-malicious network endpoints by
//! adding **drop rules to the platform firewall**:
//!   * **Windows** — `netsh advfirewall firewall` (outbound block by remote IP)
//!   * **Linux**   — `iptables` (OUTPUT … -j DROP)
//!
//! Block source: the **abuse.ch Feodo Tracker** botnet C2 IP blocklist (free).
//! Applying/removing rules needs Administrator / root.

use std::collections::HashSet;
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

use crate::error::{Result, ScanError};

/// Windows firewall rule-name prefix / Linux iptables comment used to tag (and
/// later find/remove) the rules Talos creates.
const TAG: &str = "TalosBlock";

/// Dedicated Linux chain holding the synced feed (refilled atomically on sync).
const FEED_CHAIN: &str = "TALOS_C2";

/// IPs per Windows feed rule. netsh accepts a comma-separated `remoteip` list,
/// so a whole feed fits in a handful of rules instead of one process per IP.
const FEED_CHUNK: usize = 100;

/// Default abuse.ch Feodo Tracker C2 IP blocklist URL.
pub fn default_feodo_url() -> &'static str {
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
}

/// Outcome of a firewall sync.
#[derive(Debug, Default)]
pub struct FirewallReport {
    pub listed: usize,
    pub applied: usize,
    /// Feed entries rejected by the public-routability guard.
    pub skipped: usize,
    pub messages: Vec<String>,
}

/// Fetch the Feodo Tracker C2 blocklist and block every listed IP.
///
/// Intelligent: only **publicly routable** addresses are accepted — a poisoned
/// or garbled feed can never push rules that sever loopback, the LAN, the
/// gateway or other reserved space. Efficient: rules are applied in **batches**
/// (a handful of OS calls for the whole feed, not one process per IP), and a
/// re-sync **replaces** the previous feed set, so it never duplicates rules.
pub fn sync_c2_blocklist(url: &str) -> Result<FirewallReport> {
    let text = fetch_https(url)?;
    let listed = parse_ip_blocklist(&text);
    let total = listed.len();
    let (ips, skipped): (Vec<String>, Vec<String>) = listed.into_iter().partition(|ip| {
        ip.parse::<Ipv4Addr>()
            .map(|p| is_public_ipv4(&p))
            .unwrap_or(false)
    });
    let mut report = FirewallReport {
        listed: total,
        skipped: skipped.len(),
        ..Default::default()
    };
    if ips.is_empty() {
        report.messages.push(format!(
            "Feodo Tracker: {total} entr{} listed; none publicly routable — nothing applied",
            if total == 1 { "y" } else { "ies" }
        ));
        return Ok(report);
    }
    let rules = apply_feed(&ips)?;
    report.applied = ips.len();
    let mut msg = format!(
        "Feodo Tracker: {} C2 IP(s) blocked via {} batched rule(s)",
        report.applied, rules
    );
    if report.skipped > 0 {
        msg.push_str(&format!(
            " · {} non-public entr(ies) skipped",
            report.skipped
        ));
    }
    report.messages.push(msg);
    Ok(report)
}

/// Apply the feed in batches, replacing any previously synced set (idempotent).
///
/// * **Windows** — all chunks share the rule name `TalosBlock-feed`; one
///   `netsh … delete rule` drops every previous chunk, then each chunk of
///   [`FEED_CHUNK`] IPs becomes one multi-IP rule.
/// * **Linux** — a dedicated [`FEED_CHAIN`] chain (jumped to from OUTPUT) is
///   flushed and refilled through a single `iptables-restore --noflush` call.
///
/// Returns the number of OS rules/batches created.
fn apply_feed(ips: &[String]) -> Result<usize> {
    if cfg!(windows) {
        // Drop the previous feed set; ignore failure (first sync has none).
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
        let chunks = chunk_ips(ips, FEED_CHUNK);
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
        // Ensure the chain exists and is jumped to exactly once, then refill it
        // atomically in a single child process.
        let _ = run("iptables", &argv(&["-N", FEED_CHAIN]));
        if run("iptables", &argv(&["-C", "OUTPUT", "-j", FEED_CHAIN])).is_err() {
            run("iptables", &argv(&["-I", "OUTPUT", "-j", FEED_CHAIN]))?;
        }
        run("iptables", &argv(&["-F", FEED_CHAIN]))?;
        run_stdin(
            "iptables-restore",
            &argv(&["--noflush"]),
            &restore_payload(ips),
        )?;
        Ok(1)
    }
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// Comma-join `ips` into chunks of at most `n` for multi-IP `remoteip=` rules.
fn chunk_ips(ips: &[String], n: usize) -> Vec<String> {
    ips.chunks(n.max(1)).map(|c| c.join(",")).collect()
}

/// The `iptables-restore` payload that refills [`FEED_CHAIN`].
fn restore_payload(ips: &[String]) -> String {
    let mut out = String::from("*filter\n");
    for ip in ips {
        out.push_str(&format!("-A {FEED_CHAIN} -d {ip}/32 -j DROP\n"));
    }
    out.push_str("COMMIT\n");
    out
}

/// True for addresses that are routable on the public internet — the only kind
/// a C2 feed should ever name. Everything reserved (RFC 1918 private, loopback,
/// link-local, CGNAT, multicast, documentation, 0/8, 240/4) is rejected so feed
/// content can never knock out local connectivity.
fn is_public_ipv4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    !(o[0] == 0
        || o[0] == 10
        || o[0] == 127
        || o[0] >= 224
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113))
}

/// Add a drop rule for a single IPv4 address.
pub fn block_ip(ip: &str) -> Result<()> {
    if !is_ipv4(ip) {
        return Err(ScanError::Update(format!("not an IPv4 address: {ip}")));
    }
    let (prog, args) = block_command(ip);
    run(prog, &args)
}

/// Remove the drop rule for a single IPv4 address (mirrors [`block_ip`]).
pub fn unblock_ip(ip: &str) -> Result<()> {
    if !is_ipv4(ip) {
        return Err(ScanError::Update(format!("not an IPv4 address: {ip}")));
    }
    let (prog, args) = unblock_command(ip);
    run(prog, &args)
}

/// Remove all Talos-created firewall rules.
pub fn flush() -> Result<()> {
    let (prog, args) = flush_command();
    run(prog, &args)
}

/// Build the platform command that drops outbound traffic to `ip`.
fn block_command(ip: &str) -> (&'static str, Vec<String>) {
    if cfg!(windows) {
        (
            "netsh",
            vec![
                "advfirewall".into(),
                "firewall".into(),
                "add".into(),
                "rule".into(),
                format!("name={TAG}-{ip}"),
                "dir=out".into(),
                "action=block".into(),
                format!("remoteip={ip}"),
            ],
        )
    } else {
        (
            "iptables",
            vec![
                "-A".into(),
                "OUTPUT".into(),
                "-d".into(),
                ip.to_string(),
                "-m".into(),
                "comment".into(),
                "--comment".into(),
                TAG.to_string(),
                "-j".into(),
                "DROP".into(),
            ],
        )
    }
}

/// Build the platform command that removes the drop rule for `ip` (the inverse
/// of [`block_command`]).
fn unblock_command(ip: &str) -> (&'static str, Vec<String>) {
    if cfg!(windows) {
        (
            "netsh",
            vec![
                "advfirewall".into(),
                "firewall".into(),
                "delete".into(),
                "rule".into(),
                format!("name={TAG}-{ip}"),
            ],
        )
    } else {
        (
            "iptables",
            vec![
                "-D".into(),
                "OUTPUT".into(),
                "-d".into(),
                ip.to_string(),
                "-m".into(),
                "comment".into(),
                "--comment".into(),
                TAG.to_string(),
                "-j".into(),
                "DROP".into(),
            ],
        )
    }
}

/// Build the platform command that removes **only** the rules Talos created
/// (matched by the `TalosBlock-*` name on Windows / the comment tag on Linux).
fn flush_command() -> (&'static str, Vec<String>) {
    if cfg!(windows) {
        (
            "powershell",
            vec![
                "-NoProfile".into(),
                "-Command".into(),
                format!("Get-NetFirewallRule -DisplayName '{TAG}-*' | Remove-NetFirewallRule"),
            ],
        )
    } else {
        // Tear down the feed chain, then remove every manual rule carrying our
        // comment tag.
        (
            "sh",
            vec![
                "-c".into(),
                format!(
                    "iptables -D OUTPUT -j {FEED_CHAIN} 2>/dev/null || :; \
                     iptables -F {FEED_CHAIN} 2>/dev/null || :; \
                     iptables -X {FEED_CHAIN} 2>/dev/null || :; \
                     while iptables -D OUTPUT -m comment --comment {TAG} -j DROP 2>/dev/null; \
                     do :; done"
                ),
            ],
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

/// Like [`run`] but feeds `input` to the child's stdin (e.g. `iptables-restore`).
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

/// Parse a one-IP-per-line blocklist (`#` comments, optional columns), keeping
/// valid IPv4 addresses.
fn parse_ip_blocklist(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Feodo's plain list is one IP per line; tolerate a leading column.
        let token = line.split_whitespace().next().unwrap_or("");
        if is_ipv4(token) && seen.insert(token.to_string()) {
            out.push(token.to_string());
        }
    }
    out
}

/// Strict dotted-quad IPv4 check (each octet 0–255).
fn is_ipv4(s: &str) -> bool {
    let mut parts = 0;
    for octet in s.split('.') {
        parts += 1;
        if octet.is_empty() || octet.len() > 3 || !octet.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        if octet.parse::<u16>().map(|v| v > 255).unwrap_or(true) {
            return false;
        }
    }
    parts == 4
}

pub(crate) fn fetch_https(url: &str) -> Result<String> {
    if !url.starts_with("https://") {
        return Err(ScanError::Update(format!("refusing non-HTTPS URL: {url}")));
    }
    // Stream the body to stdout and capture it in memory instead of writing a
    // predictable temp file in a world-writable dir — that path is a symlink /
    // clobber target when the agent runs as root/SYSTEM.
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
    fn parses_feodo_style_list() {
        let input = "# Feodo Tracker IP Blocklist\n# header\n\
                     185.100.87.202\n45.142.212.61\nnot-an-ip\n185.100.87.202\n";
        let ips = parse_ip_blocklist(input);
        assert_eq!(ips, vec!["185.100.87.202", "45.142.212.61"]); // junk + dup removed
    }

    #[test]
    fn block_command_targets_the_ip() {
        let (prog, args) = block_command("1.2.3.4");
        let joined = args.join(" ");
        if cfg!(windows) {
            assert_eq!(prog, "netsh");
            assert!(joined.contains("remoteip=1.2.3.4"));
            assert!(joined.contains("action=block"));
        } else {
            assert_eq!(prog, "iptables");
            assert!(joined.contains("1.2.3.4"));
            assert!(joined.contains("DROP"));
        }
    }

    #[test]
    fn unblock_command_targets_the_ip() {
        let (prog, args) = unblock_command("1.2.3.4");
        let joined = args.join(" ");
        if cfg!(windows) {
            assert_eq!(prog, "netsh");
            assert!(joined.contains("delete"));
            assert!(joined.contains("name=TalosBlock-1.2.3.4"));
        } else {
            assert_eq!(prog, "iptables");
            assert!(joined.contains("-D"));
            assert!(joined.contains("1.2.3.4"));
            assert!(joined.contains("DROP"));
        }
    }

    #[test]
    fn rejects_non_ip_block() {
        assert!(block_ip("example.com").is_err());
        assert!(unblock_ip("example.com").is_err());
    }

    #[test]
    fn public_routability_guard() {
        let public = ["8.8.8.8", "185.100.87.202", "1.1.1.1", "223.255.255.1"];
        for ip in public {
            assert!(
                is_public_ipv4(&ip.parse().unwrap()),
                "{ip} should be accepted"
            );
        }
        let reserved = [
            "0.1.2.3",         // 0/8
            "10.0.0.1",        // RFC1918
            "100.64.0.1",      // CGNAT shared space
            "127.0.0.1",       // loopback
            "169.254.1.1",     // link-local
            "172.16.0.1",      // RFC1918
            "192.168.1.1",     // RFC1918
            "192.0.2.5",       // TEST-NET-1
            "198.18.0.1",      // benchmarking
            "198.51.100.7",    // TEST-NET-2
            "203.0.113.9",     // TEST-NET-3
            "224.0.0.1",       // multicast
            "240.0.0.1",       // reserved
            "255.255.255.255", // broadcast
        ];
        for ip in reserved {
            assert!(
                !is_public_ipv4(&ip.parse().unwrap()),
                "{ip} must be rejected — a poisoned feed cannot block local space"
            );
        }
    }

    #[test]
    fn feed_is_chunked_for_batching() {
        let ips: Vec<String> = (0..250)
            .map(|i| format!("5.5.{}.{}", i / 250, i % 250))
            .collect();
        let chunks = chunk_ips(&ips, 100);
        assert_eq!(chunks.len(), 3, "250 IPs in 100-IP chunks → 3 rules");
        assert_eq!(chunks[0].matches(',').count(), 99);
        assert!(!chunks[0].contains(' '));
    }

    #[test]
    fn restore_payload_refills_the_chain() {
        let ips = vec!["5.6.7.8".to_string(), "9.10.11.12".to_string()];
        let payload = restore_payload(&ips);
        assert!(payload.starts_with("*filter\n"));
        assert!(payload.contains("-A TALOS_C2 -d 5.6.7.8/32 -j DROP\n"));
        assert!(payload.contains("-A TALOS_C2 -d 9.10.11.12/32 -j DROP\n"));
        assert!(payload.ends_with("COMMIT\n"));
    }

    #[test]
    fn flush_tears_down_the_feed_chain_on_linux() {
        let (prog, args) = flush_command();
        if !cfg!(windows) {
            assert_eq!(prog, "sh");
            let script = args.join(" ");
            assert!(script.contains("-X TALOS_C2"), "chain removed: {script}");
            assert!(
                script.contains("--comment TalosBlock"),
                "manual rules removed"
            );
        }
    }
}
