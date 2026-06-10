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

use std::process::Command;

use crate::error::{Result, ScanError};

/// Windows firewall rule-name prefix / Linux iptables comment used to tag (and
/// later find/remove) the rules Talos creates.
const TAG: &str = "TalosBlock";

/// Default abuse.ch Feodo Tracker C2 IP blocklist URL.
pub fn default_feodo_url() -> &'static str {
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
}

/// Outcome of a firewall sync.
#[derive(Debug, Default)]
pub struct FirewallReport {
    pub listed: usize,
    pub applied: usize,
    pub messages: Vec<String>,
}

/// Fetch the Feodo Tracker C2 blocklist and add an OS-firewall drop rule per IP.
pub fn sync_c2_blocklist(url: &str) -> Result<FirewallReport> {
    let text = fetch_https(url)?;
    let ips = parse_ip_blocklist(&text);
    let mut report = FirewallReport {
        listed: ips.len(),
        ..Default::default()
    };
    for ip in &ips {
        if block_ip(ip).is_ok() {
            report.applied += 1;
        }
    }
    report.messages.push(format!(
        "Feodo Tracker: {} C2 IP(s); {} firewall drop rule(s) applied",
        report.listed, report.applied
    ));
    Ok(report)
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
        // Remove every OUTPUT rule carrying our comment tag.
        (
            "sh",
            vec![
                "-c".into(),
                format!(
                    "while iptables -D OUTPUT -m comment --comment {TAG} -j DROP 2>/dev/null; \
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

/// Parse a one-IP-per-line blocklist (`#` comments, optional columns), keeping
/// valid IPv4 addresses.
fn parse_ip_blocklist(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Feodo's plain list is one IP per line; tolerate a leading column.
        let token = line.split_whitespace().next().unwrap_or("");
        if is_ipv4(token) && !out.contains(&token.to_string()) {
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
}
