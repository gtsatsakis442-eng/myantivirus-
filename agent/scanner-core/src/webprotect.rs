//! Web / domain protection (**user-mode**): block known-malicious domains at the
//! OS resolver by sinkholing them in the system **hosts** file (`0.0.0.0`).
//!
//! Source: abuse.ch **URLhaus** host file (free) — domains actively serving
//! malware. Editing the hosts file needs Administrator / root, so the Talos
//! agent (LocalSystem) applies it. This is DNS/hosts-level blocking — broad and
//! effective for known-bad domains, but *not* in-browser URL inspection or
//! DoH-proof interception (that needs the Phase-2 kernel/web filter, docs/01).

use std::path::{Path, PathBuf};

use crate::error::{Result, ScanError};

/// Markers delimiting the Talos-managed block in the hosts file, so we can
/// update/remove our entries without touching the user's own.
const BEGIN: &str = "# >>> Talos EPP web protection (managed; do not edit) >>>";
const END: &str = "# <<< Talos EPP web protection <<<";

/// Default abuse.ch URLhaus host-file URL (malware-distribution domains).
pub fn default_urlhaus_url() -> &'static str {
    "https://urlhaus.abuse.ch/downloads/hostfile/"
}

/// Outcome of a web-protection sync.
#[derive(Debug, Default)]
pub struct WebReport {
    pub domains: usize,
    pub messages: Vec<String>,
}

/// Path to the system hosts file (override with `TALOS_HOSTS_FILE` for testing).
fn hosts_path() -> PathBuf {
    if let Ok(p) = std::env::var("TALOS_HOSTS_FILE") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        PathBuf::from(root)
            .join("System32")
            .join("drivers")
            .join("etc")
            .join("hosts")
    } else {
        PathBuf::from("/etc/hosts")
    }
}

/// Fetch the URLhaus host file and write a Talos-managed block section into the
/// system hosts file. Returns the number of domains applied.
pub fn sync_blocklist(url: &str) -> Result<WebReport> {
    let text = crate::firewall::fetch_https(url)?;
    let domains = parse_hostfile_domains(&text);
    if domains.is_empty() {
        return Err(ScanError::Update(
            "web protection: blocklist contained no usable domains".to_string(),
        ));
    }
    apply_domains(&domains)?;
    let count = domains.len();
    Ok(WebReport {
        domains: count,
        messages: vec![format!(
            "URLhaus: {count} malicious domain(s) sinkholed via the hosts file"
        )],
    })
}

/// Remove the Talos-managed block section from the hosts file.
pub fn clear() -> Result<()> {
    let path = hosts_path();
    let current = std::fs::read_to_string(&path)
        .map_err(|e| ScanError::Update(format!("reading hosts file: {e}")))?;
    let cleaned = strip_section(&current);
    write_hosts(&path, &cleaned)
}

fn apply_domains(domains: &[String]) -> Result<()> {
    let path = hosts_path();
    let current = std::fs::read_to_string(&path).unwrap_or_default();
    let base = strip_section(&current); // drop any previous Talos section first
    let mut out = base.trim_end().to_string();
    out.push('\n');
    out.push_str(BEGIN);
    out.push('\n');
    for d in domains {
        out.push_str("0.0.0.0 ");
        out.push_str(d);
        out.push('\n');
    }
    out.push_str(END);
    out.push('\n');
    write_hosts(&path, &out)
}

fn write_hosts(path: &Path, content: &str) -> Result<()> {
    std::fs::write(path, content).map_err(|e| {
        ScanError::Update(format!(
            "writing hosts file (needs Administrator/root): {e}"
        ))
    })
}

/// Remove the lines between the BEGIN and END markers (inclusive), leaving the
/// rest of the hosts file untouched.
fn strip_section(text: &str) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for line in text.lines() {
        match line.trim() {
            BEGIN => skipping = true,
            END => skipping = false,
            _ if !skipping => {
                out.push_str(line);
                out.push('\n');
            }
            _ => {}
        }
    }
    out
}

/// Extract domains from a hosts-format blocklist: `0.0.0.0 domain` /
/// `127.0.0.1 domain` lines, skipping comments, blanks, and `localhost`.
fn parse_hostfile_domains(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let ip = it.next().unwrap_or("");
        let domain = it.next().unwrap_or("");
        if (ip == "0.0.0.0" || ip == "127.0.0.1")
            && domain != "localhost"
            && is_domain(domain)
            && !out.contains(&domain.to_string())
        {
            out.push(domain.to_string());
        }
    }
    out
}

/// Conservative hostname check (labels of letters/digits/`-`/`_`, at least one dot).
fn is_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.contains('.')
        && !s.starts_with('.')
        && !s.ends_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_validation() {
        assert!(is_domain("evil.example.com"));
        assert!(is_domain("a.co"));
        assert!(!is_domain("localhost"));
        assert!(!is_domain("nodot"));
        assert!(!is_domain(".leading"));
        assert!(!is_domain("has space.com"));
    }

    #[test]
    fn parses_urlhaus_style_hostfile() {
        let input = "# URLhaus hostfile\n# header\n\
                     0.0.0.0 bad-one.example\n127.0.0.1 bad-two.example\n\
                     0.0.0.0 localhost\n0.0.0.0 bad-one.example\njunk line\n";
        let d = parse_hostfile_domains(input);
        assert_eq!(d, vec!["bad-one.example", "bad-two.example"]); // localhost + dup dropped
    }

    #[test]
    fn strip_section_removes_only_managed_block() {
        let hosts = "127.0.0.1 localhost\n\
                     # >>> Talos EPP web protection (managed; do not edit) >>>\n\
                     0.0.0.0 evil.example\n\
                     # <<< Talos EPP web protection <<<\n\
                     10.0.0.1 myhost\n";
        let cleaned = strip_section(hosts);
        assert!(cleaned.contains("127.0.0.1 localhost"));
        assert!(cleaned.contains("10.0.0.1 myhost"));
        assert!(!cleaned.contains("evil.example"));
        assert!(!cleaned.contains("Talos EPP web protection"));
    }

    #[test]
    fn apply_then_clear_round_trips_via_temp_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        std::fs::write(&hosts, "127.0.0.1 localhost\n").unwrap();
        std::env::set_var("TALOS_HOSTS_FILE", &hosts);

        apply_domains(&["evil.example".to_string(), "bad.example".to_string()]).unwrap();
        let after = std::fs::read_to_string(&hosts).unwrap();
        assert!(after.contains("127.0.0.1 localhost")); // preserved
        assert!(after.contains("0.0.0.0 evil.example"));
        assert!(after.contains(BEGIN) && after.contains(END));

        clear().unwrap();
        let cleared = std::fs::read_to_string(&hosts).unwrap();
        assert!(cleared.contains("127.0.0.1 localhost"));
        assert!(!cleared.contains("evil.example"));
        assert!(!cleared.contains("Talos EPP web protection"));

        std::env::remove_var("TALOS_HOSTS_FILE");
    }
}
