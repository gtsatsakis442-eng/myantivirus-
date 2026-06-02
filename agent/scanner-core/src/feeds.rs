//! Signature feed updater — broadens detection by fetching reputable, openly
//! sourced signatures into a writable definitions store the engine loads.
//!
//! Network fetches shell out to the system **`curl`** (present on Windows 10+
//! and Linux), so there is no in-process TLS stack to build/maintain. The
//! production-grade signed delta channel (TUF) is described in docs/03.
//!
//! Sources (opt-in), with licenses to respect:
//!  * **abuse.ch MalwareBazaar** SHA-256 hashes — license **CC0** (public domain)
//!  * **Open YARA** rule files (e.g. Neo23x0/signature-base — **DRL**;
//!    YARA-Rules — **GPL**) — fetched at the user's request; attribution kept
//!  * **ClamAV** `.hsb` SHA-256 hash signatures — **GPL**; bring-your-own URL
//!
//! Only SHA-256 entries are ingested (the engine is SHA-256-keyed), so ClamAV
//! `.hdb` (MD5) lines are skipped.

use std::path::Path;
use std::process::Command;

use crate::error::{Result, ScanError};

/// Which feeds to pull and from where.
#[derive(Debug, Clone)]
pub struct UpdateOptions {
    pub abuse_ch: bool,
    pub open_yara: bool,
    pub clamav: bool,
    pub abuse_ch_url: String,
    pub abuse_ch_auth: Option<String>,
    pub yara_urls: Vec<String>,
    pub clamav_url: Option<String>,
}

impl Default for UpdateOptions {
    fn default() -> Self {
        Self {
            abuse_ch: true,
            open_yara: true,
            // GPL + large + host-specific: opt-in, bring-your-own URL.
            clamav: false,
            abuse_ch_url: "https://bazaar.abuse.ch/export/txt/sha256/recent/".to_string(),
            abuse_ch_auth: env_nonempty("TALOS_ABUSE_KEY"),
            yara_urls: default_yara_urls(),
            clamav_url: env_nonempty("TALOS_CLAMAV_URL"),
        }
    }
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn default_yara_urls() -> Vec<String> {
    if let Some(v) = env_nonempty("TALOS_YARA_URLS") {
        return v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    // A small, broad selection from Neo23x0/signature-base (DRL-licensed).
    [
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_webshells.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_metasploit_payloads.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_cobaltstrike.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/expl_proxyshell.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_fake_amsi_dll.yar",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Outcome of an update run (per-feed messages + totals).
#[derive(Debug, Default)]
pub struct UpdateReport {
    pub messages: Vec<String>,
    pub hashes_added: usize,
    pub yara_files: usize,
}

/// Fetch the configured feeds into `store` (`store/hashes/*.hashdb`,
/// `store/yara/*.yar`). Failures of one feed don't abort the others.
pub fn update(store: &Path, opts: &UpdateOptions) -> UpdateReport {
    let mut report = UpdateReport::default();
    let hashes_dir = store.join("hashes");
    let yara_dir = store.join("yara");
    let _ = std::fs::create_dir_all(&hashes_dir);
    let _ = std::fs::create_dir_all(&yara_dir);

    if opts.abuse_ch {
        match fetch_text(&opts.abuse_ch_url, opts.abuse_ch_auth.as_deref()) {
            Ok(text) => {
                let n = parse_sha256_list(&text, "MalwareBazaar");
                let _ = std::fs::write(hashes_dir.join("malwarebazaar.hashdb"), &n.1);
                report.hashes_added += n.0;
                report
                    .messages
                    .push(format!("abuse.ch MalwareBazaar: {} hashes", n.0));
            }
            Err(e) => report.messages.push(format!("abuse.ch: {e}")),
        }
    }

    if opts.clamav {
        match &opts.clamav_url {
            Some(url) => match fetch_text(url, None) {
                Ok(text) => {
                    let n = parse_clamav_hashes(&text);
                    let _ = std::fs::write(hashes_dir.join("clamav.hashdb"), &n.1);
                    report.hashes_added += n.0;
                    report
                        .messages
                        .push(format!("ClamAV: {} SHA-256 hashes", n.0));
                }
                Err(e) => report.messages.push(format!("ClamAV: {e}")),
            },
            None => report
                .messages
                .push("ClamAV: set TALOS_CLAMAV_URL to a .hsb SHA-256 list".to_string()),
        }
    }

    if opts.open_yara {
        let mut ok = 0usize;
        for url in &opts.yara_urls {
            let name = sanitize_name(url.rsplit('/').next().unwrap_or("rules.yar"));
            match fetch_text(url, None) {
                Ok(text) if text.contains("rule ") => {
                    if std::fs::write(yara_dir.join(&name), text).is_ok() {
                        ok += 1;
                    }
                }
                Ok(_) => report
                    .messages
                    .push(format!("YARA {name}: not a rule file")),
                Err(e) => report.messages.push(format!("YARA {name}: {e}")),
            }
        }
        report.yara_files += ok;
        report
            .messages
            .push(format!("Open YARA: {ok} rule file(s)"));
    }

    report
}

fn sanitize_name(name: &str) -> String {
    let n: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_' || *c == '-')
        .collect();
    if n.is_empty() {
        "rules.yar".to_string()
    } else {
        n
    }
}

fn fetch_text(url: &str, auth: Option<&str>) -> Result<String> {
    let tmp = std::env::temp_dir().join(format!(
        "talos-feed-{}-{}.tmp",
        std::process::id(),
        url.len()
    ));
    let mut cmd = Command::new("curl");
    cmd.arg("-fsSL")
        .arg("--max-time")
        .arg("180")
        .arg("-A")
        .arg("talos-epp/0.1");
    if let Some(a) = auth {
        cmd.arg("-H").arg(format!("Auth-Key: {a}"));
    }
    cmd.arg("-o").arg(&tmp).arg(url);

    let status = cmd
        .status()
        .map_err(|e| ScanError::Update(format!("curl unavailable: {e}")))?;
    if !status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(ScanError::Update(format!(
            "download failed (curl exit {:?})",
            status.code()
        )));
    }
    let text = std::fs::read_to_string(&tmp).map_err(|source| ScanError::Io {
        path: tmp.clone(),
        source,
    })?;
    let _ = std::fs::remove_file(&tmp);
    Ok(text)
}

/// Parse a list of SHA-256 hashes (one per line, optional `"`/`#`), returning
/// `(count, hashdb_text)` in our `<sha256>  Family` format.
fn parse_sha256_list(text: &str, family: &str) -> (usize, String) {
    let mut out = String::new();
    let mut n = 0;
    for raw in text.lines() {
        let line = raw.trim().trim_matches('"');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() == 64 && line.bytes().all(|b| b.is_ascii_hexdigit()) {
            out.push_str(&line.to_ascii_lowercase());
            out.push_str("  ");
            out.push_str(family);
            out.push('\n');
            n += 1;
        }
    }
    (n, out)
}

/// Parse ClamAV hash signatures (`<hash>:<size>:<name>`); keeps SHA-256 only.
fn parse_clamav_hashes(text: &str) -> (usize, String) {
    let mut out = String::new();
    let mut n = 0;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.split(':');
        let hash = f.next().unwrap_or("").trim().to_ascii_lowercase();
        let _size = f.next();
        let name = f.next().unwrap_or("ClamAV").trim();
        if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            out.push_str(&hash);
            out.push_str("  ClamAV.");
            out.push_str(if name.is_empty() { "Sig" } else { name });
            out.push('\n');
            n += 1;
        }
    }
    (n, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_list_parses_and_skips_junk() {
        let input = "# header\n\
                     \"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\"\n\
                     deadbeef\n\
                     275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F\n";
        let (n, text) = parse_sha256_list(input, "MalwareBazaar");
        assert_eq!(n, 2); // the quoted one + the uppercase one; "deadbeef" skipped
        assert!(text.contains(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f  MalwareBazaar"
        ));
    }

    #[test]
    fn clamav_hsb_keeps_sha256_skips_md5() {
        let input = "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Md5\n\
                     275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:Win.Test.EICAR_HDB-1\n";
        let (n, text) = parse_clamav_hashes(input);
        assert_eq!(n, 1, "only the SHA-256 line is kept");
        assert!(text.contains("ClamAV.Win.Test.EICAR_HDB-1"));
    }

    #[test]
    fn sanitize_name_strips_paths() {
        assert_eq!(sanitize_name("gen_webshells.yar"), "gen_webshells.yar");
        assert_eq!(sanitize_name("../../etc/passwd"), "....etcpasswd");
    }
}
