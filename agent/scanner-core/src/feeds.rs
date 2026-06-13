//! Signature feed updater — broadens detection by fetching reputable, openly
//! sourced signatures into a writable definitions store the engine loads.
//!
//! Network fetches shell out to the system **`curl`** (present on Windows 10+
//! and Linux), so there is no in-process TLS stack to build/maintain. The
//! production-grade signed delta channel (TUF) is described in docs/03.
//!
//! Sources (opt-in), with licenses to respect:
//!  * **abuse.ch MalwareBazaar** SHA-256 hashes — license **CC0** (public domain)
//!  * **abuse.ch ThreatFox** IOC SHA-256 hashes — **CC0**; needs a free Auth-Key
//!  * **Open YARA** rule files (e.g. Neo23x0/signature-base — **DRL**;
//!    YARA-Rules — **GPL**) — fetched at the user's request; attribution kept
//!  * **ClamAV** `.hsb` SHA-256 hash signatures — **GPL**; bring-your-own URL
//!
//! Only SHA-256 entries are ingested (the engine is SHA-256-keyed), so ClamAV
//! `.hdb` (MD5) lines are skipped.
//!
//! Hardening: downloads are restricted to **HTTPS** (`curl --proto =https
//! --tlsv1.2`), size-capped (`--max-filesize`), and time-bounded; one feed
//! failing never aborts the others.

use std::path::Path;
use std::process::Command;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::error::{Result, ScanError};

/// Ed25519 verifying key burned into the binary for signed definition-pack
/// verification.  The companion private key is kept off the repo and used
/// only by the build/release pipeline to sign first-party feeds.
///
/// To generate a new keypair (replace before production shipping):
///   openssl genpkey -algorithm ed25519 -out talos-sign.pem
///   openssl pkey -in talos-sign.pem -pubout -outform DER -out talos-sign-pub.der
///   xxd -i talos-sign-pub.der  # last 32 bytes are the raw key
///
/// To sign a feed file and produce the companion `.sig` (hex-encoded 64 bytes):
///   openssl pkeyutl -sign -inkey talos-sign.pem -rawin -in feed.hashdb \
///       | xxd -p -c 64 > feed.hashdb.sig
///
/// This placeholder is the RFC 8037 Appendix A test vector; replace with the
/// real production key before shipping.
const TALOS_VERIFYING_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// Which feeds to pull and from where.
#[derive(Debug, Clone)]
pub struct UpdateOptions {
    pub abuse_ch: bool,
    pub threatfox: bool,
    pub open_yara: bool,
    pub clamav: bool,
    pub abuse_ch_url: String,
    pub abuse_ch_auth: Option<String>,
    pub threatfox_url: String,
    pub yara_urls: Vec<String>,
    pub clamav_url: Option<String>,
    /// Optional URL to a first-party, Ed25519-signed SHA-256 hash list.
    /// The signature is fetched from `<url>.sig` (hex-encoded 64-byte raw
    /// Ed25519 signature) and verified against [`TALOS_VERIFYING_KEY`] before
    /// the hashes are applied.  Leave `None` to disable.
    pub signed_feed_url: Option<String>,
}

impl Default for UpdateOptions {
    fn default() -> Self {
        Self {
            abuse_ch: true,
            // abuse.ch ThreatFox IOC hashes (CC0); needs a free Auth-Key.
            threatfox: true,
            open_yara: true,
            // GPL + large + host-specific: opt-in, bring-your-own URL.
            clamav: false,
            abuse_ch_url: "https://bazaar.abuse.ch/export/txt/sha256/recent/".to_string(),
            abuse_ch_auth: env_nonempty("TALOS_ABUSE_KEY"),
            threatfox_url: "https://threatfox.abuse.ch/export/csv/sha256/recent/".to_string(),
            yara_urls: default_yara_urls(),
            clamav_url: env_nonempty("TALOS_CLAMAV_URL"),
            // Optional: point at a self-hosted, Ed25519-signed hash pack.
            signed_feed_url: env_nonempty("TALOS_SIGNED_FEED_URL"),
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
    // Incompatible files are skipped gracefully by the lenient YARA compiler,
    // so adding more candidates only ever broadens coverage. For a much larger
    // set, point TALOS_YARA_URLS at YARA Forge / ReversingLabs / YARA-Rules.
    [
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_webshells.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_metasploit_payloads.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_cobaltstrike.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/expl_proxyshell.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_fake_amsi_dll.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/expl_log4j_cve_2021_44228.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_mimikatz.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_susp_obfuscation.yar",
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

    if opts.threatfox {
        match opts.abuse_ch_auth.as_deref() {
            Some(key) => match fetch_text(&opts.threatfox_url, Some(key)) {
                Ok(text) => {
                    let n = parse_csv_hashes(&text, "ThreatFox");
                    let _ = std::fs::write(hashes_dir.join("threatfox.hashdb"), &n.1);
                    report.hashes_added += n.0;
                    report
                        .messages
                        .push(format!("abuse.ch ThreatFox: {} hashes", n.0));
                }
                Err(e) => report.messages.push(format!("ThreatFox: {e}")),
            },
            None => report.messages.push(
                "ThreatFox: set TALOS_ABUSE_KEY (free abuse.ch account) to enable".to_string(),
            ),
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

    // Signed first-party feed: fetch, verify Ed25519 signature, then apply.
    if let Some(ref url) = opts.signed_feed_url {
        match fetch_verified(url) {
            Ok(text) => {
                let n = parse_sha256_list(&text, "TalosSignedFeed");
                let _ = std::fs::write(hashes_dir.join("signed_feed.hashdb"), &n.1);
                report.hashes_added += n.0;
                report.messages.push(format!(
                    "signed feed: {} hash(es) — signature verified",
                    n.0
                ));
            }
            Err(e) => report.messages.push(format!("signed feed: {e}")),
        }
    }

    report
}

/// Download `url` AND the companion `<url>.sig` file (hex-encoded 64-byte raw
/// Ed25519 signature), verify the signature against [`TALOS_VERIFYING_KEY`],
/// and return the feed text only if the signature is valid.
fn fetch_verified(url: &str) -> Result<String> {
    let sig_url = format!("{url}.sig");
    let text = fetch_text(url, None)?;
    let sig_hex = fetch_text(&sig_url, None)
        .map_err(|e| ScanError::Update(format!("signature fetch failed ({sig_url}): {e}")))?;
    let sig_bytes = hex::decode(sig_hex.trim())
        .map_err(|_| ScanError::Update("signature file is not valid hex".into()))?;
    verify_ed25519(text.as_bytes(), &sig_bytes)?;
    Ok(text)
}

/// Verify a raw Ed25519 signature over `data` using the pinned
/// [`TALOS_VERIFYING_KEY`].  `sig_bytes` must be exactly 64 bytes.
fn verify_ed25519(data: &[u8], sig_bytes: &[u8]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(&TALOS_VERIFYING_KEY)
        .map_err(|e| ScanError::Update(format!("built-in verifying key is invalid: {e}")))?;
    let sig_arr: &[u8; 64] = sig_bytes.try_into().map_err(|_| {
        ScanError::Update(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        ))
    })?;
    let sig = Signature::from_bytes(sig_arr);
    vk.verify(data, &sig)
        .map_err(|_| ScanError::Update("Ed25519 signature verification failed".into()))
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
    // Hardening: only ever fetch over HTTPS, regardless of feed configuration.
    if !url.starts_with("https://") {
        return Err(ScanError::Update(format!("refusing non-HTTPS URL: {url}")));
    }
    let mut cmd = Command::new("curl");
    cmd.arg("-fsSL")
        // Force TLS and forbid protocol downgrade on redirects.
        .arg("--proto")
        .arg("=https")
        .arg("--tlsv1.2")
        .arg("--max-time")
        .arg("180")
        // Cap downloads at 256 MiB so a hostile/huge feed can't exhaust disk.
        .arg("--max-filesize")
        .arg("268435456")
        .arg("--retry")
        .arg("2")
        .arg("-A")
        .arg("talos-epp/0.3");
    if let Some(a) = auth {
        cmd.arg("-H").arg(format!("Auth-Key: {a}"));
    }
    // Stream the body to stdout and capture it in memory instead of writing a
    // predictable temp file in a world-writable dir — that path is a symlink /
    // clobber target when the agent runs as root/SYSTEM.
    cmd.arg(url);

    let output = cmd
        .output()
        .map_err(|e| ScanError::Update(format!("curl unavailable: {e}")))?;
    if !output.status.success() {
        return Err(ScanError::Update(format!(
            "download failed (curl exit {:?})",
            output.status.code()
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| ScanError::Update(format!("feed was not valid UTF-8: {url}")))
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

/// Parse a CSV export (e.g. abuse.ch ThreatFox), collecting the first 64-hex
/// SHA-256 field on each row. Tolerant of quoting, headers, and extra columns.
fn parse_csv_hashes(text: &str, family: &str) -> (usize, String) {
    let mut out = String::new();
    let mut n = 0;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for field in line.split(',') {
            let f = field.trim().trim_matches('"').to_ascii_lowercase();
            if f.len() == 64 && f.bytes().all(|b| b.is_ascii_hexdigit()) {
                out.push_str(&f);
                out.push_str("  ");
                out.push_str(family);
                out.push('\n');
                n += 1;
                break; // one hash per row
            }
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
    fn csv_hashes_extracts_sha256_column() {
        // ThreatFox-style CSV row: timestamp, id, the SHA-256 ioc, type, …
        let input = "# comment line\n\
                     \"2024-01-01 00:00:00\",\"123\",\"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\",\"sha256_hash\",\"Cobalt Strike\"\n\
                     \"2024-01-01 00:00:01\",\"124\",\"deadbeef\",\"md5_hash\",\"x\"\n";
        let (n, text) = parse_csv_hashes(input, "ThreatFox");
        assert_eq!(n, 1, "only the row with a SHA-256 field is kept");
        assert!(text.contains(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f  ThreatFox"
        ));
    }

    #[test]
    fn fetch_text_refuses_non_https() {
        let err = fetch_text("http://example.com/x", None);
        assert!(matches!(err, Err(ScanError::Update(_))));
    }

    #[test]
    fn sanitize_name_strips_paths() {
        assert_eq!(sanitize_name("gen_webshells.yar"), "gen_webshells.yar");
        assert_eq!(sanitize_name("../../etc/passwd"), "....etcpasswd");
    }

    #[test]
    fn verify_ed25519_rejects_wrong_sig() {
        // An all-zero signature is always invalid.
        let bad = [0u8; 64];
        assert!(matches!(
            verify_ed25519(b"hello world", &bad),
            Err(ScanError::Update(_))
        ));
    }

    #[test]
    fn verify_ed25519_rejects_wrong_length() {
        let short = [0u8; 32];
        assert!(matches!(
            verify_ed25519(b"hello", &short),
            Err(ScanError::Update(_))
        ));
    }

    #[test]
    fn signed_feed_url_in_default_options_reads_env() {
        // Without the env var set, signed_feed_url is None.
        std::env::remove_var("TALOS_SIGNED_FEED_URL");
        let opts = UpdateOptions::default();
        assert!(opts.signed_feed_url.is_none());
    }
}
