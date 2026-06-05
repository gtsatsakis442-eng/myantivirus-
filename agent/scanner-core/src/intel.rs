//! Threat-intelligence enrichment — look up a file's **SHA-256** against a free
//! online malware database to learn what is publicly known about it (family,
//! tags, first-seen, AV detection ratio). This is the user-mode form of the
//! cloud-reputation layer; it **never uploads file content — only a hash**.
//!
//! Providers (free; key from a free account; HTTPS-only via `curl`):
//!  * abuse.ch **MalwareBazaar** — `query=get_info`, header `Auth-Key`
//!    (`TALOS_ABUSE_KEY`, get one at <https://auth.abuse.ch/>).
//!  * **VirusTotal** v3 — `GET /api/v3/files/<sha256>`, header `x-apikey`
//!    (`TALOS_VT_KEY`).
//!
//! Selection order: VirusTotal if `TALOS_VT_KEY` is set, else MalwareBazaar if
//! `TALOS_ABUSE_KEY` is set, else a helpful "set a key" error.

use std::process::Command;

use serde_json::Value;

use crate::error::{Result, ScanError};

/// The result of a hash lookup against one provider.
#[derive(Debug, Clone)]
pub struct IntelReport {
    pub source: String,
    /// Whether the provider had a record of this hash.
    pub found: bool,
    /// Human-readable `Label: value` lines for display.
    pub lines: Vec<String>,
}

impl IntelReport {
    pub fn text(&self) -> String {
        self.lines.join("\n")
    }
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

/// Look up `sha256` against the configured provider.
pub fn lookup_hash(sha256: &str) -> Result<IntelReport> {
    let sha = sha256.trim().to_ascii_lowercase();
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ScanError::Update("not a SHA-256 hash".to_string()));
    }
    if let Some(key) = env_nonempty("TALOS_VT_KEY") {
        let (code, body) = curl_request(
            &format!("https://www.virustotal.com/api/v3/files/{sha}"),
            "GET",
            &[("x-apikey", key.as_str())],
            None,
        )?;
        return Ok(parse_vt(&sha, code, &body));
    }
    if let Some(key) = env_nonempty("TALOS_ABUSE_KEY") {
        let (_code, body) = curl_request(
            "https://mb-api.abuse.ch/api/v1/",
            "POST",
            &[("Auth-Key", key.as_str())],
            Some(&format!("query=get_info&hash={sha}")),
        )?;
        return Ok(parse_mb(&sha, &body));
    }
    Err(ScanError::Update(
        "set TALOS_ABUSE_KEY (auth.abuse.ch) or TALOS_VT_KEY (virustotal.com) to enable lookups"
            .to_string(),
    ))
}

/// Issue an HTTPS request via `curl`, returning `(http_status, body)`. Uses no
/// `-f`, so HTTP errors (e.g. 404 = not found) return their body rather than
/// failing — only genuine network/transfer errors are surfaced as `Err`.
fn curl_request(
    url: &str,
    method: &str,
    headers: &[(&str, &str)],
    data: Option<&str>,
) -> Result<(u16, String)> {
    if !url.starts_with("https://") {
        return Err(ScanError::Update(format!("refusing non-HTTPS URL: {url}")));
    }
    let tmp = std::env::temp_dir().join(format!(
        "talos-intel-{}-{}.tmp",
        std::process::id(),
        url.len()
    ));
    let mut cmd = Command::new("curl");
    cmd.arg("-sS")
        .arg("--proto")
        .arg("=https")
        .arg("--tlsv1.2")
        .arg("--max-time")
        .arg("60")
        .arg("--max-filesize")
        .arg("8388608") // 8 MiB is plenty for a JSON report
        .arg("-o")
        .arg(&tmp)
        .arg("-w")
        .arg("%{http_code}");
    if method == "POST" {
        cmd.arg("-X").arg("POST");
    }
    for (k, v) in headers {
        cmd.arg("-H").arg(format!("{k}: {v}"));
    }
    if let Some(d) = data {
        cmd.arg("--data").arg(d);
    }
    cmd.arg(url);

    let output = cmd
        .output()
        .map_err(|e| ScanError::Update(format!("curl unavailable: {e}")))?;
    if !output.status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(ScanError::Update("network request failed".to_string()));
    }
    let code: u16 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or(0);
    let body = std::fs::read_to_string(&tmp).unwrap_or_default();
    let _ = std::fs::remove_file(&tmp);
    Ok((code, body))
}

/// Parse a MalwareBazaar `get_info` response body.
fn parse_mb(sha: &str, body: &str) -> IntelReport {
    let mut lines = Vec::new();
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return IntelReport {
                source: "abuse.ch MalwareBazaar".to_string(),
                found: false,
                lines: vec!["unexpected response".to_string()],
            }
        }
    };
    let status = v.get("query_status").and_then(|s| s.as_str()).unwrap_or("");
    let found = status == "ok";
    if found {
        if let Some(d) = v
            .get("data")
            .and_then(|d| d.as_array())
            .and_then(|a| a.first())
        {
            let g = |k: &str| d.get(k).and_then(|x| x.as_str()).unwrap_or("—").to_string();
            lines.push(format!("Family / signature: {}", g("signature")));
            lines.push(format!("File type: {}", g("file_type")));
            lines.push(format!("First seen: {}", g("first_seen")));
            if let Some(tags) = d.get("tags").and_then(|t| t.as_array()) {
                let t: Vec<String> = tags
                    .iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect();
                if !t.is_empty() {
                    lines.push(format!("Tags: {}", t.join(", ")));
                }
            }
        }
        lines.push(format!("More: https://bazaar.abuse.ch/sample/{sha}/"));
    } else if status == "hash_not_found" {
        lines.push("Not found in MalwareBazaar (no record of this hash).".to_string());
    } else {
        lines.push(format!("MalwareBazaar: {status}"));
    }
    IntelReport {
        source: "abuse.ch MalwareBazaar".to_string(),
        found,
        lines,
    }
}

/// Parse a VirusTotal v3 file report (`code` is the HTTP status).
fn parse_vt(sha: &str, code: u16, body: &str) -> IntelReport {
    let source = "VirusTotal".to_string();
    if code == 404 {
        return IntelReport {
            source,
            found: false,
            lines: vec!["Not found in VirusTotal (no record of this hash).".to_string()],
        };
    }
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return IntelReport {
                source,
                found: false,
                lines: vec!["unexpected response".to_string()],
            }
        }
    };
    let mut lines = Vec::new();
    if let Some(a) = v.get("data").and_then(|d| d.get("attributes")) {
        if let Some(st) = a.get("last_analysis_stats") {
            let n = |k: &str| st.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
            let flagged = n("malicious") + n("suspicious");
            let total = flagged + n("undetected") + n("harmless") + n("timeout");
            lines.push(format!("AV detections: {flagged}/{total} engines"));
        }
        if let Some(label) = a
            .get("popular_threat_classification")
            .and_then(|p| p.get("suggested_threat_label"))
            .and_then(|x| x.as_str())
        {
            lines.push(format!("Threat label: {label}"));
        }
        if let Some(td) = a.get("type_description").and_then(|x| x.as_str()) {
            lines.push(format!("File type: {td}"));
        }
    }
    lines.push(format!("More: https://www.virustotal.com/gui/file/{sha}"));
    IntelReport {
        source,
        found: code == 200,
        lines,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_hash() {
        assert!(lookup_hash("not-a-hash").is_err());
        assert!(lookup_hash("deadbeef").is_err());
    }

    #[test]
    fn parses_malwarebazaar_hit() {
        let body = r#"{"query_status":"ok","data":[{"signature":"CobaltStrike","file_type":"exe","first_seen":"2024-01-01 00:00:00","tags":["CobaltStrike","exe"]}]}"#;
        let r = parse_mb("aa", body);
        assert!(r.found);
        assert!(r.text().contains("Family / signature: CobaltStrike"));
        assert!(r.text().contains("Tags: CobaltStrike, exe"));
    }

    #[test]
    fn parses_malwarebazaar_miss() {
        let r = parse_mb("aa", r#"{"query_status":"hash_not_found"}"#);
        assert!(!r.found);
        assert!(r.text().to_lowercase().contains("not found"));
    }

    #[test]
    fn parses_virustotal_stats() {
        let body = r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":58,"suspicious":2,"undetected":10,"harmless":0,"timeout":0},"popular_threat_classification":{"suggested_threat_label":"trojan.cobaltstrike/beacon"},"type_description":"Win32 EXE"}}}"#;
        let r = parse_vt("aa", 200, body);
        assert!(r.found);
        assert!(r.text().contains("AV detections: 60/70 engines"));
        assert!(r.text().contains("trojan.cobaltstrike/beacon"));
    }

    #[test]
    fn virustotal_404_is_not_found() {
        let r = parse_vt("aa", 404, "");
        assert!(!r.found);
    }
}
