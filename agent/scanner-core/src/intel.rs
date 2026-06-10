//! Threat-intelligence enrichment — look up a file's **SHA-256** against free
//! online malware databases to learn what is publicly known about it (family,
//! tags, first-seen, AV detection ratio, sandbox verdict, OTX pulses). This is
//! the user-mode form of the cloud-reputation layer; it **never uploads file
//! content — only a hash**.
//!
//! Every provider for which a free API key is configured is queried, and the
//! results are aggregated, so you get the fullest possible picture:
//!
//! | Provider | Env var | Auth |
//! |---|---|---|
//! | **VirusTotal** v3 | `TALOS_VT_KEY` | header `x-apikey` |
//! | **abuse.ch MalwareBazaar** | `TALOS_ABUSE_KEY` | header `Auth-Key` |
//! | **MalShare** | `TALOS_MALSHARE_KEY` | query `api_key` |
//! | **AlienVault OTX** | `TALOS_OTX_KEY` | header `X-OTX-API-KEY` |
//! | **Hybrid Analysis** (Falcon Sandbox) | `TALOS_HYBRID_KEY` | header `api-key` |
//!
//! A provider whose request fails still yields a report (with an error line),
//! so one slow/over-quota provider never hides the others.

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

fn err_report(source: &str, msg: &str) -> IntelReport {
    IntelReport {
        source: source.to_string(),
        found: false,
        lines: vec![msg.to_string()],
    }
}

/// Look up `sha256` against every configured provider, returning one report
/// each. Fails only if the input isn't a SHA-256 or no provider key is set.
pub fn lookup_hash(sha256: &str) -> Result<Vec<IntelReport>> {
    let sha = sha256.trim().to_ascii_lowercase();
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ScanError::Update("not a SHA-256 hash".to_string()));
    }
    let mut reports = Vec::new();
    if let Some(k) = env_nonempty("TALOS_VT_KEY") {
        reports.push(query_vt(&sha, &k));
    }
    if let Some(k) = env_nonempty("TALOS_ABUSE_KEY") {
        reports.push(query_mb(&sha, &k));
    }
    if let Some(k) = env_nonempty("TALOS_MALSHARE_KEY") {
        reports.push(query_malshare(&sha, &k));
    }
    if let Some(k) = env_nonempty("TALOS_OTX_KEY") {
        reports.push(query_otx(&sha, &k));
    }
    if let Some(k) = env_nonempty("TALOS_HYBRID_KEY") {
        reports.push(query_hybrid(&sha, &k));
    }
    if reports.is_empty() {
        return Err(ScanError::Update(
            "set at least one provider key: TALOS_VT_KEY, TALOS_ABUSE_KEY, \
             TALOS_MALSHARE_KEY, TALOS_OTX_KEY, TALOS_HYBRID_KEY"
                .to_string(),
        ));
    }
    Ok(reports)
}

// ---- per-provider network calls (network error -> error report) ----------

fn query_vt(sha: &str, key: &str) -> IntelReport {
    match curl_request(
        &format!("https://www.virustotal.com/api/v3/files/{sha}"),
        "GET",
        &[("x-apikey", key)],
        None,
    ) {
        Ok((code, body)) => parse_vt(sha, code, &body),
        Err(e) => err_report("VirusTotal", &e.to_string()),
    }
}

fn query_mb(sha: &str, key: &str) -> IntelReport {
    match curl_request(
        "https://mb-api.abuse.ch/api/v1/",
        "POST",
        &[("Auth-Key", key)],
        Some(&format!("query=get_info&hash={sha}")),
    ) {
        Ok((_code, body)) => parse_mb(sha, &body),
        Err(e) => err_report("abuse.ch MalwareBazaar", &e.to_string()),
    }
}

fn query_malshare(sha: &str, key: &str) -> IntelReport {
    match curl_request(
        &format!("https://malshare.com/api.php?api_key={key}&action=details&hash={sha}"),
        "GET",
        &[],
        None,
    ) {
        Ok((_code, body)) => parse_malshare(sha, &body),
        Err(e) => err_report("MalShare", &e.to_string()),
    }
}

fn query_otx(sha: &str, key: &str) -> IntelReport {
    match curl_request(
        &format!("https://otx.alienvault.com/api/v1/indicators/file/{sha}/general"),
        "GET",
        &[("X-OTX-API-KEY", key)],
        None,
    ) {
        Ok((code, body)) => parse_otx(sha, code, &body),
        Err(e) => err_report("AlienVault OTX", &e.to_string()),
    }
}

fn query_hybrid(sha: &str, key: &str) -> IntelReport {
    // Falcon Sandbox requires a non-default User-Agent.
    match curl_request(
        &format!("https://www.hybrid-analysis.com/api/v2/search/hash?hash={sha}"),
        "GET",
        &[
            ("api-key", key),
            ("User-Agent", "Falcon Sandbox"),
            ("accept", "application/json"),
        ],
        None,
    ) {
        Ok((_code, body)) => parse_hybrid(sha, &body),
        Err(e) => err_report("Hybrid Analysis", &e.to_string()),
    }
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
    let mut cmd = Command::new("curl");
    // Stream the body to stdout (no temp file — a predictable path in a
    // world-writable dir is a symlink / clobber target). `-w %{http_code}`
    // appends the 3-digit status to stdout after the body; we split it off below.
    cmd.arg("-sS")
        .arg("--proto")
        .arg("=https")
        .arg("--tlsv1.2")
        .arg("--max-time")
        .arg("60")
        .arg("--max-filesize")
        .arg("8388608") // 8 MiB is plenty for a JSON report
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
        return Err(ScanError::Update("network request failed".to_string()));
    }
    // stdout is `<body><http_code>` — the write-out status is exactly 3 digits
    // appended after the body. Split it off the end.
    let mut buf = output.stdout;
    let code: u16 = if buf.len() >= 3 {
        let tail = buf.split_off(buf.len() - 3);
        String::from_utf8_lossy(&tail).trim().parse().unwrap_or(0)
    } else {
        0
    };
    let body = String::from_utf8_lossy(&buf).into_owned();
    Ok((code, body))
}

// ---- pure response parsers (unit-tested) ---------------------------------

/// Parse a MalwareBazaar `get_info` response body.
fn parse_mb(sha: &str, body: &str) -> IntelReport {
    let source = "abuse.ch MalwareBazaar".to_string();
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return err_report(&source, "unexpected response"),
    };
    let status = v.get("query_status").and_then(|s| s.as_str()).unwrap_or("");
    let found = status == "ok";
    let mut lines = Vec::new();
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
        source,
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
        Err(_) => return err_report(&source, "unexpected response"),
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

/// Parse a MalShare `details` response body.
fn parse_malshare(sha: &str, body: &str) -> IntelReport {
    let source = "MalShare".to_string();
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return err_report(&source, "Not found in MalShare (no record)."),
    };
    if v.get("sha256").and_then(|x| x.as_str()).is_none() {
        return err_report(&source, "Not found in MalShare (no record).");
    }
    let mut lines = Vec::new();
    if let Some(ft) = v.get("f_type").and_then(|x| x.as_str()) {
        lines.push(format!("File type: {ft}"));
    }
    if let Some(sources) = v.get("sources").and_then(|x| x.as_array()) {
        lines.push(format!("Known download sources: {}", sources.len()));
    }
    lines.push(format!(
        "More: https://malshare.com/sample.php?action=detail&hash={sha}"
    ));
    IntelReport {
        source,
        found: true,
        lines,
    }
}

/// Parse an AlienVault OTX `general` file-indicator response.
fn parse_otx(sha: &str, code: u16, body: &str) -> IntelReport {
    let source = "AlienVault OTX".to_string();
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return err_report(&source, &format!("no data (HTTP {code})")),
    };
    let pulse_info = v.get("pulse_info");
    let count = pulse_info
        .and_then(|p| p.get("count"))
        .and_then(|c| c.as_u64())
        .unwrap_or(0);
    let mut lines = vec![format!(
        "Threat-intel pulses referencing this file: {count}"
    )];
    if let Some(pulses) = pulse_info
        .and_then(|p| p.get("pulses"))
        .and_then(|x| x.as_array())
    {
        let names: Vec<String> = pulses
            .iter()
            .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(String::from))
            .take(3)
            .collect();
        if !names.is_empty() {
            lines.push(format!("Reports: {}", names.join("; ")));
        }
    }
    lines.push(format!(
        "More: https://otx.alienvault.com/indicator/file/{sha}"
    ));
    IntelReport {
        source,
        found: count > 0,
        lines,
    }
}

/// Parse a Hybrid Analysis (Falcon Sandbox) `search/hash` response (an array).
fn parse_hybrid(sha: &str, body: &str) -> IntelReport {
    let source = "Hybrid Analysis".to_string();
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return err_report(&source, "unexpected response"),
    };
    let first = v.as_array().and_then(|a| a.first());
    let Some(d) = first else {
        return err_report(&source, "Not found in Hybrid Analysis (no record).");
    };
    let mut lines = Vec::new();
    let verdict = d.get("verdict").and_then(|x| x.as_str());
    if let Some(verdict) = verdict {
        lines.push(format!("Verdict: {verdict}"));
    }
    if let Some(ts) = d.get("threat_score").and_then(|x| x.as_u64()) {
        lines.push(format!("Threat score: {ts}/100"));
    }
    if let Some(av) = d.get("av_detect").and_then(|x| x.as_u64()) {
        lines.push(format!("AV detect: {av}%"));
    }
    if let Some(fam) = d.get("vx_family").and_then(|x| x.as_str()) {
        lines.push(format!("Family: {fam}"));
    }
    lines.push(format!(
        "More: https://www.hybrid-analysis.com/sample/{sha}"
    ));
    let found = verdict
        .map(|v| v == "malicious" || v == "suspicious")
        .unwrap_or(true);
    IntelReport {
        source,
        found,
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
        assert!(!parse_vt("aa", 404, "").found);
    }

    #[test]
    fn parses_malshare_hit_and_miss() {
        let hit = r#"{"md5":"x","sha1":"y","sha256":"aa","f_type":"PE32 executable","sources":["http://a","http://b"]}"#;
        let r = parse_malshare("aa", hit);
        assert!(r.found);
        assert!(r.text().contains("File type: PE32 executable"));
        assert!(r.text().contains("Known download sources: 2"));
        assert!(!parse_malshare("aa", "Sample not found by hash").found);
    }

    #[test]
    fn parses_otx_pulses() {
        let body =
            r#"{"pulse_info":{"count":4,"pulses":[{"name":"Emotet wave"},{"name":"IcedID"}]}}"#;
        let r = parse_otx("aa", 200, body);
        assert!(r.found);
        assert!(r.text().contains("pulses referencing this file: 4"));
        assert!(r.text().contains("Emotet wave; IcedID"));
        assert!(!parse_otx("aa", 200, r#"{"pulse_info":{"count":0,"pulses":[]}}"#).found);
    }

    #[test]
    fn parses_hybrid_verdict() {
        let body =
            r#"[{"verdict":"malicious","threat_score":95,"av_detect":72,"vx_family":"Emotet"}]"#;
        let r = parse_hybrid("aa", body);
        assert!(r.found);
        assert!(r.text().contains("Verdict: malicious"));
        assert!(r.text().contains("Threat score: 95/100"));
        assert!(r.text().contains("Family: Emotet"));
        assert!(!parse_hybrid("aa", "[]").found);
    }
}
