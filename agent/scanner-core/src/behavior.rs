//! Static behavioral capability analysis (L2.5).
//!
//! Inspired by Mandiant's **CAPA**: infer what a PE *would do* from its import
//! table and embedded strings, mapped to **MITRE ATT&CK**-style behavior
//! categories. This statically approximates a behavioral engine — true runtime
//! behavior monitoring (process/file/registry/network telemetry from a kernel
//! sensor) is Phase 2 (see docs/01).
//!
//! Discipline (to keep false positives low, the same stance as the heuristic
//! layer):
//!  * **Authenticode-signed** binaries are trusted and produce nothing here.
//!  * Each capability carries a weight; findings are reported only when the
//!    combined score crosses [`REPORT_THRESHOLD`], so a single benign-looking
//!    capability never raises a verdict on its own.
//!  * Output is always *suspicion* — never a standalone malicious verdict
//!    (hash/YARA remain the only layers that convict).

use goblin::pe::PE;

use crate::verdict::{Detection, DetectionKind, Severity};

/// Bytes scanned for embedded strings — a DoS guard on crafted/huge files.
const MAX_STRING_BYTES: usize = 16 * 1024 * 1024;

/// Minimum combined weight of matched behaviors before anything is reported.
const REPORT_THRESHOLD: u32 = 3;

/// A matched behavioral capability.
struct Cap {
    /// Human-readable capability id, e.g. `Behavior.ProcessInjection`.
    name: &'static str,
    /// MITRE ATT&CK technique id.
    mitre: &'static str,
    severity: Severity,
    /// Contribution to the report threshold.
    weight: u32,
}

/// Analyze a buffer, returning behavioral findings (empty for non-PE, signed,
/// or below-threshold input).
pub fn analyze(data: &[u8]) -> Vec<Detection> {
    match PE::parse(data) {
        Ok(pe) => analyze_pe(&pe, data),
        Err(_) => Vec::new(),
    }
}

/// Like [`analyze`] but reuses an already-parsed PE (shared with the heuristic
/// layer by the engine, so a file's PE is parsed once per scan, not twice).
pub(crate) fn analyze_pe(pe: &PE, data: &[u8]) -> Vec<Detection> {
    // Trust signed binaries — same FP discipline as the heuristic layer.
    if crate::heuristics::is_authenticode_signed(pe) {
        return Vec::new();
    }

    let imports: Vec<String> = pe
        .imports
        .iter()
        .map(|i| i.name.to_ascii_lowercase())
        .collect();
    let hay = behavioral_haystack(data);
    detections_from(&imports, &hay, imports.len())
}

/// Match capabilities, apply the score threshold, and map to detections. Kept
/// free of PE parsing so the (FP-sensitive) policy is unit-testable directly.
fn detections_from(imports: &[String], hay: &str, import_count: usize) -> Vec<Detection> {
    let caps = match_capabilities(imports, hay, import_count);
    let score: u32 = caps.iter().map(|c| c.weight).sum();
    if score < REPORT_THRESHOLD {
        return Vec::new();
    }
    caps.into_iter()
        .map(|c| Detection {
            name: format!("{} [{}]", c.name, c.mitre),
            kind: DetectionKind::Behavior,
            severity: c.severity,
        })
        .collect()
}

/// Build one lowercased haystack covering ASCII and (zero-collapsed) UTF-16LE
/// strings, bounded by [`MAX_STRING_BYTES`].
fn behavioral_haystack(data: &[u8]) -> String {
    let n = data.len().min(MAX_STRING_BYTES);
    let mut out = String::with_capacity(n / 2);
    for &b in &data[..n] {
        if b == 0 {
            continue; // collapse UTF-16LE wide chars into their ASCII bytes
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

fn match_capabilities(imports: &[String], hay: &str, import_count: usize) -> Vec<Cap> {
    let imp = |needle: &str| imports.iter().any(|i| i.contains(needle));
    let any_imp = |needles: &[&str]| needles.iter().any(|n| imp(n));
    let s = |needle: &str| hay.contains(needle);
    let any_s = |needles: &[&str]| needles.iter().any(|n| s(n));

    let mut caps: Vec<Cap> = Vec::new();

    // Process injection: allocate + write + remote execution in another process.
    let alloc = any_imp(&["virtualallocex", "ntallocatevirtualmemory"]);
    let write = any_imp(&["writeprocessmemory", "ntwritevirtualmemory"]);
    let exec = any_imp(&[
        "createremotethread",
        "ntcreatethreadex",
        "rtlcreateuserthread",
        "queueuserapc",
        "ntqueueapcthread",
        "setthreadcontext",
    ]);
    if alloc && write && exec {
        caps.push(Cap {
            name: "Behavior.ProcessInjection",
            mitre: "T1055",
            severity: Severity::High,
            weight: 3,
        });
    }

    // Credential access: LSASS memory dumping.
    if imp("minidumpwritedump") || (s("lsass") && any_imp(&["openprocess", "readprocessmemory"])) {
        caps.push(Cap {
            name: "Behavior.CredentialAccess",
            mitre: "T1003",
            severity: Severity::High,
            weight: 3,
        });
    }

    // Ransomware-like: cryptographic encryption + mass file enumeration.
    let crypto = any_imp(&[
        "cryptencrypt",
        "bcryptencrypt",
        "cryptderivekey",
        "cryptgenkey",
    ]);
    let enum_files = any_imp(&["findfirstfile", "findnextfile"]);
    if crypto && enum_files {
        caps.push(Cap {
            name: "Behavior.Ransomware",
            mitre: "T1486",
            severity: Severity::High,
            weight: 3,
        });
    }

    // Defense evasion: AMSI / ETW tampering.
    if s("amsiscanbuffer") || (s("etweventwrite") && s("amsi")) {
        caps.push(Cap {
            name: "Behavior.DefenseEvasion.AmsiEtw",
            mitre: "T1562.001",
            severity: Severity::High,
            weight: 3,
        });
    }

    // Anti-analysis: debugger / sandbox / VM detection.
    if any_imp(&[
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ntqueryinformationprocess",
    ]) || any_s(&[
        "vmware",
        "virtualbox",
        "vboxservice",
        "qemu",
        "sbiedll",
        "sandboxie",
    ]) {
        caps.push(Cap {
            name: "Behavior.AntiAnalysis",
            mitre: "T1497",
            severity: Severity::Medium,
            weight: 2,
        });
    }

    // Persistence: Run key / service / scheduled task.
    if (imp("regsetvalue") && any_s(&["currentversion\\run", "currentversion/run"]))
        || imp("createservice")
        || any_s(&["schtasks", "currentversion\\runonce"])
    {
        caps.push(Cap {
            name: "Behavior.Persistence",
            mitre: "T1547",
            severity: Severity::Medium,
            weight: 2,
        });
    }

    // Keylogging.
    if imp("setwindowshookex") && any_imp(&["getasynckeystate", "getkeystate", "getkeyboardstate"])
    {
        caps.push(Cap {
            name: "Behavior.Keylogging",
            mitre: "T1056.001",
            severity: Severity::Medium,
            weight: 2,
        });
    }

    // Download / command-and-control.
    if any_imp(&[
        "urldownloadtofile",
        "internetopenurl",
        "winhttpopenrequest",
        "internetreadfile",
    ]) || (any_imp(&["wsastartup", "connect", "recv"])
        && any_s(&["http://", "https://", "user-agent"]))
    {
        caps.push(Cap {
            name: "Behavior.CommandAndControl",
            mitre: "T1071",
            severity: Severity::Medium,
            weight: 2,
        });
    }

    // Privilege escalation: enable SeDebugPrivilege.
    if imp("adjusttokenprivileges") && s("sedebugprivilege") {
        caps.push(Cap {
            name: "Behavior.PrivilegeEscalation",
            mitre: "T1134",
            severity: Severity::Medium,
            weight: 2,
        });
    }

    // Execution via shell / script interpreter.
    if any_s(&[
        "cmd.exe /c",
        "cmd /c",
        "powershell -",
        "powershell.exe",
        "-encodedcommand",
        "wscript.shell",
    ]) {
        caps.push(Cap {
            name: "Behavior.Execution.Shell",
            mitre: "T1059",
            severity: Severity::Medium,
            weight: 2,
        });
    }

    // Dynamic API resolution with a tiny import table (packer / loader).
    if imp("getprocaddress") && any_imp(&["loadlibrary", "ldrloaddll"]) && import_count < 15 {
        caps.push(Cap {
            name: "Behavior.DynamicApiResolution",
            mitre: "T1027",
            severity: Severity::Low,
            weight: 1,
        });
    }

    // Discovery: host + process enumeration.
    if any_imp(&["getcomputername", "getusername"])
        && any_imp(&[
            "createtoolhelp32snapshot",
            "process32first",
            "process32next",
        ])
    {
        caps.push(Cap {
            name: "Behavior.Discovery",
            mitre: "T1082",
            severity: Severity::Low,
            weight: 1,
        });
    }

    caps
}

#[cfg(test)]
mod tests {
    use super::*;

    fn imports(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn injection_trio_flags_high() {
        let imp = imports(&["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]);
        let lower: Vec<String> = imp.iter().map(|s| s.to_ascii_lowercase()).collect();
        let d = detections_from(&lower, "", lower.len());
        assert_eq!(d.len(), 1);
        assert!(d[0].name.starts_with("Behavior.ProcessInjection"));
        assert!(d[0].name.contains("T1055"));
        assert_eq!(d[0].kind, DetectionKind::Behavior);
        assert_eq!(d[0].severity, Severity::High);
    }

    #[test]
    fn lone_weak_signal_is_not_reported() {
        // Anti-analysis alone (weight 2) is below the threshold (3).
        let lower = imports(&["isdebuggerpresent"]);
        assert!(detections_from(&lower, "", lower.len()).is_empty());
    }

    #[test]
    fn two_weak_signals_corroborate() {
        // Anti-analysis (2) + keylogging (2) = 4 >= threshold.
        let lower = imports(&["isdebuggerpresent", "setwindowshookex", "getasynckeystate"]);
        let d = detections_from(&lower, "", lower.len());
        assert!(d.len() >= 2, "both behaviors reported: {d:?}");
        assert!(d
            .iter()
            .any(|x| x.name.starts_with("Behavior.AntiAnalysis")));
        assert!(d.iter().any(|x| x.name.starts_with("Behavior.Keylogging")));
    }

    #[test]
    fn ransomware_combo_flags() {
        let lower = imports(&["CryptEncrypt", "FindFirstFileW", "FindNextFileW"]);
        let lower: Vec<String> = lower.iter().map(|s| s.to_ascii_lowercase()).collect();
        let d = detections_from(&lower, "", lower.len());
        assert!(d.iter().any(|x| x.name.starts_with("Behavior.Ransomware")));
    }

    #[test]
    fn benign_imports_yield_nothing() {
        let lower = imports(&["getmodulehandlew", "messageboxw", "getcommandlinew"]);
        assert!(detections_from(&lower, "hello world", lower.len()).is_empty());
    }

    #[test]
    fn non_pe_is_empty() {
        assert!(analyze(b"not a PE file").is_empty());
    }

    #[test]
    fn haystack_handles_utf16_and_bounds() {
        // UTF-16LE "run" -> collapses to "run".
        let wide = [b'r', 0, b'u', 0, b'n', 0];
        assert!(behavioral_haystack(&wide).contains("run"));
    }
}
