/*
 * Talos EPP — offensive tooling & post-exploitation (high-fidelity).
 *
 * These rules target hallmark strings/commands that are extremely rare in
 * benign software. Executable-oriented rules require a PE header (`MZ`) so a
 * document or script that merely *mentions* a tool is not flagged; command
 * rules target the actual invocation. Conditions are size-bounded.
 */

rule Mimikatz_Credential_Tool
{
    meta:
        author      = "Talos Threat Research"
        description = "Mimikatz credential-theft tool (distinctive module strings)"
        severity    = "critical"
        reference   = "MITRE ATT&CK T1003.001 (OS Credential Dumping: LSASS Memory)"
        date        = "2026-06-12"
    strings:
        $a1 = "sekurlsa::logonpasswords" nocase
        $a2 = "sekurlsa::" nocase
        $a3 = "privilege::debug" nocase
        $a4 = "lsadump::sam" nocase
        $a5 = "kuhl_m_" nocase
        $a6 = "gentilkiwi" nocase
        $a7 = "mimikatz" nocase
    condition:
        // Two independent module strings — a single passing mention is ignored.
        2 of ($a*) and filesize < 10MB
}

rule Ransomware_Inhibit_Recovery
{
    meta:
        author      = "Talos Threat Research"
        description = "Inhibits system recovery: deletes shadow copies / backups"
        severity    = "high"
        reference   = "MITRE ATT&CK T1490 (Inhibit System Recovery)"
        date        = "2026-06-12"
    strings:
        $v1 = "vssadmin delete shadows" nocase
        $v2 = "vssadmin.exe delete shadows" nocase
        $v3 = "wmic shadowcopy delete" nocase
        $v4 = "wbadmin delete catalog" nocase
        $v5 = "bcdedit /set {default} recoveryenabled no" nocase
        $v6 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase
    condition:
        any of them and filesize < 10MB
}

rule DefenseEvasion_Disable_Defender
{
    meta:
        author      = "Talos Threat Research"
        description = "Disables Microsoft Defender real-time protection / AV service"
        severity    = "high"
        reference   = "MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools)"
        date        = "2026-06-12"
    strings:
        $d1 = "Set-MpPreference -DisableRealtimeMonitoring" nocase
        $d2 = "DisableRealtimeMonitoring $true" nocase
        $d3 = "sc stop WinDefend" nocase
        $d4 = "Stop-Service WinDefend" nocase
        $d5 = "Set-MpPreference -DisableIOAVProtection" nocase
    condition:
        any of them and filesize < 5MB
}

rule DefenseEvasion_Clear_Windows_Logs
{
    meta:
        author      = "Talos Threat Research"
        description = "Clears Windows event logs / USN journal to remove evidence"
        severity    = "high"
        reference   = "MITRE ATT&CK T1070.001 (Indicator Removal: Clear Windows Event Logs)"
        date        = "2026-06-12"
    strings:
        $w1 = "wevtutil cl " nocase
        $w2 = "wevtutil.exe cl " nocase
        $w3 = "Clear-EventLog" nocase
        $w4 = "fsutil usn deletejournal" nocase
    condition:
        any of them and filesize < 5MB
}

rule CobaltStrike_Beacon
{
    meta:
        author      = "Talos Threat Research"
        description = "Cobalt Strike beacon (default named pipes / reflective payload)"
        severity    = "critical"
        reference   = "MITRE ATT&CK S0154 (Cobalt Strike)"
        date        = "2026-06-12"
    strings:
        $p1 = "\\\\.\\pipe\\MSSE-" nocase
        $p2 = "\\\\.\\pipe\\msagent_" nocase
        $p3 = "\\\\.\\pipe\\status_" nocase
        $p4 = "\\\\.\\pipe\\postex_" nocase
        $r  = "ReflectiveLoader"
        $b1 = "beacon.dll" nocase
        $b2 = "beacon.x64.dll" nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($p*) or ($r and any of ($b*)))
}

rule Meterpreter_Reflective_Stager
{
    meta:
        author      = "Talos Threat Research"
        description = "Metasploit Meterpreter reflective DLL payload markers"
        severity    = "critical"
        reference   = "Metasploit Meterpreter (reflective loading, T1055.001)"
        date        = "2026-06-12"
    strings:
        $m1 = "metsrv.dll" nocase
        $m2 = "ReflectiveLoader"
        $m3 = "stdapi_sys_process" nocase
        $m4 = "core_channel_open" nocase
    condition:
        uint16(0) == 0x5A4D and ($m1 or ($m2 and any of ($m3, $m4)))
}
