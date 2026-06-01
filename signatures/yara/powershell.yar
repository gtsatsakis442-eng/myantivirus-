/*
 * Talos EPP — malicious PowerShell patterns (high-fidelity).
 * These target hallmark offensive tradecraft strings that are extremely rare
 * in legitimate scripts; conditions are anchored and size-bounded.
 */

rule PowerShell_Download_Cradle
{
    meta:
        author      = "Talos Threat Research"
        description = "PowerShell in-memory download-and-execute cradle"
        severity    = "high"
        reference   = "MITRE ATT&CK T1059.001 / T1105"
        date        = "2026-06-01"
    strings:
        $iex = "IEX" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadData" nocase
        $net = "Net.WebClient" nocase
    condition:
        $iex and ($dl1 or $dl2) and $net and filesize < 200KB
}

rule PowerShell_AMSI_Bypass
{
    meta:
        author      = "Talos Threat Research"
        description = "PowerShell AMSI bypass via amsiInitFailed reflection"
        severity    = "high"
        reference   = "MITRE ATT&CK T1562.001 (Impair Defenses)"
        date        = "2026-06-01"
    strings:
        $a = "amsiInitFailed" nocase
        $b = "System.Management.Automation.AmsiUtils" nocase
    condition:
        any of them and filesize < 200KB
}

rule PowerShell_EncodedCommand
{
    meta:
        author      = "Talos Threat Research"
        description = "PowerShell launched with a base64 -EncodedCommand payload"
        severity    = "medium"
        reference   = "MITRE ATT&CK T1027 / T1059.001"
        date        = "2026-06-01"
    strings:
        // -enc / -encodedcommand followed by a long base64 blob.
        $enc = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/]{60,}/ nocase
    condition:
        $enc and filesize < 200KB
}
