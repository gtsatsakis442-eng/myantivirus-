/*
 * Sentinel EPP — test-vector rules.
 * High-fidelity: the EICAR string is a standardized test token that does not
 * occur in legitimate software outside of AV testing.
 */

rule EICAR_Test_File
{
    meta:
        author      = "Sentinel Threat Research"
        description = "EICAR standard anti-malware test file (NOT real malware)"
        severity    = "low"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
        date        = "2026-06-01"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    condition:
        // Bound location and size to keep the rule tight (the real file is 68 bytes).
        $eicar in (0..256) and filesize < 1KB
}
