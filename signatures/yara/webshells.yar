/*
 * Talos EPP — web shell detection (illustrative, high-fidelity).
 * These rules target tight, low-false-positive patterns. They are examples of
 * the authoring standard (see README.md), not an exhaustive ruleset.
 */

rule PHP_WebShell_Eval_Request
{
    meta:
        author      = "Talos Threat Research"
        description = "PHP one-liner web shell: eval()/assert() of request input"
        severity    = "high"
        reference   = "MITRE ATT&CK T1505.003 (Server Software Component: Web Shell)"
        date        = "2026-06-01"
    strings:
        $php = "<?php"
        $e1 = /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase
        $e2 = /assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase
    condition:
        // Require a PHP marker AND a request-driven dynamic-exec pattern in a
        // small file: characteristic of a dropped web shell, rare in real apps.
        $php and any of ($e1, $e2) and filesize < 50KB
}

rule PHP_WebShell_System_Request
{
    meta:
        author      = "Talos Threat Research"
        description = "PHP web shell: shell command execution of request input"
        severity    = "high"
        reference   = "MITRE ATT&CK T1505.003"
        date        = "2026-06-01"
    strings:
        $php = "<?php"
        $s1 = /system\s*\(\s*\$_(POST|GET|REQUEST)\s*\[/ nocase
        $s2 = /(passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST)\s*\[/ nocase
    condition:
        $php and any of ($s1, $s2) and filesize < 50KB
}
