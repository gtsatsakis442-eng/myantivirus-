# Security Policy

Talos EPP is a **defensive endpoint-protection product**. We hold the codebase
to the same security bar we expect of anything that runs with high privilege on
a user's machine. This document explains how to report a vulnerability and what
the product does to stay trustworthy.

---

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through GitHub's **“Report a vulnerability”** flow
(repository **Security** tab → **Advisories** → *Report a vulnerability*). This
opens a private advisory visible only to the maintainers.

Include where you can:

- affected component (`scanner-core`, `talos-agent`, `talos-gui`, `talos-ipc`,
  `scanner-cli`, installer, or CI/release pipeline) and version (`v0.13.x`);
- a description of the issue and its security impact;
- reproduction steps or a proof-of-concept;
- any suggested remediation.

**What to expect**

| Stage | Target |
|---|---|
| Acknowledgement of your report | within **72 hours** |
| Initial assessment & severity (CVSS) | within **7 days** |
| Fix or mitigation plan | tracked on the private advisory |
| Coordinated public disclosure | after a fix ships, by mutual agreement |

We support coordinated disclosure and will credit reporters who wish to be
named. Please give us a reasonable window to remediate before any public
disclosure.

---

## Supported Versions

Phase 1 ships as a rolling release. Security fixes land on `main` and are
published to the **`latest`** release.

| Version | Supported |
|---|---|
| `0.13.x` (current) | ✅ |
| `< 0.13` | ❌ (upgrade to the latest) |

---

## Product Security Posture

This section is intentionally specific so deployers can audit our claims. Where
something is a roadmap item rather than shipping behavior, it is labeled as
such — we do not present planned controls as if they were active.

### Memory safety & supply chain

- **No `unsafe` in our own code.** `scanner-core` enforces this at compile time
  with `#![forbid(unsafe_code)]`. The only `unsafe` in the dependency tree lives
  in audited, widely-used crates (`goblin` for PE parsing, `yara-x`,
  `rusqlite`/`libsqlite3-sys`).
- **No FFI.** OS capabilities are driven through well-scoped **subprocesses**
  (`netsh`/`iptables`, `curl`, PowerShell `Get-AuthenticodeSignature`,
  `iptables-restore`) rather than hand-rolled foreign-function bindings, keeping
  the native attack surface minimal.
- **CI security gates** on every PR: `cargo fmt --check`, `cargo clippy
  --workspace -- -D warnings` (warnings are errors), the full test suite, and a
  release build on **both Linux and Windows (MSVC)**. A **CodeQL** analysis
  workflow runs static security analysis.
- **Signed releases (roadmap):** EV-signed Windows binaries and a
  WHQL/attestation-signed kernel sensor are planned (see
  [docs/04](docs/04-deployment-distribution.md)). Until the EV certificate is
  applied, downloaded binaries are **unsigned** and will trigger SmartScreen.

### Trust & detection pipeline (fail-secure by design)

- **Cryptographic trust check is fail-secure.** Native signature validation
  (Authenticode via `Get-AuthenticodeSignature`) runs first; a binary is only
  treated as legitimate when it **chains to a trusted root**. Trust is **never**
  granted on a publisher *name* string alone.
- **Cloud reputation never blocks or leaks.** Threat-intel lookups send **only a
  SHA-256 hash — never file contents**, are bounded by a **token-bucket rate
  limiter** (so provider quotas can't be exceeded) and a **hard 500 ms
  timeout**, and **fail secure to local analysis** on timeout/error.
- **Anti-false-positive without anti-security.** Legitimate-DLL suppression
  requires a full **`path` + `SHA-256` + `signing-cert thumbprint`** match — never
  name/path alone — which defeats **DLL side-loading / hijacking**. A trusted
  module loaded from a high-risk context (temp/download dir, or under a LOLBin
  such as `powershell`/`rundll32`/`regsvr32`) is **escalated to isolation**, not
  suppressed.
- **Heuristic/behavioral findings are corroborated**, not auto-actioned: a
  *suspicious* verdict requires signals whose combined weight reaches a
  threshold, and Authenticode-signed binaries are fully trusted at this layer
  to keep false positives low.

#### Detection layers in depth (what is actually shipping)

| Layer | Engine | What it catches |
|---|---|---|
| **L1 — Hash** | SHA-256 exact match against `.hashdb` | Known-bad files; always-on even for oversized files |
| **L2 — YARA** | `yara-x` compiled ruleset | Pattern families: ransomware, stealers, loaders, webshells, packers |
| **L2 — PE heuristics** | `goblin` PE parser | Packed code (entropy > 7.2), W^X sections, injection import trio, 23 packer section names (UPX/Themida/VMProtect/MPRESS…), anomalous overlay, zero imports, DLL-with-no-exports, `ReflectiveLoader` export (standalone High) |
| **L2.5 — Behavioral** | Import + string capability inference (CAPA-style) | 25 ATT&CK-tagged patterns: process injection, hollowing, mapped-section injection, token impersonation, driver loading, WMI persistence, UAC bypass, named-pipe C2, DCSync/Kerberoast, registry hive dump, boot-config tamper, LSASS dump, ransomware file-encrypt loop, AMSI/ETW bypass, anti-analysis, keylogging, C2 download, lateral movement, browser credential theft, and more |
| **L3 — Script analysis** | Lowercased text haystack (handles UTF-16LE) | **Non-PE content only** — PHP/ASP/ASPX webshells (eval on `$_POST`, gzinflate+base64 chain, 9 kit names), VBScript/JScript droppers (ADODB.Stream, WScript.Shell.Run, MSXML2), PowerShell post-exploitation (16 named cmdlets, base64+IEX chain, char-obfuscation), batch destruction (format/del/cipher), Metasploit, Cobalt Strike, Mimikatz, 7 RAT families |
| **L3 — LOLBin** | String pattern registry | 20+ LOLBin abuse patterns: PowerShell -enc, download cradles, IEX, reflective load, MSHTA, Certutil, Regsvr32, Rundll32, BITSAdmin, MSIExec, InstallUtil, WMIC, Netsh, schtasks, net user, DNSCmd, MavInject |
| **L4 — Archive** | ZIP unpacking with zip-bomb guard | Infected entries inside `.zip` archives (entry-attributed findings) |
| **L5 — Realtime** | fanotify (Linux) / ReadDirectoryChangesW (Windows) | On-access interception: each written/executed file scanned by the full pipeline before the process can read it |

All non-PE script content (PowerShell `.ps1`, VBScript `.vbs`, JScript `.js`,
PHP/ASPX webshells, batch `.bat`) is now processed by **both** the LOLBin
detector and the script-analysis layer, closing the gap that existed when only
PE images received dynamic analysis.

### Secure updates

- The signed-feed channel verifies an **Ed25519** signature over downloaded
  content (`url` + `url.sig`) against `TALOS_VERIFYING_KEY` before applying it.
- ⚠️ The shipped verifying key is an **RFC 8037 test vector** and **must be
  replaced with a production key before shipping** (see `feeds.rs` and
  [docs/03](docs/03-secure-updates.md)).
- All feed/intel downloads are **HTTPS-only**, TLS ≥ 1.2, and **size-capped**;
  non-HTTPS URLs are refused.
- **TUF-secured, delta, staged/canary updates with auto-rollback** are the
  roadmap target (see [docs/03](docs/03-secure-updates.md)).

### Network controls (firewall)

- A **public-routability guard** means a poisoned or hijacked threat feed can
  **never** add a rule that blocks RFC-1918, loopback, link-local, CGNAT,
  multicast, or documentation address space.
- All Talos firewall rules are **tagged and reversible** (flush removes exactly
  what Talos added); the offline baseline blocks only ports/IPs with no
  legitimate use on a managed endpoint.

### Quarantine vault

- Stored samples are **defanged** (XOR-transformed) so a quarantined file cannot
  accidentally execute or be re-detected — this is **not** a confidentiality
  control.
- The vault and its blobs are **owner-locked** (Unix `0700`/`0600`; on Windows,
  the MSI install-location ACL).
- Entry IDs are **validated before use in paths**, blocking path-traversal from
  a tampered manifest; manifest writes are **atomic** (write-then-rename).
- Restore and bulk **Delete all** are available in the GUI; *Delete all* is a
  destructive action and requires an explicit two-step confirmation.

### Privacy & telemetry

- The ML telemetry store is **local to the endpoint — nothing is transmitted.**
- It records file paths and hashes, so the database should be treated as
  **sensitive**; deployment must respect the privacy and workplace-monitoring
  mandates in [docs/05-compliance-privacy.md](docs/05-compliance-privacy.md) and
  the telemetry-field assessment in [docs/07](docs/07-telemetry-flow.md).

### Privilege model

Applying firewall/web-protection rules, restoring quarantined files, and
real-time enforcement require **Administrator/root**. The GUI degrades
gracefully and reports when an action needs elevation rather than failing
silently.

---

## Scope, Ethics & Authorization

- Talos is for the **protection of endpoints you are authorized to manage.**
  Its monitoring capabilities are equivalent to workplace monitoring and must
  respect employment law and co-determination requirements (see
  [docs/05-compliance-privacy.md](docs/05-compliance-privacy.md)).
- Do not use this software to surveil systems you do not own or administer.
- Kernel-mode components (Phase 2) carry system-stability risk and are gated
  behind staged rollout for exactly that reason.

---

## Hardening Still on the Roadmap

For transparency, these protections are **designed but not yet shipping** in
Phase 1:

- Windows kernel minifilter + AMSI for true pre-execution blocking
- EV / WHQL / ELAM-anchored PPL code signing
- TUF-secured delta updates with canary rollout and anti-rollback
- Production Ed25519 feed-signing key (replacing the test vector)
- In-browser/per-URL web filtering and ransomware rollback (VSS)
