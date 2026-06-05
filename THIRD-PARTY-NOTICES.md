# Third-Party Notices

Talos EPP bundles a small built-in baseline of detection content and can
**optionally fetch** additional, openly-licensed signatures at runtime via
`talos update` (CLI) or the **Update** button in the GUI. This document records
the sources and their licenses so downstream users can honor the original terms.

> Fetched content is downloaded **to the end user's machine** into the local
> definitions store (`%PROGRAMDATA%\Talos EPP\signatures` on Windows,
> `~/.local/share/talos-epp/signatures` on Linux). It is **not redistributed**
> by this repository. Each source is fetched at the operator's request.

---

## 1. Signature & Detection Content (feeds)

### abuse.ch — MalwareBazaar (malware hashes)
- **What we use:** recent malware sample **SHA-256** hashes.
- **Endpoint (default):** `https://bazaar.abuse.ch/export/txt/sha256/recent/`
- **License:** **CC0 1.0 Universal** (public domain dedication). abuse.ch
  publishes MalwareBazaar data under CC0; no attribution is legally required,
  but we credit abuse.ch here as a courtesy and to aid auditability.
- **Notes:** some abuse.ch endpoints require a free **Auth-Key**. Provide one via
  the `TALOS_ABUSE_KEY` environment variable; Talos sends it as an `Auth-Key`
  request header.
- **Project:** https://abuse.ch · https://bazaar.abuse.ch

### abuse.ch — ThreatFox (IOC hashes)
- **What we use:** IOC **SHA-256** hashes from the CSV export.
- **Endpoint (default):** `https://threatfox.abuse.ch/export/csv/sha256/recent/`
- **License:** **CC0 1.0 Universal** (public domain dedication).
- **Notes:** ThreatFox requires a free abuse.ch **Auth-Key**; provide it via
  `TALOS_ABUSE_KEY` (sent as the `Auth-Key` header). Disabled in effect until a
  key is present.
- **Project:** https://threatfox.abuse.ch

### abuse.ch — Feodo Tracker (C2 IP blocklist)
- **What we use:** botnet **command-and-control IP** addresses, applied as
  OS-firewall drop rules by `talos firewall sync`.
- **Endpoint (default):** `https://feodotracker.abuse.ch/downloads/ipblocklist.txt`
- **License:** **CC0 1.0 Universal** (public domain dedication).
- **Project:** https://feodotracker.abuse.ch

### Neo23x0 — `signature-base` (YARA rules)
- **What we use:** a curated subset of `*.yar` rule files (web shells, offensive
  tooling, APT/Cobalt Strike, exploitation, AMSI-tampering, …).
- **License:** **Detection Rule License (DRL) 1.1** unless a stricter per-rule
  license is stated in the rule's `meta`. The DRL permits use, modification, and
  redistribution provided the license and attribution are preserved.
- **Attribution:** rules are authored by Florian Roth and contributors. Original
  author/reference metadata inside each rule is preserved as fetched.
- **Project:** https://github.com/Neo23x0/signature-base
- **License text:** https://github.com/Neo23x0/signature-base/blob/master/LICENSE

### ClamAV — hash signatures *(opt-in, bring-your-own URL)*
- **What we use:** `.hsb` **SHA-256** hash signatures (`<hash>:<size>:<name>`).
  MD5 (`.hdb`) lines are intentionally skipped — the engine is SHA-256-keyed.
- **How to enable:** `talos update --clamav-url <url-to-.hsb-list>` (or set
  `TALOS_CLAMAV_URL`). Disabled by default.
- **License:** **GPL-2.0**. ClamAV signature databases are distributed by Cisco
  Talos under the GPL; redistribution carries GPL obligations, which is why this
  feed is **opt-in** and never bundled into the Talos EPP binaries.
- **Project:** https://www.clamav.net · https://docs.clamav.net

> **Operator responsibility.** Mixing signature sets with differing licenses
> (e.g. GPL ClamAV data) into a redistributed product can create license
> obligations. Talos keeps GPL content **opt-in and local** for this reason. If
> you redistribute a populated definitions store, you are responsible for
> complying with each source's license.

---

## 2. Built-in baseline content

The `signatures/` directory in this repository (embedded into the binaries)
contains only **original, first-party** content written for Talos EPP:

- `signatures/hashes/baseline.hashdb` — the EICAR test-file SHA-256.
- `signatures/yara/*.yar` — first-party rules (EICAR, web shells, malicious
  PowerShell) authored for this project.

The **EICAR** test string itself is an industry-standard, intentionally harmless
anti-malware test vector published by the European Institute for Computer
Antivirus Research; it is not malware.

---

## 3. Software dependencies

Talos EPP is built in Rust. Its dependencies are distributed under permissive
open-source licenses (predominantly **MIT** and **Apache-2.0**). Notable
components:

- **`yara-x`** — VirusTotal's pure-Rust YARA engine (the YARA scanning layer).
- **`goblin`** — PE/object parsing for static heuristics & behavioral analysis.
- **`notify`** — cross-platform filesystem watching (real-time on-access monitor).
- **`nix`** (Linux only) — safe `fanotify` bindings for blocking on-access
  enforcement (`talos watch --enforce`).
- **`eframe` / `egui`** — the GUI toolkit (`talos-gui`).
- **`rayon`**, **`walkdir`**, **`zip`**, **`sha2` / `sha1` / `md-5`**,
  **`clap`**, **`serde` / `serde_json`**, **`tempfile`**.

For the authoritative, version-pinned license list, run
[`cargo license`](https://github.com/onur/cargo-license) or
[`cargo about`](https://github.com/EmbarkStudios/cargo-about) against
`Cargo.lock`. Each crate's license is declared in its own metadata.

---

## 4. Threat-intelligence enrichment APIs (optional)

`talos lookup` / the GUI **Threat Intel** view query a free online malware
database **with a SHA-256 hash only** (no file content is uploaded). These are
external services used at the operator's request with the operator's own free
API key; Talos neither bundles nor redistributes their data:

- **VirusTotal** (`x-apikey`, `TALOS_VT_KEY`) — https://www.virustotal.com —
  subject to the VirusTotal Terms of Service / API usage policy.
- **abuse.ch MalwareBazaar** (`Auth-Key`, `TALOS_ABUSE_KEY`) — CC0 data —
  https://bazaar.abuse.ch/api/
- **MalShare** (`api_key`, `TALOS_MALSHARE_KEY`) — https://malshare.com — free
  community service; respect its API terms.
- **AlienVault OTX / LevelBlue** (`X-OTX-API-KEY`, `TALOS_OTX_KEY`) —
  https://otx.alienvault.com — Open Threat Exchange API terms.
- **Hybrid Analysis** (Falcon Sandbox) (`api-key`, `TALOS_HYBRID_KEY`) —
  https://www.hybrid-analysis.com — CrowdStrike Falcon Sandbox API terms.

Respect each provider's rate limits and terms when using these lookups.

*This product is for authorized, defensive use only. See the repository README
and `docs/05-compliance-privacy.md` for scope, ethics, and authorization.*
