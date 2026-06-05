# Talos EPP — User Guide

A practical guide to installing and running the Phase 1 app. For the broader
architecture, see [the docs index](../README.md#document-index).

> **Safety & authorization:** only run this on machines you are authorized to
> manage. Use the harmless **EICAR** test file (below) to prove detection works
> — never real malware.

---

## 1. What it does

Talos scans files and flags threats using four layers:

| Layer | What it catches | Verdict |
|---|---|---|
| **Hash signatures** | exact known-bad files (SHA-256) | malicious |
| **YARA rules** | known patterns (EICAR, web shells, malicious PowerShell) | malicious |
| **Static heuristics** | packed **code** sections, process-injection imports, W^X sections — needs **≥2 signals**; Authenticode-signed files are trusted | **suspicious** |
| **Behavioral analysis** | CAPA-style capabilities inferred from a PE's imports & strings, MITRE ATT&CK-tagged (injection, credential access, ransomware, AMSI/ETW bypass, persistence, C2, …); score-gated + signed-file-trusted | **suspicious** |

It also looks **inside ZIP archives**, and can **quarantine** (isolate) detected
files and later **restore** them.

- *Malicious* findings can be quarantined (and are, with `--quarantine`).
- *Suspicious* findings are reported but **never** auto-quarantined (so a
  legitimately packed installer is flagged, not deleted).
- To keep false positives low, the heuristic layer **trusts code-signed
  (Authenticode) binaries** — so signed Microsoft/vendor DLLs are not flagged —
  and only raises *suspicious* when **two or more** independent signals agree.
  Known-bad files are still caught by the hash and YARA layers regardless.
- **Behavioral analysis** is *static* (it reads a file's imports & strings, it
  never executes it) and is likewise signed-file-trusted and score-gated. True
  *runtime* behavioral monitoring (process/file/registry/network telemetry)
  arrives with the Phase-2 kernel sensor.

---

## 2. Get the app

**Option A — download the built binary (Windows):** grab the `talos-installer`
artifact from a green CI run (GitHub → **Actions** → latest run on `main` →
**Artifacts**). It contains `talos.exe` and `talos-agent.msi`.

**Option B — build it yourself:**
```bash
cargo build --release                                   # current platform
cargo build --release -p scanner-cli \
  --target x86_64-pc-windows-msvc                        # Windows .exe
```
The binary is `target/release/talos` (`.exe` on Windows).

**Enterprise install (MSI, silent):**
```bat
msiexec /i talos-agent.msi /qn /norestart TENANT_TOKEN=... UPDATE_RING=delayed
```
See [deployment](04-deployment-distribution.md) for GPO/Intune/SCCM.

---

## 3. Run it

### Desktop GUI (recommended)
Double-click **`talos-gui.exe`** to open the security console:

- **Dashboard** — a protection-status hero plus a **Security Advisor** that
  suggests one-click actions (run a scan, update signatures, review quarantine)
  based on your real state.
- **Protection** — a module grid: **Active** layers (antimalware, YARA,
  heuristics, archive inspection, quarantine, updates) with on/off toggles, and
  **Roadmap** modules (real-time, web, firewall, ransomware) clearly labeled.
- **Scan** — Quick / Full / Custom with live progress and per-detection results.
- **Quarantine** — isolate / restore / delete.
- **Activity** — a persisted log of scans, updates and quarantine actions.
- **Settings** — *real* engine controls: file-size cap, **exclusions** (trusted
  files/folders the scanner skips), archive / heuristics / symlink toggles, and a
  scheduled-scan preference. Saved to `config.json` and applied to the next scan.

### Interactive console app
Run with **no arguments** (or double-click `talos.exe`):
```bash
talos
```
You get a menu: **Quick Scan**, **Full Scan**, **Custom Scan**, **Quarantine**
manager, **Update** (fetch the latest signatures), **About**, and **Help**.

### Command line
```bash
talos selftest                      # verify detection works (EICAR)
talos scan --profile quick          # scan high-risk folders
talos scan --profile full           # scan the whole system
talos scan /path/to/dir             # scan a specific path
talos scan /path --quarantine       # scan and isolate threats
talos scan /path --json             # NDJSON output (one report/line)
talos scan /path --show-clean       # also list clean files
talos update                        # fetch the latest signatures (see §6)
```

### Quarantine management
```bash
talos quarantine list               # show isolated items + ids
talos quarantine restore <id>       # put a file back (false positive)
talos quarantine restore <id> --to /some/dir/file
talos quarantine purge <id>         # delete one item permanently
talos quarantine purge --all        # empty the vault
```

---

## 4. Useful options (`scan`)

| Flag | Meaning | Default |
|---|---|---|
| `--profile quick\|full` | scan a built-in set of locations | — |
| `--quarantine` | isolate detected (malicious) files | off |
| `--json` | NDJSON output (telemetry shape, see [docs/07](07-telemetry-flow.md)) | off |
| `--show-clean` | also print clean/skipped files | off |
| `--max-size-mib <N>` | cap in-memory inspection size (large files are hash-only) | 128 |
| `--threads <N>` | worker threads for directory scans (`0` = all CPU cores) | 0 |
| `--follow-symlinks` | follow symlinks while walking | off |
| `--no-yara` | hash-only (skip YARA) | off |
| `--no-behavior` | skip the static behavioral capability layer | off |
| `--hashes <file>` / `--rules <dir>` | merge extra signatures on top of the built-in baseline + local store | — |

**Exit codes:** `0` clean · `1` threat detected · `2` error.

---

## 5. Where things live

The app is **self-contained**: a baseline of signatures is **embedded in the
binary**, so it detects threats out of the box with no extra files. Updates land
in a writable per-machine store that the engine merges on top of the baseline.

| What | Location |
|---|---|
| Built-in baseline (hash DB + YARA) | embedded in `talos.exe` / `talos-gui.exe` |
| Updatable definitions store | `%PROGRAMDATA%\Talos EPP\signatures` (Windows) or `~/.local/share/talos-epp/signatures` — `hashes/*.hashdb` + `yara/*.yar` |
| Quarantine vault | `%PROGRAMDATA%\Talos EPP\quarantine` (Windows) or `~/.local/share/talos-epp/quarantine` |
| GUI settings | `…\Talos EPP\config.json` (file-size cap, exclusions, toggles, schedule) |
| Activity log | `…\Talos EPP\activity.jsonl` (scans, updates, quarantine actions) |

Override the quarantine location with `scan --quarantine-dir <dir>` or
`quarantine --dir <dir>`. Add extra signatures ad-hoc with `scan --hashes <file>`
/ `scan --rules <dir>` (merged on top of the baseline + store).

---

## 6. Updating signatures

A baseline ships embedded in the app. To **broaden detection**, `talos update`
fetches reputable, openly-licensed feeds into the local store (§5), and the
engine reloads them immediately. The GUI exposes the same thing as the
**Update** button on the dashboard; the interactive console offers it as menu
item **[5]**.

```bash
talos update                          # abuse.ch hashes + open YARA rules (defaults)
talos update --no-abuse-ch            # skip the abuse.ch hash feed
talos update --no-yara-feeds          # skip the open YARA rule feeds
talos update --clamav-url <url>       # also pull a ClamAV .hsb SHA-256 list (opt-in)
```

### Sources

| Feed | Content | License | Default |
|---|---|---|---|
| **abuse.ch MalwareBazaar** | recent malware **SHA-256** hashes | CC0 (public domain) | **on** |
| **abuse.ch ThreatFox** | IOC **SHA-256** hashes (CSV export) | CC0 (public domain) | **on** (needs `TALOS_ABUSE_KEY`) |
| **Open YARA** (Neo23x0/signature-base) | curated `*.yar` rules (web shells, offensive tooling, APT/Cobalt Strike, exploits, AMSI tampering) | DRL 1.1 | **on** |
| **ClamAV** | `.hsb` **SHA-256** hash signatures (MD5 lines skipped) | GPL-2.0 | off (opt-in) |

Talos ingests only **SHA-256** hash entries (the engine is SHA-256-keyed). YARA
rule files our engine can't compile (unsupported modules/features) are **skipped
gracefully** — one bad rule never breaks the set. Downloads use the system
`curl`, so there's no in-process TLS to maintain. Full attribution and license
terms are in [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md).

### Tuning via environment variables

| Variable | Effect |
|---|---|
| `TALOS_ABUSE_KEY` | abuse.ch Auth-Key (sent as the `Auth-Key` header) for endpoints that require one |
| `TALOS_YARA_URLS` | comma-separated list of YARA URLs to fetch instead of the defaults |
| `TALOS_CLAMAV_URL` | a ClamAV `.hsb` SHA-256 list URL (same as `--clamav-url`) |

> **Production roadmap.** The hardened path is the signed, staged **delta + TUF**
> channel (48h baseline + emergency push) described in
> [docs/03](03-secure-updates.md). `talos update` is the Phase-1 fetcher that
> proves the multi-source ingestion end-to-end.

---

## 7. Quick smoke test (EICAR)

```bash
# Create the harmless EICAR test file and scan it — it must be detected.
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com
talos scan eicar.com         # -> [CRIT] ... Eicar.Test.File ; exit code 1
talos selftest               # -> SELFTEST PASSED
```

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `provide a PATH or --profile` | give a path or `--profile quick\|full` |
| `talos update` says `curl unavailable` | install `curl` (built into Windows 10+/most Linux), or check connectivity |
| `abuse.ch: download failed` | the endpoint may need a free key — set `TALOS_ABUSE_KEY`, or run `talos update --no-abuse-ch` |
| `YARA …: not a rule file` / a feed is skipped | the source changed or won't compile; it's skipped safely — other feeds still apply |
| Quarantine `list` is empty after `--quarantine-dir` | pass the same `--dir` to `quarantine list` |
| Large file shows `content_inspected: false` | it exceeded `--max-size-mib`; it was hash-checked only |
| Windows "Unknown Publisher" warning | expected until the production EV signature is applied ([docs/04](04-deployment-distribution.md)) |
