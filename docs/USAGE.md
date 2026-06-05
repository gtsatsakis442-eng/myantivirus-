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
- **Protection** — a module grid with on/off toggles, including a **Real-time
  Protection** switch: on-access **scan + instant auto-quarantine** of new/changed
  files (true *blocking* on Linux via `talos watch --enforce`; see §6.5). The
  Windows kernel minifilter, web, firewall and ransomware rollback are **Roadmap**.
- **Scan** — Quick / Full / Custom with live progress and per-detection results.
- **Quarantine** — isolate / restore / delete.
- **Activity** — a persisted log of scans, updates, real-time hits, quarantine.
- **Threat Intel** — paste a SHA-256 to look it up against a free online malware
  database (VirusTotal / MalwareBazaar). Only the hash is sent, never the file.
- **Settings** — *real* engine controls: file-size cap, **exclusions** (trusted
  files/folders the scanner skips), archive / heuristics / **behavior** / symlink
  toggles, scheduled-scan preference. Saved to `config.json`, applied next scan.

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
talos scan /path --no-behavior      # skip the behavioral capability layer
talos update                        # fetch the latest signatures (see §6)
talos lookup <sha256|file>          # threat-intel lookup (free API; see §9)
talos watch [folders...]            # real-time: scan + auto-quarantine on access
talos watch --enforce               # real-time BLOCKING via fanotify (Linux, root)
talos scan /path --json > scan.log  # export a scan log, then …
talos ingest scan.log               # … grow the signature DB from it (see §10)
talos guard [folders...]            # ransomware guard: canary decoys + alerts
sudo talos firewall sync            # drop known C2 IPs via the OS firewall
talos firewall block <ip> / flush   # block one IP / remove Talos rules
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
| `TALOS_ABUSE_KEY` | abuse.ch Auth-Key (MalwareBazaar/ThreatFox feeds **and** `talos lookup`) |
| `TALOS_VT_KEY` | VirusTotal API key (`talos lookup`) |
| `TALOS_MALSHARE_KEY` | MalShare API key (`talos lookup`) |
| `TALOS_OTX_KEY` | AlienVault OTX API key (`talos lookup`) |
| `TALOS_HYBRID_KEY` | Hybrid Analysis (Falcon Sandbox) API key (`talos lookup`) |
| `TALOS_YARA_URLS` | comma-separated list of YARA URLs to fetch instead of the defaults |
| `TALOS_CLAMAV_URL` | a ClamAV `.hsb` SHA-256 list URL (same as `--clamav-url`) |

> **Production roadmap.** The hardened path is the signed, staged **delta + TUF**
> channel (48h baseline + emergency push) described in
> [docs/03](03-secure-updates.md). `talos update` is the Phase-1 fetcher that
> proves the multi-source ingestion end-to-end.

---

## 6.5. Threat-intel lookups & real-time monitoring

**Threat intelligence** (`talos lookup`, or the GUI **Threat Intel** view) checks
a file's **SHA-256** against free online malware databases and reports what's
known (family, tags, first-seen, AV-detection ratio, sandbox verdict, OTX
pulses). **Only the hash is sent — file contents never leave the machine.** It
queries **every provider you have a free key for** and aggregates the results:

```bash
export TALOS_VT_KEY=...        # virustotal.com
export TALOS_ABUSE_KEY=...     # auth.abuse.ch — MalwareBazaar
export TALOS_MALSHARE_KEY=...  # malshare.com
export TALOS_OTX_KEY=...       # otx.alienvault.com
export TALOS_HYBRID_KEY=...    # hybrid-analysis.com (Falcon Sandbox)
talos lookup C:\Users\me\Downloads\suspicious.exe   # hashes the file, then looks up
talos lookup 275a021b…fd0f                           # or pass a SHA-256 directly
```

**Real-time protection** comes in two backends, chosen by what each OS lets a
user-mode process do — the same split the major products use:

| Backend | Platform | What it does |
|---|---|---|
| **Monitoring + auto-quarantine** | all (GUI toggle, `talos watch`) | reacts to file create/modify, scans, and **instantly quarantines** a malicious file on access |
| **Enforcing (blocking)** | **Linux** (`talos watch --enforce`, needs root) | intercepts every **open/exec** via **fanotify** `FAN_OPEN_PERM`/`FAN_OPEN_EXEC_PERM`, scans, and **denies** access to malicious files in real time — the mechanism ClamAV's `clamonacc` uses |

True *pre-execution blocking on Windows* needs a kernel file-system **minifilter**
(+ **AMSI** for scripts/memory) — a signed-driver effort that's Phase 2 (see
[docs/01](01-core-architecture.md)). Until then, Windows uses the monitoring +
instant-auto-quarantine backend.

```bash
talos watch                       # monitor + auto-quarantine (Quick-Scan folders)
talos watch C:\Users\me\Downloads # monitor specific folders (Ctrl-C to stop)
sudo talos watch --enforce /home  # Linux: BLOCK malicious open/exec in real time
```

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

---

## 10. Growing the signature database (feedback loop)

Talos ships its **own** first-party database (`signatures/hashes/talos.hashdb`,
embedded in the binaries) on top of the external feeds. You make it better by
feeding back **scan logs** — and turning the confirmed detections into
signatures:

```bash
talos scan C:\Users\me\Downloads --json > scan.log   # export an NDJSON log
talos ingest scan.log                                # fold its hashes into your DB
talos ingest scan.log --include-suspicious           # also keep heuristic/behaviour hits
talos ingest scan.log --into C:\path\custom.hashdb   # write to a specific DB
```

`ingest` extracts the **SHA-256** of every **malicious** report (only — by
default), labels it by its detection name, de-duplicates against what you
already have, and appends to your local store so the engine picks it up on the
next scan. **Only the hash + label are taken — file paths in the log are
ignored**, so a shared log leaks no local paths.

**To improve the shipped database for everyone:** send the `scan.log` upstream.
Confirmed-malicious hashes are vetted and added to `signatures/hashes/talos.hashdb`
in the repo, then published in the next release. (A hash signature is an
exact-match fingerprint and permanent, so only *confirmed* malware is added —
generalising detections are written as YARA rules instead.)

---

## 11. Ransomware guard & firewall (user-mode)

These are the **user-mode** forms of two roadmap modules — real and useful, but
not the kernel versions (a kernel I/O filter + Volume Shadow Copy rollback, and
a WFP/Netfilter packet filter, remain Phase 2).

**Ransomware guard** plants **canary decoy files** in protected folders and
raises the alarm the instant one is **encrypted or deleted** — a strong
mass-encryption signal. It runs automatically while **Real-time Protection** is
on (GUI), or standalone:

```bash
talos guard                       # protect the Quick-Scan folders (Ctrl-C to stop)
talos guard C:\Users\me\Documents # protect specific folders
```

**Firewall** drops traffic to known **botnet C2 IPs** by adding rules to the
**OS firewall** (`netsh advfirewall` on Windows, `iptables` on Linux) — Talos
orchestrates the platform firewall rather than shipping its own packet filter.
The blocklist is the free **abuse.ch Feodo Tracker** C2 IP list. Needs
Administrator / root:

```bash
sudo talos firewall sync          # fetch Feodo Tracker C2 IPs → OS firewall drop rules
talos firewall block 185.0.0.1    # block one IPv4 address
talos firewall flush              # remove all Talos-created rules
```
