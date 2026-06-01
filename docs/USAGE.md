# Sentinel EPP — User Guide

A practical guide to installing and running the Phase 1 app. For the broader
architecture, see [the docs index](../README.md#document-index).

> **Safety & authorization:** only run this on machines you are authorized to
> manage. Use the harmless **EICAR** test file (below) to prove detection works
> — never real malware.

---

## 1. What it does

Sentinel scans files and flags threats using three layers:

| Layer | What it catches | Verdict |
|---|---|---|
| **Hash signatures** | exact known-bad files (SHA-256) | malicious |
| **YARA rules** | known patterns (EICAR, web shells, malicious PowerShell) | malicious |
| **Static heuristics** | packed/high-entropy PEs, process-injection imports, W^X sections | **suspicious** |

It also looks **inside ZIP archives**, and can **quarantine** (isolate) detected
files and later **restore** them.

- *Malicious* findings can be quarantined (and are, with `--quarantine`).
- *Suspicious* findings are reported but **never** auto-quarantined (so a
  legitimately packed installer is flagged, not deleted).

---

## 2. Get the app

**Option A — download the built binary (Windows):** grab the `sentinel-installer`
artifact from a green CI run (GitHub → **Actions** → latest run on `main` →
**Artifacts**). It contains `sentinel-scan.exe` and `sentinel-agent.msi`.

**Option B — build it yourself:**
```bash
cargo build --release                                   # current platform
cargo build --release -p scanner-cli \
  --target x86_64-pc-windows-msvc                        # Windows .exe
```
The binary is `target/release/sentinel-scan` (`.exe` on Windows).

**Enterprise install (MSI, silent):**
```bat
msiexec /i sentinel-agent.msi /qn /norestart TENANT_TOKEN=... UPDATE_RING=delayed
```
See [deployment](04-deployment-distribution.md) for GPO/Intune/SCCM.

---

## 3. Run it

### Interactive app (easiest)
Run with **no arguments** (or double-click the `.exe`):
```bash
sentinel-scan
```
You get a menu: **Quick Scan**, **Full Scan**, **Custom Scan**, **Quarantine**
manager, **Update info**, **About**, and **Help**.

### Command line
```bash
sentinel-scan selftest                      # verify detection works (EICAR)
sentinel-scan scan --profile quick          # scan high-risk folders
sentinel-scan scan --profile full           # scan the whole system
sentinel-scan scan /path/to/dir             # scan a specific path
sentinel-scan scan /path --quarantine       # scan and isolate threats
sentinel-scan scan /path --json             # NDJSON output (one report/line)
sentinel-scan scan /path --show-clean       # also list clean files
```

### Quarantine management
```bash
sentinel-scan quarantine list               # show isolated items + ids
sentinel-scan quarantine restore <id>       # put a file back (false positive)
sentinel-scan quarantine restore <id> --to /some/dir/file
sentinel-scan quarantine purge <id>         # delete one item permanently
sentinel-scan quarantine purge --all        # empty the vault
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
| `--follow-symlinks` | follow symlinks while walking | off |
| `--no-yara` | hash-only (skip YARA) | off |
| `--hashes <file>` / `--rules <dir>` | override signature locations | install dir |

**Exit codes:** `0` clean · `1` threat detected · `2` error.

---

## 5. Where things live

| What | Location |
|---|---|
| Signatures (hash DB + YARA) | next to the exe under `signatures/`, else `./signatures` |
| Quarantine vault | `%PROGRAMDATA%\Sentinel EPP\quarantine` (Windows) or `~/.local/share/sentinel-epp/quarantine` |

Override the quarantine location with `scan --quarantine-dir <dir>` or
`quarantine --dir <dir>`.

---

## 6. Updating signatures

In this phase, signatures ship with the app. Production updates flow over the
secure, staged channel (delta + TUF integrity, 48h baseline + emergency push) —
see [docs/03](03-secure-updates.md). Run `sentinel-scan update` for a summary.

---

## 7. Quick smoke test (EICAR)

```bash
# Create the harmless EICAR test file and scan it — it must be detected.
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com
sentinel-scan scan eicar.com         # -> [CRIT] ... Eicar.Test.File ; exit code 1
sentinel-scan selftest               # -> SELFTEST PASSED
```

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `loading hash database ... No such file` | run from the install dir, or pass `--hashes`/`--rules` |
| `provide a PATH or --profile` | give a path or `--profile quick\|full` |
| Quarantine `list` is empty after `--quarantine-dir` | pass the same `--dir` to `quarantine list` |
| Large file shows `content_inspected: false` | it exceeded `--max-size-mib`; it was hash-checked only |
| Windows "Unknown Publisher" warning | expected until the production EV signature is applied ([docs/04](04-deployment-distribution.md)) |
