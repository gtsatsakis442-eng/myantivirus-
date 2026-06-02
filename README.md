# Talos EPP — Enterprise Endpoint Protection Platform

> **Status:** Architecture & Roadmap (Design Phase — no production code yet)
> **Target:** Standalone, EV-signed Windows executable + WHQL-signed kernel sensor
> **Audience:** Engineering, Security Research, Product, Compliance

This repository contains the technical architecture and delivery roadmap for an
enterprise-grade **Endpoint Protection Platform (EPP)** with integrated **EDR**
(Endpoint Detection & Response) capabilities, modeled on the design principles
of best-in-class solutions (CrowdStrike Falcon, SentinelOne Singularity,
Microsoft Defender for Endpoint).

---

## ⚠️ Scope, Ethics & Authorization

This is a **defensive security product**. Everything here is intended for the
*protection* of endpoints owned and operated by the deploying organization.

- The behavioral and telemetry capabilities described (process monitoring, script
  inspection, network visibility) are powerful and are equivalent to
  **workplace monitoring**. Deployment must respect employment law, works-council
  / co-determination requirements (e.g., German *Betriebsrat*), and the privacy
  mandates covered in [docs/05-compliance-privacy.md](docs/05-compliance-privacy.md).
- Kernel-mode code carries system-stability risk. The architecture deliberately
  minimizes kernel logic and mandates staged rollout for exactly this reason
  (see the "CrowdStrike lesson" in [docs/03](docs/03-secure-updates.md)).
- Ship only on machines you are authorized to manage.

---

## Executive Summary

| Pillar | Approach (one-liner) |
|---|---|
| **Core engine** | Thin **kernel sensor** (minifilter + kernel callbacks + ETW-TI) for unbypassable visibility and pre-execution blocking; **heavy logic in user mode** to contain blast radius. Agent runs as **PPL** anchored by an **ELAM** driver. |
| **Detection** | A 5-stage funnel: reputation cache → signatures (hash/YARA) → static ML → behavioral engine (MITRE ATT&CK) → cloud verdict fusion. Behavior-first design catches zero-days. |
| **Updates** | **TUF-secured**, delta (content-defined chunking + Merkle) content channel on a 48 h cadence with an out-of-band emergency channel; **staged/canary rollout** with auto-rollback. |
| **Distribution** | EV-signed bootstrapper `.exe` wrapping an MSI; **WHQL/attestation-signed** driver; silent install via GPO/Intune/SCCM; auto-enroll via tenant token. |
| **Compliance** | Data minimization, pseudonymization, EU data residency, configurable telemetry, DPIA, ISO 27001 / SOC 2 alignment. |

---

## Document Index

| # | Document | Covers |
|---|---|---|
| 01 | [Core Architecture](docs/01-core-architecture.md) | Kernel vs. user mode, minifilter, callbacks, ETW/AMSI, PPL/ELAM, performance & latency budgets, IPC, self-protection |
| 02 | [Detection Engine](docs/02-detection-engine.md) | Signature, heuristic/static, behavioral, AI/ML, cloud reputation, verdict fusion, FP management, ransomware rollback |
| 03 | [Secure Update System](docs/03-secure-updates.md) | Delta updates, 48 h cadence, TUF, in-toto, HSM signing, staged rollout, anti-rollback, supply-chain threat model |
| 04 | [Deployment & Distribution](docs/04-deployment-distribution.md) | Authenticode/EV signing, WHQL & attestation, ELAM entitlement, MSI/bootstrapper, silent AD/Intune/SCCM deployment, Defender coexistence |
| 05 | [Compliance & Privacy](docs/05-compliance-privacy.md) | GDPR lawful basis, data minimization, residency, DPIA, retention, DSAR, certifications |
| 06 | [Implementation Roadmap](docs/06-implementation-roadmap.md) | Phased plan (MVP → GA → EDR), org structure, tech stack, testing/QA, KPIs, risk register |
| 07 | [Telemetry Flow ⟨FOR REVIEW⟩](docs/07-telemetry-flow.md) | The telemetry record, end-to-end flow, tiers, per-field PII assessment, privacy controls — **pending sign-off** |

---

## Repository Layout

```
.
├── docs/                  Architecture & roadmap (01–07)
├── agent/                 User-mode agent (Rust workspace)
│   ├── scanner-core/      Engine library: hashing, hash-sig DB, YARA, pipeline, quarantine
│   ├── scanner-cli/       `talos` console/CLI agent (scan/quarantine, automation)
│   └── talos-gui/         `talos-gui` desktop GUI app (egui) — dashboard/scan/quarantine
├── signatures/            Seed detection content (hashes + high-fidelity YARA)
├── installer/             WiX MSI + Burn bootstrapper + code-signing simulation
├── kernel/                Phase 2 kernel sensor (placeholder)
├── cloud/  ml/  tools/    Later-phase placeholders
└── .github/workflows/     CI: Linux engine gates + Windows installer + signing sim
```

## Phase 1 — the app (`talos-gui.exe` + `talos.exe`)

Ships as a **desktop GUI** (`talos-gui.exe`, a dark dashboard-style console) and
a headless **CLI agent** (`talos.exe`) — both over the same engine. Three detection layers
today: exact **hash signatures**, **YARA** rules, and **static PE heuristics**
(entropy/packing, process-injection imports, W^X sections — reported as
*suspicious*, never auto-actioned). It also scans **inside ZIP archives**
(zip-bomb-guarded). Detections can be **quarantined** (isolated) and restored.
Directory scans run **in parallel across all CPU cores** (tune with `--threads`)
and report throughput. The ONNX static-ML layer is intentionally deferred until
the file-processing pipeline is hardened (see `ml/`).

📖 **Full usage guide:** [docs/USAGE.md](docs/USAGE.md) — install, commands,
quarantine, troubleshooting.

### Windows — get & run

Two binaries ship on the **Releases → `latest`** page (both self-contained —
signatures are embedded, no extra files needed):

| File | What it is |
|---|---|
| **`talos-gui.exe`** | the **desktop GUI** — a dark, dashboard-style security console. Double-click it. |
| `talos.exe` | the console/CLI agent for automation & scripting |
| `talos-agent.msi` | the enterprise installer (GPO / Intune / SCCM) |

**Download the GUI** (PowerShell; `gh` works for this private repo):
```powershell
gh release download latest --repo gtsatsakis442-eng/myantivirus- --pattern talos-gui.exe
.\talos-gui.exe            # opens the GUI window
```
No `gh`? Use the browser (**Releases → "latest"**) or:
```powershell
Invoke-WebRequest "https://github.com/gtsatsakis442-eng/myantivirus-/releases/download/latest/talos-gui.exe" -OutFile talos-gui.exe
```

**Build it yourself** (PowerShell; needs the Rust toolchain):
```powershell
cargo build --release -p talos-gui     # the GUI  -> target\release\talos-gui.exe
cargo build --release -p scanner-cli   # the CLI  -> target\release\talos.exe
.\target\release\talos.exe selftest    # verify detection (EICAR)
```

**Drive it from the CLI** (Windows or Unix):
```text
talos scan --profile quick         # scan high-risk folders (Downloads, Temp, …)
talos scan C:\Users\me\Downloads   # scan a specific path
talos scan C:\path --quarantine    # scan + isolate detected threats
talos scan C:\path --json          # NDJSON telemetry (see docs/07)
talos quarantine list              # review the vault
talos quarantine restore <id>      # restore a false positive
```
Exit codes: `0` clean · `1` threat detected · `2` error.

> The build is **unsigned**, so Windows SmartScreen shows an "Unknown Publisher"
> prompt (click *More info → Run anyway*) until the EV certificate is applied.

## System-at-a-Glance

```
                          ┌──────────────────────────────────────────────┐
                          │                CLOUD BACKEND                  │
                          │  Reputation │ ML (heavy) │ EDR/Hunting │ Mgmt  │
                          │  TUF content repo │ Telemetry lake │ Console   │
                          └───────────────▲───────────────┬──────────────┘
                                          │ mTLS, pinned   │ signed content
                                          │ telemetry      ▼ (delta + TUF)
┌───────────────────────────── ENDPOINT (Windows) ──────────────────────────────┐
│  USER MODE                                                                     │
│   ┌───────────────┐   ┌──────────────┐   ┌───────────────┐   ┌──────────────┐ │
│   │ Scan Service  │   │ Behavioral   │   │ Update Agent  │   │ AMSI Provider│ │
│   │ (PPL)         │◄─►│ Engine + ML  │   │ (TUF client)  │   │ (scripts)    │ │
│   └──────▲────────┘   └──────▲───────┘   └───────────────┘   └──────────────┘ │
│          │ FltSendMessage / inverted call         ▲ ETW (incl. Threat-Intel)   │
│ ─────────┼───────────────────────────────────────┼─────────────────────────── │
│  KERNEL  │                                        │                            │
│   ┌──────┴─────────┐ ┌───────────────┐ ┌──────────┴───────┐ ┌───────────────┐ │
│   │ Minifilter     │ │ Process/Thread│ │ Registry / Object│ │ WFP callout   │ │
│   │ (file I/O)     │ │ /Image cbacks │ │ callbacks        │ │ (network)     │ │
│   └────────────────┘ └───────────────┘ └──────────────────┘ └───────────────┘ │
│   ┌────────────────┐                                                           │
│   │ ELAM driver    │  → anchors PPL, classifies boot-start drivers             │
│   └────────────────┘                                                           │
└────────────────────────────────────────────────────────────────────────────────┘
```

## Recommended Technology Stack (summary)

| Component | Language / Framework | Rationale |
|---|---|---|
| Kernel sensor (minifilter, callbacks) | **C, KMDF / FltMgr** | Only supported route for kernel; KMDF reduces footguns |
| ELAM driver | **C** | Tiny, strict Microsoft requirements |
| User-mode service & engine | **Rust** (or modern C++20) | Memory safety for the largest attack surface |
| On-device ML inference | **ONNX Runtime** (models trained in Python) | Portable, no Python on endpoint |
| AMSI provider | **C++ (COM)** | Required COM interface |
| Installer | **WiX (MSI + Burn bootstrapper)** | Enterprise/GPO standard |
| Update client | **Rust + go-tuf/rust-tuf** | Secure-update standard |
| Cloud backend | **Go / Rust** services, **Kafka** ingest, object store + columnar lake | Throughput & cost |

See [docs/06-implementation-roadmap.md](docs/06-implementation-roadmap.md) for the
full stack, phased milestones, and KPIs.
