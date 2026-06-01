# Sentinel EPP — Enterprise Endpoint Protection Platform

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

---

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
