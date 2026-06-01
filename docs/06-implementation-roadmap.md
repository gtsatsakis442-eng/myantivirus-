# 06 — Implementation Roadmap

> A phased plan from empty repo to enterprise GA, with the long-lead items
> (Microsoft ELAM/PPL entitlement, WHQL) started early.

## 1. Guiding sequencing principles
1. **Start the Microsoft-gated items first** — EV cert issuance, Partner Center
   onboarding, and especially **ELAM/PPL anti-malware entitlement** have long,
   external lead times. Begin in Phase 0.
2. **User-mode first, kernel later** — prove the detection engine in user mode
   before taking on kernel risk; it de-risks the schedule and the BSOD surface.
3. **Cloud reputation early** — gives real protection before the local content
   pipeline is mature, and covers the gap between 48 h syncs.
4. **Every detection-content capability ships with its rollout/rollback rails**
   (the CrowdStrike lesson) — not as an afterthought.

## 2. Phased plan

### Phase 0 — Foundations & long-lead items (Months 0–2)
- Procure **EV code-signing cert** (HSM-backed); enroll in **Partner Center**.
- **Initiate ELAM/PPL anti-malware entitlement** with Microsoft (long pole).
- Stand up CI/CD with **reproducible builds**, **SBOM**, **in-toto** scaffolding.
- Request the **minifilter altitude** allocation.
- Threat-model the whole system; finalize tech-stack decisions (§4).
- **Exit:** signing identity ready; entitlement in flight; secure pipeline skeleton.

### Phase 1 — User-mode MVP engine (Months 2–5)
- User-mode **on-demand scanner**: file walk → L1 signatures (hash + YARA) +
  L2 static heuristics; quarantine vault.
- **On-device static ML** (EMBER-style) via ONNX.
- **Cloud reputation** service + local cache (L0/L4).
- Basic **management console** + agent check-in + EV-signed **MSI/bootstrapper**.
- **Exit:** detects known + some unknown malware on-demand; deployable MSI;
  measurable detection/FP rates on test corpora.

### Phase 2 — Real-time kernel sensor (Months 5–9)
- **Minifilter** for real-time file protection (scan-on-access, kernel verdict
  cache, comms port).
- **Process/thread/image + registry + object** callbacks → tamper protection &
  credential-theft defense.
- **ELAM driver** + **PPL** launch (assuming entitlement landed).
- **AMSI provider** (fileless/script) + key **ETW** consumers (incl. Threat-Intel).
- **Attestation-sign** the driver; pursue **WHQL** in parallel.
- **Exit:** real-time prevention; agent self-protects; passes Driver Verifier/SDV
  and HLK subset; Defender coexistence via WSC.

### Phase 3 — Behavioral engine + EDR (Months 9–14)
- **Process-lineage graph** + **MITRE ATT&CK** behavioral detections; behavioral
  ML; **command-line NLP** classifier.
- **Ransomware** canary + entropy detection + **rollback** (journaling/VSS).
- **EDR**: telemetry pipeline to the lake, alerts, **response actions**
  (isolate, kill-tree, remediate), threat hunting / retro-hunt.
- **Exit:** zero-day behavioral coverage; EDR investigation/response loop.

### Phase 4 — Secure update system at scale (Months 12–16, overlaps Ph.3)
- **TUF** content repo (offline root ceremony, threshold keys) + CDN.
- **Delta** updates (content-defined chunking + Merkle) on the **48 h** cadence
  + **out-of-band emergency** channel.
- **Staged/canary rollout** with health gates + **auto-rollback**; update rings.
- **Exit:** efficient, supply-chain-hardened content delivery in production.

### Phase 5 — Enterprise hardening & GA (Months 16–20)
- **Full WHQL** logo; scale/perf hardening to latency budgets ([docs/01 §6](docs/01-core-architecture.md)).
- **Compliance**: ISO 27001 + SOC 2 Type II audits; EU data residency; DPIA pack.
- **Deployment** polish: Intune/SCCM/GPO packages, ADMX, `.mst`, tamper-proof
  uninstall, coverage reconciliation.
- **Exit → GA.**

### Phase 6 — Continuous (ongoing)
- Threat-research signature/rule/model cadence; **MLOps** retraining; red-team &
  external pen-test; AMTSO/third-party efficacy testing (AV-TEST, AV-Comparatives,
  MITRE ATT&CK Evaluations); bug-bounty.

## 3. Critical path & dependencies
```
EV cert ─► Partner Center ─► ELAM/PPL entitlement ───────────────► PPL service
   │                              (LONG POLE)                          ▲
   └─► driver signing ─► attestation ─► WHQL                           │
Phase1 UM engine ─► Phase2 kernel sensor ───────────────────────────────┘
Cloud reputation (early) ─► TUF/delta (Phase4) ─► staged rollout
```
**Watch items:** ELAM/PPL approval and WHQL are external/Microsoft-gated — the
schedule's biggest risk. Start in Phase 0; have a non-PPL fallback for early
pilots.

## 4. Technology stack (decisions)

| Layer | Choice | Notes |
|---|---|---|
| Kernel sensor | **C + KMDF / FltMgr** | Only supported path; KMDF over WDM |
| ELAM | **C** | Minimal; strict MS requirements |
| User-mode service/engine | **Rust** (fallback C++20) | Memory safety on the biggest attack surface |
| AMSI provider | **C++ (COM)** | Required interface |
| ML training / inference | **Python (train) → ONNX Runtime (infer)** | No Python on endpoint |
| Pattern matching | **YARA + Aho-Corasick/Hyperscan-style** | Multi-pattern in one pass |
| Installer | **WiX (MSI + Burn `.exe`)** | Enterprise/GPO standard |
| Update client | **Rust + rust-tuf/go-tuf** | Secure-update standard |
| Cloud services | **Go/Rust**, **Kafka** ingest, **object store + columnar lake**, K8s | Throughput/cost |
| Crypto/keys | **HSM (FIPS 140-3)**, Sigstore-style tooling | Supply-chain integrity |

## 5. Team / org (lean → scaled)
- **Kernel/driver** engineers (Windows internals) — small, senior.
- **Detection engine / ML** engineers + **Threat Research** analysts (author
  sigs/rules, run the content lifecycle).
- **Cloud/backend** + **SRE**.
- **Installer/deployment/QA** incl. **driver QA** (Verifier/HLK).
- **Security/compliance** (product security, DPO/privacy, audits).
- **SOC/MDR** (optional managed-service tier).

## 6. Testing & QA gates
- **Driver:** Driver Verifier (all flags), Static Driver Verifier, CodeQL,
  comms-port fuzzing, HLK — **zero tolerance** for kernel faults.
- **Detection:** detection-rate gate on malware corpus + **FP gate on a large
  clean corpus**, run on every content release.
- **Performance:** automated benchmarks against the [docs/01 §6](docs/01-core-architecture.md)
  latency/boot/CPU budgets; regression gates.
- **Update system:** chaos tests for interrupted/rolled-back/corrupted updates;
  TUF key-compromise tabletop.
- **EICAR** + AMTSO test resources for safe end-to-end validation.
- **External:** AV-TEST / AV-Comparatives / MITRE ATT&CK Evaluations; annual
  pen-test; bug bounty.

## 7. Success metrics (KPIs)
| Category | KPI | Target (illustrative) |
|---|---|---|
| Efficacy | Detection rate (known/zero-day) | ≥ industry-leading on AV-Comparatives |
| Efficacy | False-positive rate | ≤ best-in-class clean-set FP |
| Performance | Added file-open latency (cached) | < 50 µs |
| Performance | Boot impact / CPU at idle | negligible / < a few % |
| Reliability | Agent crash / **BSOD** rate | ~0 (BSOD = Sev-1) |
| Ops | Mean time to ship emergency signature | minutes (OOB channel) |
| Ops | Content auto-rollback success | 100% within ring SLA |
| Trust | WHQL, ISO 27001, SOC 2 Type II | achieved before GA |

## 8. Risk register (top items)
| Risk | Impact | Mitigation |
|---|---|---|
| ELAM/PPL entitlement delay | Blocks tamper-resistance/ETW-TI | Start Phase 0; non-PPL pilot fallback |
| Kernel bug → fleet BSOD | Catastrophic (CrowdStrike-class) | Thin kernel, Verifier/SDV/HLK, staged content, watchdog/safe-mode |
| Bad content → mass FP | Outage-level customer impact | Clean-corpus gate, canary rings, auto-rollback, cloud fast-flip |
| Supply-chain compromise | Trojaned updates | TUF + in-toto + HSM + reproducible builds |
| Privacy non-compliance (EU) | Legal/sales blocker | Privacy-by-design ([docs/05](docs/05-compliance-privacy.md)), residency, DPIA pack |
| Adversarial ML evasion | Missed detections | Ensembles, adversarial training, behavior-first defense in depth |
| Performance regressions | Uninstalls | Latency budgets + automated perf gates |

## 9. Immediate next actions (this repo)
1. Ratify tech-stack and altitude/entitlement decisions ([docs/01 §9](docs/01-core-architecture.md)).
2. Kick off EV cert + Partner Center + **ELAM/PPL** entitlement (Phase 0).
3. Scaffold the monorepo: `kernel/` (minifilter, elam), `agent/` (service,
   engine, amsi, updater), `installer/` (wix), `cloud/`, `ml/`, `tools/`, with
   the CI/in-toto/SBOM pipeline.
4. Build the **Phase 1 user-mode MVP** (signatures + static ML + reputation +
   MSI) as the first running milestone.
