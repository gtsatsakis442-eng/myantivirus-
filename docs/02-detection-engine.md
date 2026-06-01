# 02 — Detection Engine

> Multi-layered, defense-in-depth detection. No single technique is trusted;
> verdicts are **fused**. Behavior-first design is what catches zero-days.

## 1. The detection funnel

Each layer is cheaper and broader than the next is deeper. Most objects are
resolved early; only the suspicious minority reach expensive analysis.

```
  File/script/process event
        │
   ┌────▼─────────────────┐  hit → allow (signed/known-good) or block (known-bad)
   │ L0  Reputation cache  │  local LRU + cloud prevalence; <100 µs on hit
   └────┬─────────────────┘
        │ miss / unknown
   ┌────▼─────────────────┐  exact + fuzzy hash, YARA, PE structural sigs
   │ L1  Signature scan    │  fast, high-precision for KNOWN threats
   └────┬─────────────────┘
        │ no sig
   ┌────▼─────────────────┐  unpack/emulate, entropy, imports, anomaly features
   │ L2  Heuristic/static  │  + on-device static ML (EMBER-style)
   └────┬─────────────────┘
        │ allowed to run / still unknown
   ┌────▼─────────────────┐  process-tree + API/ETW event correlation,
   │ L3  Behavioral engine │  MITRE ATT&CK detections, behavioral ML
   └────┬─────────────────┘
        │ ambiguous / high-value
   ┌────▼─────────────────┐  heavy ML, detonation sandbox, global prevalence,
   │ L4  Cloud verdict     │  threat-intel correlation across the fleet
   └────┬─────────────────┘
        │
   ┌────▼─────────────────┐  weighted fusion → allow / monitor / block /
   │ Verdict fusion+policy │  quarantine / kill + rollback
   └──────────────────────┘
```

## 2. L1 — Signature-based detection

Fast, deterministic, near-zero false positives for *known* malware. Necessary
but not sufficient.

- **Exact hashes:** SHA-256 of file and of each PE section. Stored in a
  memory-mapped DB fronted by a **Bloom filter** so the common "not in set" case
  costs one cache-friendly lookup.
- **Fuzzy / similarity hashes:** **SSDEEP**, **TLSH**, and **imphash** (import
  table hash) to catch repacked or lightly modified variants of known families.
- **Byte-pattern signatures:** **YARA** rules authored by Threat Research,
  matched with a vectorized multi-pattern engine (Aho-Corasick / Hyperscan-style)
  so thousands of rules run in one pass.
- **Certificate & metadata signals:** revoked/stolen signing certs, suspicious
  publishers, anomalous version info.

> **Why keep signatures in a behavior-first world?** They are the cheapest way
> to clear the 99% known-bad/known-good population so expensive layers focus on
> the unknown — and they give crisp, explainable family attribution.

## 3. L2 — Heuristic / static analysis

Static reasoning about an unknown file *before* it runs.

- **Unpacking / lightweight emulation:** a CPU emulator unwraps common packers
  and self-extracting stubs to reveal the real payload for L1/L2 to inspect.
- **PE structural heuristics:** high section **entropy** (packing/encryption),
  suspicious **import** combos (`VirtualAllocEx`+`WriteProcessMemory`+
  `CreateRemoteThread`), abnormal section permissions (W+X), TLS callbacks,
  tiny `.text` with huge overlay, mismatched checksums, resource anomalies.
- **Document / script statics:** OLE/OOXML macro extraction, PDF JS, LNK target
  inspection, HTA, shellcode pattern scanning.
- **On-device static ML** (see §5.1) is the learned successor to hand-written
  heuristics and runs here.

## 4. L3 — Behavioral / dynamic analysis (the zero-day engine)

This is the core differentiator and where CrowdStrike/SentinelOne win. We don't
ask *"what is this file?"* but *"what is this process doing, in context?"*

### 4.1 Inputs
The kernel callbacks, ETW (incl. Threat-Intel), AMSI, and WFP feed a unified,
time-ordered **event stream** per process, stitched into a **process lineage
graph** (parent→child, injected-into, files touched, network, registry).

### 4.2 Detection logic — mapped to MITRE ATT&CK
A rules + ML hybrid evaluates the graph continuously. Representative
behaviors (technique IDs):

| Behavior | Example signal | ATT&CK |
|---|---|---|
| Office spawns shell/script | `winword.exe → powershell.exe -enc …` | T1059 / T1566 |
| Credential dumping | non-trusted handle to LSASS w/ VM_READ | T1003.001 |
| Process injection / hollowing | remote alloc(W+X)+thread; image base mismatch | T1055 |
| LOLBins | `rundll32`, `mshta`, `regsvr32` w/ remote payload | T1218 |
| Persistence | Run key / service / scheduled-task / IFEO write | T1547 / T1053 |
| Defense evasion | disabling AV, clearing event logs, AMSI bypass | T1562 |
| Ransomware | rapid mass file rename/encrypt; canary-file touch; high write entropy | T1486 |
| Discovery/lateral | recon bursts, SMB/WMI/PsExec spread | T1021 |

### 4.3 Ransomware behavioral defense + **rollback**
- **Canary files** seeded in user dirs; any write/encrypt is a high-confidence
  trip.
- **Write-entropy & rename-rate** monitoring across the file event stream.
- **Journaling for rollback:** the minifilter copies-on-write or journals
  modified files (or orchestrates VSS) so that on detection we **kill the chain
  and restore** the originals — the SentinelOne-style "1-click rollback."

### 4.4 Why this catches zero-days
A brand-new binary has no signature and may evade static ML, but to achieve its
goal it must *behave* — inject, persist, encrypt, or exfiltrate. Behavior is the
invariant, so behavioral detection generalizes to never-before-seen malware.

## 5. L2/L3/L4 — AI / Machine Learning

ML appears at three tiers; **train in the cloud, infer on-device via ONNX**.

### 5.1 Static file ML (on-device, pre-execution)
- **Features:** the **EMBER**-style feature set (byte histograms, byte-entropy
  histogram, PE header/section/import/export/string features) → ~2.4k features.
- **Model:** gradient-boosted decision trees (LightGBM/XGBoost) and/or a compact
  CNN over raw bytes (MalConv-style). Quantized; **< 2 ms** inference.
- **Role:** convict obvious malware pre-execution; surface "suspicious" for
  closer watch.

### 5.2 Behavioral / sequence ML (on-device + cloud)
- **Features:** sequences of API/ETW events, command-line tokens, graph
  features over the process lineage.
- **Model:** sequence models (LSTM/Temporal-CNN/transformer) for anomaly &
  malicious-pattern scoring; a command-line **NLP classifier** for obfuscated
  PowerShell/one-liners.
- **Role:** score the *behavior stream* in real time, complementing the rules in
  §4.2.

### 5.3 Cloud "big" models & reputation (L4)
- Far larger models, multi-file/account context, and **fleet-wide prevalence**
  ("seen on 2 machines globally, 3 minutes ago, first-seen" → suspicious).
- Detonation **sandbox** for true dynamic analysis on submitted samples.

### 5.4 MLOps & the hard problems
- **Adversarial ML:** attackers craft evasive samples; mitigate with adversarial
  training, feature robustness, ensembling, and never relying on a single model.
- **Model drift & retraining:** continuous labeled-data pipeline from the
  telemetry lake + threat-research labels; scheduled retrain + offline eval gate.
- **Explainability:** every ML conviction emits top contributing features so
  analysts (and FP appeals) can understand *why*.
- **Versioning & rollout:** models are signed content shipped through the same
  TUF channel as signatures ([docs/03](docs/03-secure-updates.md)) with
  canary + auto-rollback.

## 6. L0/L4 — Cloud reputation & threat intelligence
- File/URL/domain/IP/certificate reputation with TTL-cached local answers.
- **Global prevalence & velocity** signals (rare + spreading-fast = bad).
- Integration of curated threat-intel feeds and IOCs; STIX/TAXII ingestion;
  retro-hunt across stored telemetry when new IOCs land.

## 7. Verdict fusion & response

A **fusion layer** combines layer scores with confidence weights and policy
(prevention vs. detect-only, sensitivity, exclusions) into one of:

| Verdict | Action |
|---|---|
| Clean | allow + cache |
| Suspicious | allow but **monitor** closely; raise telemetry fidelity |
| Malicious (high conf.) | **block / kill / quarantine** (pre-exec where possible) |
| Malicious + impact | block + **rollback** (ransomware) + **isolate host** (EDR) |

- **Quarantine vault:** encrypted, integrity-protected store; original ACL/path
  metadata retained for one-click restore on FP.
- **EDR response actions** (from cloud console): network-isolate endpoint, kill
  process tree, delete persistence, collect forensic package, run remediation
  script.

## 8. False-positive management (a first-class concern)
A noisy or FP-prone product gets uninstalled. Controls:
- **Allowlisting** of Microsoft/known-good signed binaries and a large
  **clean-file corpus** used as a release gate for every signature/model.
- **Staged rollout** of detection content with telemetry watch for FP spikes →
  auto-rollback ([docs/03](docs/03-secure-updates.md)).
- **Cloud override / "fast-flip"** to suppress a misfiring detection fleet-wide
  within minutes without a full content push.
- **Customer allow/block lists**, per-policy sensitivity, and a documented FP
  appeal path with explainability output.

## 9. Detection content lifecycle
```
Threat Research / ML pipeline → author sig/rule/model
   → automated test vs. malware corpus (detection rate)
   → automated test vs. clean corpus (FP rate)  ── gate ──►
   → sign (HSM) + TUF metadata → staged/canary rollout
   → fleet telemetry watch → promote OR auto-rollback
```
This lifecycle is the bridge to [docs/03 — Secure Updates](docs/03-secure-updates.md).
