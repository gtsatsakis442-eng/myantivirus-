# 03 — Secure Update System

> Efficient **delta** content sync on a 48-hour cadence, hardened against
> **supply-chain attacks** with end-to-end integrity and **staged rollout**.

## 1. What gets updated (and how often)

| Content type | Channel | Default cadence | Notes |
|---|---|---|---|
| Signatures / YARA / IOCs | content | **every 48 h** (scheduled) | The requested baseline cadence |
| ML models | content | weekly–monthly | Larger; same security pipeline |
| Behavioral rules / kernel "channel files" | content | as needed | **Treated as software** — staged + bounds-checked (CrowdStrike lesson) |
| Emergency signatures | **out-of-band** | minutes (push) | For active outbreaks; see §6 |
| Agent binaries / driver | software | controlled releases | WHQL/EV-signed; [docs/04](docs/04-deployment-distribution.md) |

> **On the 48 h requirement:** we honor a 48 h scheduled baseline as specified.
> Because real outbreaks move in minutes, the architecture *also* provides an
> out-of-band emergency channel (§6) and cloud-side reputation that needs no
> local content at all. Recommend keeping 48 h as the floor, configurable down.

## 2. Distribution architecture

```
 Build/Research ──► Content Build Pipeline ──► HSM Signing ──► TUF Repo ──► CDN
                       (in-toto attested)        (offline root)    │
                                                                   ▼
 Endpoint Update Agent ──pulls delta──► verifies (TUF + sig) ──► stages ──► applies
        ▲  reports version + health                                  │
        └──────────────────── telemetry ─────────────────────────────┘
```
- **CDN-fronted, pull-based.** Endpoints pull on schedule (never an inbound
  connection to the endpoint). CDN absorbs scale; origin holds signed artifacts.
- **Scheduling with jitter:** the 48 h timer is randomized ±a few hours per host
  to avoid a synchronized "thundering herd."
- **Resumable, bandwidth-aware** transfers; respect enterprise bandwidth policy
  and proxies; optional on-prem mirror/relay for air-gapped or egress-limited
  sites.

## 3. Delta (differential) update mechanism

Goal: download only what changed, not the multi-hundred-MB DB.

1. **Structure the DB as content-addressable chunks.** Apply
   **content-defined chunking** (e.g., FastCDC) so unchanged regions keep the
   same chunk hashes across releases.
2. **Build a Merkle tree** over the chunks; the signed root identifies the whole
   DB version.
3. **Client sync:** the agent knows its current chunk set + Merkle root. It
   fetches the new signed manifest, **diffs the chunk lists**, and downloads
   **only the missing chunks** from the CDN. (This is the rsync/Merkle model and
   degrades gracefully when many small signatures change.)
4. **Binary patching** (bsdiff/Courgette-style) is used for the agent binary /
   model blobs where whole-file deltas beat chunk-diffing.
5. **Atomic apply:** assemble the new DB in a staging area, verify the rebuilt
   Merkle root == signed root, then **atomically swap** (rename) into place. A
   crash mid-update never yields a half-written DB; the old DB stays valid.
6. **Anti-rollback:** versions are monotonic and signed; the client refuses any
   manifest older than what it has (freeze/rollback-attack defense, §5).

## 4. Integrity — defense against supply-chain attacks

TLS alone is **not** sufficient (it only authenticates the channel, not the
content, and breaks under a compromised server or CDN). We layer:

### 4.1 Transport
- **mTLS** with **certificate pinning**; modern cipher suites only.

### 4.2 Content signing with **The Update Framework (TUF)**
TUF is the industry standard for surviving **key compromise** and update-system
attacks. Roles with **separate keys** and **threshold signatures**:

| TUF role | Responsibility | Key handling |
|---|---|---|
| **root** | delegates trust to other roles; the trust anchor | **offline**, in HSM, threshold (e.g., 3-of-5), rotated |
| **targets** | signs the actual content (signatures/models) hashes & sizes | HSM, online-ish, delegated to research teams |
| **snapshot** | signs the set/versions of all metadata (consistency) | online |
| **timestamp** | frequently re-signed freshness proof (freeze defense) | online, short expiry |

TUF gives us, by construction:
- **Compromise resilience** — losing one online key ≠ arbitrary code; root
  (offline) can recover and rotate.
- **Rollback/freeze protection** — versioned + expiring metadata.
- **Mix-and-match protection** — snapshot pins a consistent set of artifacts.

Recommended impl: **go-tuf** or **rust-tuf** (Sigstore/Notary lineage).

### 4.3 Build-pipeline attestation with **in-toto** (anti-SolarWinds)
Signing the *output* doesn't help if the *build* is compromised (the SolarWinds
model). **in-toto** cryptographically attests each step of the content build
(checkout → compile rules → test → package), and the client/verifier checks the
supply-chain layout was followed by authorized functionaries.
- **Reproducible builds** so an independent rebuild yields identical bytes.
- **SBOM** for the agent; provenance per SLSA.

### 4.4 Key & process hygiene
- All signing keys in **FIPS 140-2/3 HSMs**; offline root with M-of-N quorum and
  ceremony logging.
- **Separation of duties:** authoring ≠ approving ≠ signing ≠ releasing.
- **Mandatory code review** on detection content; no single human can ship.
- Regular **key rotation** and documented revocation runbooks.

### 4.5 Client-side verification (every update, every time)
```
download manifest ─► verify TUF chain (root→targets, thresholds, expiry, version↑)
                  ─► for each chunk: hash matches signed manifest?
                  ─► rebuild DB: Merkle root == signed root?
                  ─► all checks pass ──► atomic swap; else ──► discard + alert
```
The endpoint trusts **only** content whose hashes chain up to the **pinned TUF
root** baked into the (EV-signed) agent — independent of TLS and CDN integrity.

## 5. Threat model & mitigations (summary)

| Attack | Mitigation |
|---|---|
| MITM / malicious CDN node | Content signing + TUF (TLS is secondary) |
| Stolen online signing key | TUF threshold + offline root rotation |
| Build/CI compromise (SolarWinds-style) | in-toto attestation + reproducible builds + SBOM/SLSA |
| Rollback to vulnerable old content | Monotonic signed versions; client refuses downgrade |
| Freeze attack (withhold updates) | timestamp role w/ short expiry; client flags stale content |
| Mix-and-match inconsistent artifacts | snapshot role pins consistent set |
| **Authentic-but-bad content** (CrowdStrike-style) | **§7 staged rollout + bounds-checked kernel content + auto-rollback** |
| Tampered local DB on disk | Merkle verification on load; PPL/minifilter protect files |

## 6. Out-of-band emergency channel
For active outbreaks, a separate **push** channel (same TUF/signing guarantees)
delivers a tiny critical-signature bundle in minutes. Cloud reputation (L0/L4 in
[docs/02](docs/02-detection-engine.md)) provides protection **with no local
content update at all**, covering the gap between 48 h syncs.

## 7. Staged / canary rollout & rollback (the CrowdStrike lesson)
Even perfectly *authentic* content can be *wrong* and cause mass FPs or
instability. **Content is released like software:**
1. **Ring 0 — internal** test fleet + full clean/malware corpus gate.
2. **Ring 1 — canary** (small % of opted-in production), watch FP/crash/perf
   telemetry.
3. **Ring 2..N — progressive** rollout (e.g., 1% → 10% → 50% → 100%) with health
   gates between rings.
4. **Automatic rollback** if any ring breaches FP/crash/perf thresholds.
5. **Kernel-consumed content is strictly validated & bounds-checked**; the
   parser for complex content lives in user mode (see
   [docs/01 §8](docs/01-core-architecture.md)).
6. Customers can choose update rings (e.g., "N-1" / delayed) per policy.

## 8. Offline / air-gapped support
- On-prem **content mirror** that itself verifies TUF before redistributing.
- Manual, signed content bundles importable via the console for fully
  disconnected networks; same verification path.
