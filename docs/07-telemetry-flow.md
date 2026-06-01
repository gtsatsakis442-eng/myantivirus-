# 07 — Telemetry Flow  ⟨FOR REVIEW⟩

> **This document is for sign-off before we commit to the architecture.**
> It defines exactly what the agent collects, how it travels to the cloud, and
> the privacy controls applied at each hop. It binds the abstract privacy design
> ([docs/05](docs/05-compliance-privacy.md)) to the **concrete record the Phase 1
> engine already emits** (`scanner_core::ScanReport`).

## 1. The telemetry record (today, in code)

The scanner emits one record per inspected artifact. This is the literal NDJSON
produced by `talos --json` against an EICAR test file:

```json
{
  "path": "C:\\Users\\jdoe\\Downloads\\eicar.com",
  "size": 68,
  "hashes": {
    "md5": "44d88612fea8a8f36de82e1278abb02f",
    "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
    "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
  },
  "disposition": "malicious",
  "detections": [
    { "name": "Eicar.Test.File", "kind": "hash_signature", "severity": "critical" },
    { "name": "EICAR_Test_File", "kind": "yara_rule", "severity": "low" }
  ],
  "content_inspected": true,
  "duration_ms": 4
}
```

### 1.1 Per-field privacy assessment
This is the core of what needs review — **which fields can carry personal data**
and how we treat them:

| Field | Personal data? | Default treatment before upload |
|---|---|---|
| `path` | **Yes** — leaks usernames, document titles | **Redacted/tokenized**: collapse user profile (`C:\Users\<user>` → `%USERPROFILE%`), apply customer regex redaction rules. Full path only at `Full` tier or on confirmed detection per policy. |
| `hashes` | No (one-way digest) | Sent as-is; the primary pivot for reputation/hunting. |
| `size`, `duration_ms`, `content_inspected` | No | Sent as-is. |
| `disposition`, `detections` | No (our own verdicts) | Sent as-is — the security signal. |
| `error` | Maybe (may embed a path) | Same redaction as `path`. |
| **file content / sample** | **Yes, highest risk** | **Not in the record. Never sent by default.** Sample submission is opt-in, pre-screened/redacted, audited (see [docs/05 §3.3](docs/05-compliance-privacy.md)). |

Device/user identifiers added at the agent layer (not in the scan record) are
**pseudonymized** (tokenized device ID), per [docs/05 §3.2](docs/05-compliance-privacy.md).

## 2. End-to-end flow

```
 ┌────────────── ENDPOINT (agent) ──────────────┐
 │  scan event → ScanReport (§1)                 │
 │        │                                      │
 │   ┌────▼─────────────┐  drop fields not in    │
 │   │ TIER FILTER       │  the configured tier   │   (§3)
 │   └────┬─────────────┘                        │
 │   ┌────▼─────────────┐  %USERPROFILE%, secret │
 │   │ REDACTION         │  scrub, customer regex │   (docs/05 §3.2)
 │   └────┬─────────────┘                        │
 │   ┌────▼─────────────┐  tokenize device/user  │
 │   │ PSEUDONYMIZATION  │                        │
 │   └────┬─────────────┘                        │
 │   ┌────▼─────────────┐  bounded disk spool,    │
 │   │ LOCAL SPOOL+BATCH │  survives offline       │
 │   └────┬─────────────┘                        │
 └────────┼──────────────────────────────────────┘
          │  mTLS (pinned), compressed, regional endpoint   (docs/03 §4.1, docs/05 §3.4)
 ┌────────▼──────────────────────────────────────┐
 │  CLOUD (regional: EU data stays in EU)         │
 │   ingest → validate → telemetry lake           │
 │   → console / hunting / reputation enrichment  │
 │   retention clock starts (auto-delete §3)       │   (docs/05 §3.6)
 └────────────────────────────────────────────────┘
```

**Phase 1 reality:** the cloud hops are *not built yet*. Today telemetry is
**local only** — NDJSON to stdout or a local file. The tier filter / redaction /
pseudonymization stages are the **agreed contract** for the Phase 3 cloud
pipeline, shown here so we can ratify them now. Marked `⟨FOR REVIEW⟩` for that
reason.

## 3. Telemetry tiers (customer-controlled)

The deploying org chooses the tier; it bounds what can ever leave the endpoint.

| Tier | What ships | Path handling | Use case |
|---|---|---|---|
| **Minimal** | verdicts + critical alerts only (`disposition`, `detections`, `hashes`) | path omitted | Most privacy-sensitive; meets bare security need |
| **Standard** (default) | + security metadata (`size`, timing, redacted `path`) | redacted | Recommended balance |
| **Full** | + rich EDR event stream, full paths/command lines | full (still secret-scrubbed) | Active IR / hunting; higher DPIA scrutiny |

Sample (file content) submission is an **independent opt-in** switch, off by
default at every tier.

## 4. Lawful basis & controls (cross-reference)
- **Lawful basis:** legitimate interest (security), Recital 49 — [docs/05 §2](docs/05-compliance-privacy.md).
- **Minimization / pseudonymization / residency / retention / DSAR:** [docs/05 §3](docs/05-compliance-privacy.md).
- **Transport integrity (mTLS, pinning):** [docs/03 §4.1](docs/03-secure-updates.md).

## 5. Open questions for reviewers ⟨please confirm⟩
1. **Default tier = `Standard`** with redacted paths — agree, or default to `Minimal`?
2. **Path redaction policy:** is `%USERPROFILE%` collapse + customer regex
   sufficient, or do we tokenize *all* path segments at `Standard`?
3. **Sample submission default OFF** — confirm this is acceptable to the
   detection/IR teams (it reduces cloud retro-hunt fidelity).
4. **Retention defaults:** raw events 30 days / alerts 1 year — confirm with DPO.
5. **Identifier scheme:** per-tenant tokenized device ID with rotation cadence — confirm.
