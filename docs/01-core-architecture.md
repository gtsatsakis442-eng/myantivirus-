# 01 — Core Architecture

> High-performance, low-latency engine for real-time monitoring with minimal
> system impact and maximal tamper resistance.

## 1. Design principles

1. **Visibility must be unbypassable** → sensor lives partly in the kernel, where
   malware running as Administrator cannot easily hide from it.
2. **Blast radius must be small** → keep the kernel component a *thin sensor /
   enforcement layer*; do all heavy parsing, ML, and content interpretation in
   **user mode**. (See §8, the CrowdStrike lesson.)
3. **Fail safe, not fail open** *and* **fail safe, not fail catastrophic** — a
   bug or bad content update must degrade detection gracefully, never BSOD the
   fleet.
4. **The agent protects itself** → run as Protected Process Light (PPL),
   anchored by an ELAM driver, with object-callback handle stripping.
5. **Pay for protection in microseconds, not seconds** → cache aggressively,
   scan asynchronously, and keep the hot path allocation-free.

## 2. Kernel-mode vs. user-mode — the decision

| Capability | Kernel mode | User mode | Our choice |
|---|---|---|---|
| Intercept file I/O before completion | ✅ minifilter | ❌ | **Kernel** (minifilter) |
| Block process/thread creation pre-exec | ✅ Ps* callbacks | ❌ | **Kernel** |
| Observe in-memory / injection telemetry | ✅ ETW-TI (needs PPL) | partial | **Kernel-sourced, consumed in UM** |
| Script / fileless (PowerShell, VBA, .NET) | ❌ | ✅ AMSI | **User mode** (AMSI) |
| Heavy parsing (PE, archives, documents) | 🚫 dangerous | ✅ safe | **User mode** |
| ML inference | 🚫 | ✅ | **User mode** |
| Tamper resistance for the agent itself | ✅ | weak | **Kernel** (Ob callbacks + PPL) |

**Conclusion: a hybrid model.** The kernel layer is a *minimal, rigorously
validated sensor and policy-enforcement point*. Everything that parses
attacker-controlled bytes runs in user mode where a crash is recoverable.

## 3. Kernel-mode components

All kernel components ship in **one driver package** but logically separate.

### 3.1 File-system minifilter (real-time file protection)
- Built on the **Filter Manager (FltMgr)** model, **not** a legacy filter
  hook. Register with `FltRegisterFilter`.
- **Altitude:** request an altitude in the Microsoft-assigned
  **FSFilter Anti-Virus** range (320000–329999) via the allocation process.
  Altitude determines ordering relative to other filters; AV sits high.
- **Operations hooked (pre/post callbacks):**
  - `IRP_MJ_CREATE` — file open/exec → primary scan trigger.
  - `IRP_MJ_WRITE` / `IRP_MJ_CLEANUP` — content changed → invalidate cache,
    schedule rescan-on-close (cheaper than scan-on-every-write).
  - `IRP_MJ_SET_INFORMATION` — rename/delete → track, support ransomware
    detection and prevent self-deletion of the agent.
- **Verdict path:** kernel does *not* scan. It sends a scan request to the
  user-mode service via the **communication port** (`FltCreateCommunicationPort`
  / `FltSendMessage`). The service replies allow/block/quarantine. On block, the
  pre-op completes the IRP with `STATUS_VIRUS_INFECTED` / `STATUS_ACCESS_DENIED`.
- **Performance:** scan decisions are cached in a kernel hash table keyed by
  **file reference number + USN/last-write stamp**; a cache hit returns in
  nanoseconds with no user-mode round trip.

### 3.2 Process, thread, and image callbacks
- `PsSetCreateProcessNotifyRoutineEx2` — notified on process create/exit; the
  *Ex* form allows **blocking** a process launch by setting
  `CreationStatus`. Used for pre-execution prevention and to build the process
  tree (parent/child lineage for behavioral analysis).
- `PsSetCreateThreadNotifyRoutineEx` — remote-thread creation is a strong
  injection signal.
- `PsSetLoadImageNotifyRoutineEx` — DLL/driver image loads → detect unsigned /
  reflectively loaded / hijacked modules.

### 3.3 Registry callbacks
- `CmRegisterCallbackEx` — monitor `Run`/`RunOnce`, services, IFEO, COM
  hijacks, and other persistence locations; can block writes to protected keys.

### 3.4 Object callbacks (self-protection + credential-theft defense)
- `ObRegisterCallbacks` on `PsProcessType` / `PsThreadType` to **strip
  dangerous access rights** from handles:
  - Deny `PROCESS_VM_READ`/`PROCESS_VM_WRITE` to **LSASS** from non-trusted
    callers → blocks Mimikatz-style credential dumping.
  - Deny `PROCESS_TERMINATE`/handle-duplication against **our own** service →
    tamper protection.

### 3.5 Network — WFP callout driver
- A **Windows Filtering Platform** callout driver at the ALE
  (Application Layer Enforcement) and stream layers for:
  - Host firewall / network containment ("isolate this endpoint" EDR action),
  - C2 / malicious-IP blocking from threat intel,
  - DNS visibility (complemented by the DNS-client ETW provider in user mode).

### 3.6 ELAM driver (Early Launch Anti-Malware)
- A tiny driver that loads **before** other boot-start drivers and classifies
  them (Known Good / Bad / Unknown) using a signed ELAM signature blob in the
  registry.
- Two purposes:
  1. Catch boot-time/rootkit drivers early.
  2. **Anchor our PPL** — having a signed ELAM driver is what entitles the
     user-mode service to launch as an anti-malware Protected Process. (Signing
     details in [docs/04](docs/04-deployment-distribution.md).)

## 4. User-mode components

### 4.1 Protection Service (the brain) — runs as PPL
- Owns the detection engine ([docs/02](docs/02-detection-engine.md)), the scan
  cache, policy, and the kernel communication port.
- **Launched as `PROTECTED_LIGHT` / anti-malware signer** via
  `SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT`. Once PPL, even SYSTEM cannot
  read its memory, inject into it, or kill it without kernel help → strong
  tamper resistance.
- Registers with the **Windows Security Center (WSC)** so Windows recognizes a
  3rd-party AV is present and Defender steps to passive mode (no double-scan
  tax).

### 4.2 AMSI provider (fileless / script defense)
- Implements the **Antimalware Scan Interface** `IAntimalwareProvider` COM
  interface. Windows hands us, *post-deobfuscation*, the content of:
  - PowerShell scripts & dynamic code, VBScript/JScript (WSH), Office VBA
    macros, MSHTA, .NET in-memory assemblies (where AMSI is wired).
- This is how we catch attacks that **never touch disk** — the minifilter never
  sees them, but AMSI does.

### 4.3 ETW consumers
- Subscribe to high-value providers:
  - **Microsoft-Windows-Threat-Intelligence (ETW-TI)** — kernel-sourced signals
    on memory allocation/protection changes, remote injection, suspicious
    syscalls. **Requires the consumer to be PPL** — another reason for §4.1.
  - DNS-Client, DNS-Server, Kernel-Process/Network, WinINet, AMSI, RPC.
- ETW gives breadth without writing more kernel code — the preferred way to
  expand telemetry safely.

### 4.4 Update Agent — see [docs/03](docs/03-secure-updates.md).

### 4.5 UI / Tray + local management — thin, talks to the service over a
local, authenticated RPC; no security logic lives here.

## 5. Inter-process & kernel↔user communication

```
 Kernel minifilter ──FltSendMessage──► [Filter comm port] ──► Scan Service (PPL)
 Kernel callbacks  ──ring buffer / inverted call──────────► Behavioral Engine
 Service ◄──local ALPC/named-pipe (auth + ACL'd)──► UI, CLI, Update Agent
 Service ──mTLS (pinned)──► Cloud
```
- **Inverted call model** for kernel→user event streaming: user mode posts a
  pool of pended IRPs/messages; the kernel completes them as events occur →
  low latency, no polling.
- All local IPC endpoints are **ACL-restricted** and the service verifies the
  **PPL level / signature** of callers where the OS allows.

## 6. Performance & low-latency engineering

Real-time AV is judged on **file-open latency**, **boot impact**, and **CPU/RAM
under load**. Budgets and tactics:

| Hot path | Target | How |
|---|---|---|
| Cached-clean file open | **< 50 µs** added | Kernel verdict cache (file-id + USN stamp); no UM round trip |
| First-seen file scan (small PE) | **< 5 ms** p50 | Memory-mapped signature DB, Bloom-filter pre-check, Aho-Corasick / vectorized multi-pattern (Hyperscan-style) |
| Behavioral event ingest | **non-blocking** | Lock-free ring buffer; events processed off the I/O path |
| On-device ML inference | **< 2 ms** | Quantized gradient-boosted/compact NN via ONNX Runtime |
| Boot delay | **negligible** | ELAM is tiny; defer non-critical work; no synchronous cloud calls at boot |

Additional tactics:
- **Verdict caching with precise invalidation** keyed on the NTFS **USN change
  journal** so a clean verdict survives until the file actually changes.
- **Allowlist fast-path** for Microsoft-signed and known-good (catalog-verified)
  binaries — skip deep scan, just verify signature.
- **Scan-on-close, not scan-on-every-write** for write-heavy workloads.
- **Asynchronous + tiered**: a fast synchronous gate (cache/hash/reputation)
  unblocks the app; deep static + behavioral analysis continues async and can
  retroactively kill/quarantine.
- **Backpressure & throttling**: bounded queues, CPU budget caps, idle-time
  scheduling for full scans, I/O priority hints.
- **Exclusions** honored at the kernel layer to avoid round trips for trusted
  paths (e.g., SQL data files) — with policy guardrails so exclusions can't be
  abused as an evasion.

## 7. Self-protection (tamper resistance)

| Threat | Control |
|---|---|
| Kill the agent process | PPL + Ob callback denies `PROCESS_TERMINATE` |
| Read/inject agent memory | PPL (memory access denied to non-PPL); Ob handle stripping |
| Stop/disable the service | Service launch-protected; recovery restarts; kernel watchdog |
| Delete agent files / unload driver | Minifilter denies delete/rename of protected paths; driver marked non-unloadable in production |
| Disable via registry | Registry callbacks protect agent keys |
| Uninstall by local admin | Tamper-protection policy + uninstall password enforced from cloud console |

## 8. The CrowdStrike lesson (why kernel logic is minimized)

In July 2024 a **content update** consumed by a kernel driver triggered an
out-of-bounds read and BSOD'd millions of Windows hosts worldwide. The
architectural takeaways are baked into this design:

1. **Content must not be able to crash the kernel.** Any data the kernel reads
   (rules, channel files) is **strictly validated and bounds-checked**; the
   interpreter for complex content lives in **user mode**.
2. **Content updates are software updates** — they get the same staged/canary
   rollout, health gating, and automatic rollback as binaries
   (see [docs/03](docs/03-secure-updates.md)).
3. **Prefer user-mode and ETW** over new kernel code for new telemetry; this
   also aligns with Microsoft's post-2024 *endpoint security platform*
   initiative to move AV vendors out of the kernel hot path.
4. **Watchdog & safe mode:** if the agent detects repeated early crashes, it
   boots into a minimal "safe" mode (kernel sensor passive, no content
   interpretation) and reports home, rather than crash-looping.

## 9. Open questions / decisions to ratify
- Exact altitude request and ELAM entitlement timeline (Microsoft-gated).
- KMDF vs. WDM for the sensor (recommend **KMDF**).
- Rust-for-Windows vs. C++ for the user-mode service (recommend **Rust** for the
  parsing-heavy surface; C++ acceptable if team velocity demands).
- How much network inspection in WFP vs. delegating to OS firewall + ETW.
