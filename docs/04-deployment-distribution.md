# 04 — Deployment & Distribution

> Shipping a trusted, standalone Windows `.exe` + kernel driver, and deploying
> silently at enterprise scale across Active Directory.

## 1. Code signing (Authenticode)

Everything executable is signed: the **bootstrapper `.exe`**, the **MSI**,
every **DLL**, the **kernel driver**, the **ELAM driver**, and **catalog
(`.cat`)** files.

### 1.1 Certificate
- Use an **EV (Extended Validation) code-signing certificate**.
  - As of the CA/Browser Forum 2023 baseline, code-signing private keys must
    live on **FIPS 140-2 (Level 2)+ hardware** (HSM / hardware token / cloud HSM
    such as Azure Key Vault HSM). No more exportable PFX on a laptop.
  - EV grants **immediate Microsoft SmartScreen reputation**, avoiding the
    "Unknown Publisher" warning that kills enterprise trust on day one.
- Sign with `signtool` using **SHA-256**.

### 1.2 Timestamping (don't skip)
- **RFC 3161** timestamp every signature so binaries remain valid **after the
  cert expires**. Without it, the whole installed base "expires" with the cert.

### 1.3 What the signature buys us
- SmartScreen / "Mark of the Web" trust, AppLocker/WDAC publisher rules, and the
  **prerequisite for kernel-driver acceptance** (below).

## 2. Kernel-driver signing — WHQL & attestation

On 64-bit Windows 10/11 and Server, kernel-mode drivers **must be signed by
Microsoft**; a vendor EV signature alone is not loadable for new drivers.

### 2.1 Onboarding
1. Enroll in the **Microsoft Hardware Developer Program** via **Partner Center**.
2. Identity is bound to your **EV code-signing certificate** (used to
   authenticate submissions to the dashboard).

### 2.2 Two routes to a Microsoft signature

| Route | What it is | Effort | Use when |
|---|---|---|---|
| **Attestation signing** | Submit the driver to Partner Center; Microsoft signs it after automated checks (no logo, no HLK test suite). | Low / fast | Win10+ only; our default for the sensor & ELAM during dev/early GA |
| **WHQL certification** | Run the **Windows Hardware Lab Kit (HLK)** test suite, submit logs + driver; Microsoft signs + grants the **WHQL logo**. | High | Broadest compatibility, "Certified for Windows" credibility, down-level coverage |

> **Plan:** attestation-sign to move fast, then pursue **full WHQL** for the GA
> sensor for maximum compatibility and enterprise trust signaling.

### 2.3 ELAM signing & PPL entitlement (special)
- The **ELAM driver** must be signed with the **Early-Launch Anti-Malware EKU**
  and meet Microsoft's ELAM requirements; the capability is **gated/approved by
  Microsoft** (anti-malware vendor vetting).
- The ELAM driver + correct registry resource section is what lets the
  user-mode service launch as **anti-malware PPL**
  (`SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT`) — see
  [docs/01 §3.6/§4.1](docs/01-core-architecture.md).
- **Lead time is significant** — start the ELAM/PPL entitlement process early
  (it's the long pole in the schedule, see [docs/06](docs/06-implementation-roadmap.md)).

### 2.4 Driver quality gates (acceptance criteria before any signing)
- Clean under **Driver Verifier** (all relevant flags), **Static Driver
  Verifier (SDV)**, **CodeQL**, and the **HLK** subset; kernel fuzzing of the
  comms port; no pool leaks; IRQL correctness. A driver bug is a fleet-wide BSOD.

## 3. The installer

### 3.1 Packaging
- Build with **WiX Toolset**:
  - An **MSI** is the core (enterprise/GPO/SCCM expect MSI).
  - A **Burn bootstrapper `.exe`** wraps the MSI + driver + prerequisites
    (VC++ runtime, etc.) into the single **standalone signed `.exe`** the
    product is distributed as. The `.exe` can also extract/serve the MSI for
    teams that deploy MSI directly.
- Sign **both** the `.exe` and the inner MSI.

### 3.2 Install behavior
- **Silent / unattended:** `/quiet /norestart` (bootstrapper) and
  `msiexec /i Talos.msi /qn /norestart` (MSI).
- **Configuration via MSI properties** (so deployment tools can parameterize):
  - `TENANT_TOKEN=…` (auto-enroll the agent to the right cloud tenant),
  - `SERVER=…`, `UPDATE_RING=…`, `PROXY=…`, `TELEMETRY_LEVEL=…`.
  - Example:
    `msiexec /i Talos.msi /qn /norestart TENANT_TOKEN=abc123 UPDATE_RING=delayed`
- **`.mst` transforms** for per-site config without re-packaging.
- **Reboot handling:** driver/ELAM ideally load without reboot; where a reboot
  is required, defer with `/norestart` and let the deployment tool schedule it.
- **Logging:** `/l*v install.log` for fleet diagnostics; report install
  success/failure home on first check-in.
- **Tamper-proof uninstall:** uninstall requires the tamper-protection
  password/policy from the console (prevents malware or users from removing it).

### 3.3 Coexistence
- Register via **Windows Security Center (WSC)** so Windows recognizes a 3rd-party
  AV and **Microsoft Defender** drops to passive mode automatically (no
  double-scan, no conflict). Detect and warn on other 3rd-party AVs.

## 4. Silent deployment across Active Directory

Ranked by enterprise fit:

| Method | How | Best for |
|---|---|---|
| **Intune / MDM** | Upload as Win32 app (`.intunewin`) or MSI; assign to device groups; silent flags. | Modern, cloud-managed, hybrid/remote fleets |
| **Microsoft Configuration Manager (SCCM/MECM)** | Application/Package with silent command line; collections by AD OU/group; staged rings; reporting. | Large on-prem estates; richest control & reporting |
| **GPO Software Installation** | Assign the **MSI** to **computer** objects via a Group Policy linked to an OU; installs at boot. | No SCCM/Intune; straightforward MSI push |
| **GPO startup script / third-party (PDQ, etc.)** | Script calls `msiexec … /qn` with the tenant token. | Edge cases, mixed tooling |

**Recommended pattern**
1. Distribute the **MSI** (computer-assigned) by **OU** so scope follows AD
   structure.
2. Pass `TENANT_TOKEN` + config via MSI properties / transform → **zero-touch
   enrollment**; the agent appears in the console on first check-in.
3. Use **AD groups/OUs as deployment rings** (pilot OU → dept → org) to mirror
   the staged-rollout philosophy from [docs/03 §7](docs/03-secure-updates.md).
4. Ship **ADMX templates** so admins set agent policy through Group Policy
   alongside everything else.
5. Health dashboard reconciles "machines in AD" vs. "agents checked in" to find
   coverage gaps.

## 5. Updates post-install
- Agent self-updates content via the TUF channel ([docs/03](docs/03-secure-updates.md));
  **binary/driver** upgrades flow through the same enterprise tooling (or
  controlled in-product auto-update) with WHQL-signed payloads, honoring the
  customer's chosen update ring (`N`, `N-1`, delayed).

## 6. Distribution security checklist
- [ ] EV cert in HSM; keys never exportable
- [ ] All PE files + MSI + `.exe` Authenticode-signed, SHA-256, **timestamped**
- [ ] Driver Microsoft-signed (attestation → WHQL); ELAM EKU + Microsoft approval
- [ ] Driver passes Verifier/SDV/CodeQL/HLK gates
- [ ] Installer integrity verified by bootstrapper before applying
- [ ] Tamper-protected uninstall enforced from console
- [ ] WSC registration for Defender coexistence
- [ ] Reproducible build + SBOM published (ties to [docs/03 §4.3](docs/03-secure-updates.md))
