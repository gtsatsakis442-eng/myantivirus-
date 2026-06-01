# Installer & Code Signing

| Path | Purpose |
|---|---|
| `wix/Package.wxs` | The **MSI** (enterprise/GPO/SCCM/Intune deployment artifact). |
| `wix/Bundle.wxs` | The **Burn bootstrapper** → the single standalone `.exe`. |
| `sign/sign.ps1` | Code-signing abstraction with a **CI simulation** mode. |

## Build (Windows, WiX v4/v5)

```powershell
# 1. Build the scanner for Windows
cargo build --release -p scanner-cli --target x86_64-pc-windows-msvc

# 2. Build the MSI (core WiX, no extensions needed)
cd installer/wix
wix build Package.wxs -o talos-agent.msi

# 3. (release pipeline) Wrap into the standalone .exe
wix extension add -g WixToolset.Bal.wixext
wix build Bundle.wxs -ext WixToolset.Bal.wixext -o talos-setup.exe
```

## Silent deployment (Active Directory)

```bat
:: Zero-touch enrollment via MSI properties (GPO/SCCM/Intune)
msiexec /i talos-agent.msi /qn /norestart ^
        TENANT_TOKEN=abc123 SERVER=https://cloud.example UPDATE_RING=delayed
```
Config is written to `HKLM\SOFTWARE\Talos EPP`. See
[docs/04-deployment-distribution.md](../docs/04-deployment-distribution.md) for
GPO/Intune/SCCM patterns and rollout rings.

## Code signing

`sign/sign.ps1` is the single signing entry point:

- **`-Mode simulate`** (CI default): signs artifacts with an **ephemeral
  self-signed** certificate and verifies the signature was applied. It exercises
  the full Authenticode/timestamp path so signing breakage is caught on every
  commit — *without* the production credential. The signature is deliberately
  untrusted.
- **`-Mode production`** (release host only): refuses to run in CI; on the
  hardened signing host it would invoke `signtool` against the **EV certificate
  in an HSM / Azure Key Vault** with an RFC-3161 timestamp. See
  [docs/04](../docs/04-deployment-distribution.md) §1.

```powershell
pwsh ./installer/sign/sign.ps1 -Mode simulate -Path talos.exe, talos-agent.msi
```

> Production driver signing (WHQL/attestation) and the ELAM/PPL entitlement are
> Phase 2/0 long-lead items, tracked in
> [docs/06-implementation-roadmap.md](../docs/06-implementation-roadmap.md).
