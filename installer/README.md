# Installer & Code Signing

| Path | Purpose |
|---|---|
| `wix/Package.wxs` | The **MSI** (enterprise/GPO/SCCM/Intune deployment artifact). |
| `wix/Bundle.wxs` | The **Burn bootstrapper** → the single standalone `.exe`. |
| `sign/sign.ps1` | Code-signing entry point — **simulate** (CI gate) + **production** (signs exes + MSI). |
| `sign/new-selfsigned-cert.ps1` | One-time helper to mint a stable self-signed signing cert + repo secrets. |

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

`sign/sign.ps1` is the single signing entry point. It signs both the **exes**
and the **MSI** (Authenticode, SHA-256, RFC-3161 timestamp):

- **`-Mode simulate`** (CI default): signs with an **ephemeral self-signed**
  certificate and asserts a signature was applied, then deletes the cert. It
  exercises the full Authenticode/timestamp path so signing breakage is caught
  on every commit — *without* shipping a signature. Deliberately untrusted.
- **`-Mode production`** (release workflow): signs for real and **keeps** the
  signature. The certificate comes from two repo secrets when set, otherwise a
  self-signed cert is generated on the fly:
  - `TALOS_SIGNING_PFX_BASE64` — base64 of a `.pfx` (self-signed **or** CA/EV)
  - `TALOS_SIGNING_PFX_PASSWORD` — its password

```powershell
pwsh ./installer/sign/sign.ps1 -Mode production -Path talos.exe, talos-agent.msi
```

### Free self-signed signing (current default)

With no secrets set, releases are signed with a generated **self-signed** cert.
The binaries carry a `Talos Security` publisher, but Windows still shows
**"Unknown Publisher"** because the cert isn't from a public CA. To get a
*stable* identity (same cert across releases) you can trust + push to managed
machines, mint one once and store it as the two secrets:

```powershell
pwsh ./installer/sign/new-selfsigned-cert.ps1 -Password '<strong-password>'
# -> talos-signing.pfx (sign), .cer (trust), .pfx.base64 (the secret value)
```

Push the exported `.cer` to **Trusted Publishers** via GPO/Intune to make the
signature trusted on your fleet.

### Upgrading to a trusted (CA/EV) certificate

The release path is identical — just replace `TALOS_SIGNING_PFX_BASE64` /
`TALOS_SIGNING_PFX_PASSWORD` with a CA-issued `.pfx`. An **EV** certificate
(key in an HSM / Azure Key Vault) grants immediate SmartScreen reputation and
removes the warning; see [docs/04](../docs/04-deployment-distribution.md) §1.
Note that this script signs the *standalone* exes and the MSI container, not the
exes *embedded inside* the MSI — fine for the self-signed case; for a trusted
cert, sign the exes before `wix build` if you also need the installed copies
signed.

> Production driver signing (WHQL/attestation) and the ELAM/PPL entitlement are
> Phase 2/0 long-lead items, tracked in
> [docs/06-implementation-roadmap.md](../docs/06-implementation-roadmap.md).
