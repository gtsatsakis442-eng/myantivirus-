<#
.SYNOPSIS
    Talos EPP code-signing abstraction.

.DESCRIPTION
    One entry point for signing build artifacts, with two modes:

      -Mode simulate   (default, used in CI)
          Generates an EPHEMERAL self-signed code-signing certificate and signs
          the given artifacts with it, then verifies a signature was applied.
          This exercises the ENTIRE signing path (signtool/Authenticode plumbing,
          artifact signability, timestamping) WITHOUT the real EV/HSM credential,
          so signing breakage is caught on every commit instead of at release.
          The signature is intentionally NOT trusted (self-signed, 1-day cert).

      -Mode production (release pipeline only)
          Placeholder that must run on the hardened signing host with the EV
          certificate in an HSM / Azure Key Vault. Intentionally refuses to run
          in CI. See docs/04-deployment-distribution.md.

.EXAMPLE
    pwsh ./installer/sign/sign.ps1 -Mode simulate -Path a.exe, b.msi
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Path,

    [ValidateSet('simulate', 'production')]
    [string]$Mode = 'simulate',

    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'

if ($Mode -eq 'production') {
    throw "Production signing must run on the hardened signing host with the EV/HSM credential. " +
          "It is intentionally unavailable in CI (see docs/04-deployment-distribution.md)."
}

Write-Host "=== Talos code-signing SIMULATION (non-production, self-signed) ==="

# 1. Create a throwaway code-signing certificate.
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject 'CN=Talos EPP CI Test Signing (DO NOT TRUST)' `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -KeyExportPolicy Exportable `
    -KeyUsage DigitalSignature `
    -NotAfter (Get-Date).AddDays(1)

$failed = $false
try {
    foreach ($p in $Path) {
        if (-not (Test-Path -LiteralPath $p)) {
            throw "artifact not found: $p"
        }
        Write-Host "Signing: $p"

        # Try with an RFC-3161 timestamp; fall back if CI has no egress to the
        # timestamp server (the simulation must not depend on network).
        try {
            $null = Set-AuthenticodeSignature -FilePath $p -Certificate $cert `
                -HashAlgorithm SHA256 -TimestampServer $TimestampUrl -ErrorAction Stop
        }
        catch {
            Write-Warning "  timestamping failed ($($_.Exception.Message)); signing without timestamp."
            $null = Set-AuthenticodeSignature -FilePath $p -Certificate $cert `
                -HashAlgorithm SHA256 -ErrorAction Stop
        }

        # Verify a signature was actually applied. (Status will be 'UnknownError'
        # / 'NotTrusted' because the cert is self-signed; that is expected. The
        # real assertion is that a SignerCertificate is present.)
        $sig = Get-AuthenticodeSignature -FilePath $p
        if ($null -eq $sig.SignerCertificate) {
            Write-Error "  FAILED: no signature applied to $p"
            $failed = $true
        }
        else {
            $ts = if ($sig.TimeStamperCertificate) { 'yes' } else { 'no' }
            Write-Host ("  OK: status={0} timestamped={1}" -f $sig.Status, $ts)
        }
    }
}
finally {
    # Always remove the throwaway certificate.
    Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $cert.Thumbprint) -Force -ErrorAction SilentlyContinue
}

if ($failed) {
    throw "Code-signing simulation FAILED: one or more artifacts could not be signed."
}
Write-Host "=== Simulation OK: all artifacts are signable and a signature was applied. ==="
