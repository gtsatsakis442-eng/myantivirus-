<#
.SYNOPSIS
    Talos EPP code-signing (Authenticode) for the app exes and the MSI.

.DESCRIPTION
    One entry point for signing build artifacts, with two modes:

      -Mode simulate   (default, CI signability gate)
          Generates an EPHEMERAL self-signed code-signing certificate, signs the
          given artifacts, asserts a signature was applied, then deletes the
          cert. Exercises the ENTIRE Authenticode/timestamp path on every commit
          WITHOUT shipping a signature, so signing breakage is caught early. The
          signature is intentionally NOT trusted (self-signed, 1-day cert).

      -Mode production (release pipeline)
          Signs the artifacts for real and KEEPS the signature. The certificate
          is taken from a base64 PKCS#12 (.pfx) in the environment when present,
          otherwise a self-signed cert is generated on the fly:
              TALOS_SIGNING_PFX_BASE64    base64 of the .pfx (CA-issued OR self-signed)
              TALOS_SIGNING_PFX_PASSWORD  the .pfx password
          The same path serves a free self-signed cert and a real CA/EV cert —
          only the secret behind it changes. With no secret the release is still
          signed (a Talos publisher identity is present) but the cert is
          untrusted, so Windows still shows "Unknown Publisher" until the cert is
          trusted (e.g. pushed to Trusted Publishers via GPO/Intune) or replaced
          with a CA/EV cert. See installer/README.md and
          docs/04-deployment-distribution.md.

          Mint a stable self-signed cert + the two secrets with:
              installer/sign/new-selfsigned-cert.ps1

.EXAMPLE
    pwsh ./installer/sign/sign.ps1 -Mode simulate   -Path a.exe, b.msi
    pwsh ./installer/sign/sign.ps1 -Mode production -Path a.exe, b.msi
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

# Sign every artifact with $Cert, preferring an RFC-3161 timestamp but falling
# back to no timestamp if the runner has no egress to the timestamp server (the
# CI simulation must not depend on network). Returns the artifacts that could
# not be signed so the caller decides whether to fail.
function Invoke-Signing {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [string[]]$Paths,
        [string]$TimestampUrl
    )
    $bad = @()
    foreach ($p in $Paths) {
        if (-not (Test-Path -LiteralPath $p)) { throw "artifact not found: $p" }
        Write-Host "Signing: $p"
        try {
            $null = Set-AuthenticodeSignature -FilePath $p -Certificate $Cert `
                -HashAlgorithm SHA256 -TimestampServer $TimestampUrl -ErrorAction Stop
        }
        catch {
            Write-Warning "  timestamping failed ($($_.Exception.Message)); signing without timestamp."
            $null = Set-AuthenticodeSignature -FilePath $p -Certificate $Cert `
                -HashAlgorithm SHA256 -ErrorAction Stop
        }
        $sig = Get-AuthenticodeSignature -FilePath $p
        if ($null -eq $sig.SignerCertificate) {
            Write-Host "  FAILED: no signature applied to $p"
            $bad += $p
        }
        else {
            $ts = if ($sig.TimeStamperCertificate) { 'yes' } else { 'no' }
            Write-Host ("  OK: status={0} timestamped={1}" -f $sig.Status, $ts)
        }
    }
    return $bad
}

if ($Mode -eq 'simulate') {
    Write-Host "=== Talos code-signing SIMULATION (non-production, self-signed) ==="
    # Throwaway certificate: created, used, and deleted within this run.
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject 'CN=Talos EPP CI Test Signing (DO NOT TRUST)' `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy Exportable `
        -KeyUsage DigitalSignature `
        -NotAfter (Get-Date).AddDays(1)
    try {
        $bad = @(Invoke-Signing -Cert $cert -Paths $Path -TimestampUrl $TimestampUrl)
    }
    finally {
        Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $cert.Thumbprint) -Force -ErrorAction SilentlyContinue
    }
    if ($bad.Count) { throw "Code-signing simulation FAILED for: $($bad -join ', ')" }
    Write-Host "=== Simulation OK: all artifacts are signable and a signature was applied. ==="
    return
}

# -Mode production: sign for real and keep the signature.
$cleanup = $null
if ($env:TALOS_SIGNING_PFX_BASE64) {
    Write-Host "=== Talos code-signing (supplied certificate from TALOS_SIGNING_PFX_BASE64) ==="
    $pfxPath = Join-Path ([IO.Path]::GetTempPath()) ("talos-sign-" + [Guid]::NewGuid().ToString('N') + ".pfx")
    [IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($env:TALOS_SIGNING_PFX_BASE64))
    $cleanup = $pfxPath
    if ($env:TALOS_SIGNING_PFX_PASSWORD) {
        $pw = ConvertTo-SecureString $env:TALOS_SIGNING_PFX_PASSWORD -AsPlainText -Force
        $cert = Get-PfxCertificate -FilePath $pfxPath -Password $pw
    }
    else {
        $cert = Get-PfxCertificate -FilePath $pfxPath
    }
}
else {
    Write-Host "=== Talos code-signing (generated self-signed — untrusted; no signing secret set) ==="
    # A real publisher identity (not the 'DO NOT TRUST' simulate subject) so the
    # released binaries show a consistent "Talos Security" publisher. Untrusted
    # until the .cer is added to Trusted Publishers or a CA cert is supplied.
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject 'CN=Talos Security' `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy Exportable `
        -KeyUsage DigitalSignature `
        -NotAfter (Get-Date).AddYears(3)
    $cleanup = "Cert:\CurrentUser\My\" + $cert.Thumbprint
}

try {
    $bad = @(Invoke-Signing -Cert $cert -Paths $Path -TimestampUrl $TimestampUrl)
}
finally {
    if ($cleanup) { Remove-Item -LiteralPath $cleanup -Force -ErrorAction SilentlyContinue }
}
if ($bad.Count) { throw "Code-signing FAILED for: $($bad -join ', ')" }
Write-Host "=== Signing OK: all artifacts signed. ==="
