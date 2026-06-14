<#
.SYNOPSIS
    Mint a persistent self-signed code-signing certificate for Talos releases.

.DESCRIPTION
    Creates a self-signed code-signing cert and exports two files:
      * talos-signing.pfx   private key (password-protected) — used to SIGN
      * talos-signing.cer   public cert — distribute to establish TRUST
    plus talos-signing.pfx.base64, the base64 the release workflow reads.

    Run this ONCE on a trusted machine (Windows PowerShell or pwsh). Keep the
    .pfx off the repo. Add the two secrets below; every release then signs with
    this one stable identity instead of a throwaway per-run cert. Push the .cer
    to Trusted Publishers via GPO/Intune to make the signature trusted on your
    managed machines (a self-signed cert is otherwise untrusted, so Windows
    still shows "Unknown Publisher").

    When you later buy a CA/EV certificate, just replace the secret — the
    release workflow path is identical.

.EXAMPLE
    pwsh ./installer/sign/new-selfsigned-cert.ps1 -Password 'choose-a-strong-one'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$Password,
    [string]$Subject = 'CN=Talos Security',
    [int]$Years = 3,
    [string]$OutDir = '.'
)

$ErrorActionPreference = 'Stop'

$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $Subject `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -KeyExportPolicy Exportable `
    -KeyUsage DigitalSignature `
    -NotAfter (Get-Date).AddYears($Years)
try {
    $pfx = Join-Path $OutDir 'talos-signing.pfx'
    $cer = Join-Path $OutDir 'talos-signing.cer'
    $b64 = Join-Path $OutDir 'talos-signing.pfx.base64'
    $sec = ConvertTo-SecureString $Password -AsPlainText -Force
    $null = Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $sec
    $null = Export-Certificate    -Cert $cert -FilePath $cer
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($pfx)) | Set-Content -Path $b64 -NoNewline
}
finally {
    Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $cert.Thumbprint) -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Created in $OutDir :"
Write-Host "  talos-signing.pfx         private key (.pfx) — KEEP SECRET, do not commit"
Write-Host "  talos-signing.pfx.base64  base64 of the .pfx — value for the secret below"
Write-Host "  talos-signing.cer         public cert — push to Trusted Publishers (GPO/Intune)"
Write-Host ""
Write-Host "Add these repo secrets (Settings -> Secrets and variables -> Actions):"
Write-Host "  TALOS_SIGNING_PFX_BASE64    = contents of talos-signing.pfx.base64"
Write-Host "  TALOS_SIGNING_PFX_PASSWORD  = the password you just chose"
Write-Host ""
Write-Host "  gh secret set TALOS_SIGNING_PFX_BASE64   < talos-signing.pfx.base64"
Write-Host "  gh secret set TALOS_SIGNING_PFX_PASSWORD --body '<password>'"
