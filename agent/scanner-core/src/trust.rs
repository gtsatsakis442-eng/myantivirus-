//! Platform-agnostic **code-trust verification** interface (Module 1).
//!
//! Establishing that a binary is *legitimately signed* — ideally by a trusted
//! root such as the **Microsoft Windows Publisher** — is the cheapest, highest-
//! confidence way to eliminate false positives before incurring any network or
//! heavy-analysis cost. This module defines the verifier interface and the
//! signature-status vocabulary the rest of the engine reasons about.
//!
//! The concrete OS-backed verifier is injected by the caller (`talos-agent`
//! wiring), so this crate stays `#![forbid(unsafe_code)]`: the trait here has
//! no platform calls. A [`PortableVerifier`] (pure `goblin` PE parsing) and a
//! [`NullVerifier`] are provided for non-Windows hosts and for tests.

use std::path::Path;

use goblin::pe::PE;

/// Details extracted from a code-signing certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    /// Certificate thumbprint, folded to uppercase hex with separators removed
    /// (so it compares equal to a [`crate::remediation`] baseline thumbprint).
    pub thumbprint: String,
    /// Signer subject / friendly publisher name.
    pub subject: String,
    /// Issuer common name, when available.
    pub issuer: Option<String>,
}

impl CertInfo {
    /// True when the signer is a first-party Microsoft publisher — the strongest
    /// "this is a legitimate OS/Microsoft binary" signal.
    pub fn is_microsoft(&self) -> bool {
        let s = self.subject.to_ascii_lowercase();
        s.contains("microsoft windows")
            || s.contains("microsoft corporation")
            || s.contains("microsoft windows publisher")
    }
}

/// Whether and how a file's code signature validates against the OS trust store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Signed, and the signature chains to a trusted root.
    Trusted(CertInfo),
    /// Signed, but the signature is invalid, expired, tampered, or chains to an
    /// untrusted root. `cert` carries the offending signer when it was readable.
    Untrusted {
        reason: String,
        cert: Option<CertInfo>,
    },
    /// No embedded signature at all.
    Unsigned,
    /// Verification couldn't be performed (not a PE, unreadable, or a portable
    /// verifier that can't validate the chain).
    Unknown(String),
}

impl SignatureStatus {
    pub fn is_trusted(&self) -> bool {
        matches!(self, SignatureStatus::Trusted(_))
    }

    /// The signer thumbprint, if any cert was recovered (trusted or not). This
    /// is what feeds the Module 2 trust-baseline intersection key.
    pub fn thumbprint(&self) -> Option<&str> {
        match self {
            SignatureStatus::Trusted(c) => Some(&c.thumbprint),
            SignatureStatus::Untrusted { cert: Some(c), .. } => Some(&c.thumbprint),
            _ => None,
        }
    }

    pub fn cert(&self) -> Option<&CertInfo> {
        match self {
            SignatureStatus::Trusted(c) => Some(c),
            SignatureStatus::Untrusted { cert: Some(c), .. } => Some(c),
            _ => None,
        }
    }
}

/// A code-trust verifier backed by the OS (e.g. WinVerifyTrust / Authenticode)
/// or a portable parser. `Send + Sync` so one instance can be shared across
/// scan threads behind an `Arc`.
pub trait TrustVerifier: Send + Sync {
    fn verify(&self, path: &Path) -> SignatureStatus;
}

/// A verifier that knows nothing — always returns `Unknown`. The safe default
/// when no OS verifier is wired in (fail-secure: an unknown file is never
/// treated as trusted).
pub struct NullVerifier;

impl TrustVerifier for NullVerifier {
    fn verify(&self, _path: &Path) -> SignatureStatus {
        SignatureStatus::Unknown("no OS trust verifier configured".to_string())
    }
}

/// Portable verifier: detects *presence* of an embedded Authenticode signature
/// by parsing the PE, with no OS calls and no `unsafe`.
///
/// It deliberately **cannot** assert trust: validating the certificate chain and
/// extracting the signer thumbprint require the OS verifier. A signed file is
/// therefore reported as `Unknown` ("present, unvalidated"), never `Trusted`,
/// so the fail-secure path (threat intel / behavioral analysis) still runs.
pub struct PortableVerifier;

impl TrustVerifier for PortableVerifier {
    fn verify(&self, path: &Path) -> SignatureStatus {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => return SignatureStatus::Unknown(format!("read failed: {e}")),
        };
        match PE::parse(&data) {
            Ok(pe) => {
                if crate::heuristics::is_authenticode_signed(&pe) {
                    SignatureStatus::Unknown(
                        "embedded Authenticode signature present; OS validation required"
                            .to_string(),
                    )
                } else {
                    SignatureStatus::Unsigned
                }
            }
            Err(_) => SignatureStatus::Unknown("not a PE image".to_string()),
        }
    }
}

/// OS-backed verifier using **Authenticode** via PowerShell
/// `Get-AuthenticodeSignature` — consistent with the rest of the engine, which
/// orchestrates OS capabilities through subprocesses (`netsh`, `iptables`,
/// `curl`). It validates the signature *and* the trust chain (the cmdlet reports
/// `Valid` only when the chain reaches a trusted root) and recovers the signer
/// thumbprint + subject.
///
/// On non-Windows hosts (and if PowerShell can't be run) it falls back to
/// [`PortableVerifier`], so a Linux build still answers — fail-secure — with
/// signature *presence* rather than asserting trust.
pub struct AuthenticodeVerifier;

impl TrustVerifier for AuthenticodeVerifier {
    fn verify(&self, path: &Path) -> SignatureStatus {
        match run_authenticode(path) {
            Some(output) => parse_authenticode(&output),
            None => PortableVerifier.verify(path),
        }
    }
}

/// Run `Get-AuthenticodeSignature` and return its `KEY=VALUE` lines. Windows only.
#[cfg(windows)]
fn run_authenticode(path: &Path) -> Option<String> {
    use std::process::Command;
    // Single-quote-escape for the PowerShell literal; `-LiteralPath` prevents
    // wildcard/glob interpretation of the path.
    let escaped = path.to_string_lossy().replace('\'', "''");
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         $s = Get-AuthenticodeSignature -LiteralPath '{escaped}'; \
         Write-Output ('STATUS=' + $s.Status); \
         $c = $s.SignerCertificate; \
         if ($c) {{ \
            Write-Output ('THUMB=' + $c.Thumbprint); \
            Write-Output ('SUBJECT=' + $c.Subject); \
            Write-Output ('ISSUER=' + $c.Issuer); \
         }}"
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(not(windows))]
fn run_authenticode(_path: &Path) -> Option<String> {
    None
}

/// Parse the `KEY=VALUE` output of the `Get-AuthenticodeSignature` script into a
/// [`SignatureStatus`]. Pure — unit-tested without a Windows host.
fn parse_authenticode(output: &str) -> SignatureStatus {
    let mut status = "";
    let (mut thumb, mut subject, mut issuer) = (None, None, None);
    for line in output.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("STATUS=") {
            status = v.trim();
        } else if let Some(v) = line.strip_prefix("THUMB=") {
            let folded = fold_thumbprint(v.trim());
            if !folded.is_empty() {
                thumb = Some(folded);
            }
        } else if let Some(v) = line.strip_prefix("SUBJECT=") {
            subject = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("ISSUER=") {
            let v = v.trim();
            if !v.is_empty() {
                issuer = Some(v.to_string());
            }
        }
    }

    let cert = thumb.map(|t| CertInfo {
        thumbprint: t,
        subject: subject.unwrap_or_default(),
        issuer,
    });

    // System.Management.Automation.SignatureStatus values.
    match status.to_ascii_lowercase().as_str() {
        "valid" => match cert {
            Some(c) => SignatureStatus::Trusted(c),
            // "Valid" with no recoverable signer is anomalous — don't assert trust.
            None => SignatureStatus::Unknown("valid signature but no signer cert".to_string()),
        },
        "notsigned" => SignatureStatus::Unsigned,
        "hashmismatch" => SignatureStatus::Untrusted {
            reason: "hash mismatch — file tampered after signing".to_string(),
            cert,
        },
        "nottrusted" => SignatureStatus::Untrusted {
            reason: "signature does not chain to a trusted root".to_string(),
            cert,
        },
        "notsupportedfileformat" => {
            SignatureStatus::Unknown("file format does not support Authenticode".to_string())
        }
        "" => SignatureStatus::Unknown("no status from verifier".to_string()),
        other => SignatureStatus::Untrusted {
            reason: format!("signature not valid ({other})"),
            cert,
        },
    }
}

/// Fold a thumbprint to canonical form (uppercase hex, separators removed) so it
/// compares equal to a [`crate::remediation`] baseline thumbprint.
fn fold_thumbprint(t: &str) -> String {
    t.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms() -> CertInfo {
        CertInfo {
            thumbprint: "ABCD".to_string(),
            subject: "Microsoft Windows Publisher".to_string(),
            issuer: Some("Microsoft Windows Production PCA 2011".to_string()),
        }
    }

    #[test]
    fn microsoft_publisher_recognized() {
        assert!(ms().is_microsoft());
        assert!(CertInfo {
            thumbprint: "x".into(),
            subject: "Microsoft Corporation".into(),
            issuer: None,
        }
        .is_microsoft());
        assert!(!CertInfo {
            thumbprint: "x".into(),
            subject: "Acme Software Inc".into(),
            issuer: None,
        }
        .is_microsoft());
    }

    #[test]
    fn status_helpers() {
        let t = SignatureStatus::Trusted(ms());
        assert!(t.is_trusted());
        assert_eq!(t.thumbprint(), Some("ABCD"));

        let u = SignatureStatus::Untrusted {
            reason: "expired".into(),
            cert: Some(ms()),
        };
        assert!(!u.is_trusted());
        assert_eq!(u.thumbprint(), Some("ABCD"));

        assert_eq!(SignatureStatus::Unsigned.thumbprint(), None);
        assert!(!SignatureStatus::Unsigned.is_trusted());
    }

    #[test]
    fn null_verifier_is_failsecure_unknown() {
        let v = NullVerifier;
        assert!(matches!(
            v.verify(Path::new("/whatever")),
            SignatureStatus::Unknown(_)
        ));
    }

    #[test]
    fn portable_verifier_on_non_pe_is_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("note.txt");
        std::fs::write(&p, b"not a PE file").unwrap();
        assert!(matches!(
            PortableVerifier.verify(&p),
            SignatureStatus::Unknown(_)
        ));
    }

    #[test]
    fn portable_verifier_on_missing_file_is_unknown() {
        assert!(matches!(
            PortableVerifier.verify(Path::new("/no/such/file.dll")),
            SignatureStatus::Unknown(_)
        ));
    }

    #[test]
    fn parse_valid_microsoft_signature() {
        let out = "STATUS=Valid\n\
                   THUMB=A1B2C3D4E5F6\n\
                   SUBJECT=CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, C=US\n\
                   ISSUER=CN=Microsoft Windows Production PCA 2011\n";
        match parse_authenticode(out) {
            SignatureStatus::Trusted(c) => {
                assert_eq!(c.thumbprint, "A1B2C3D4E5F6");
                assert!(c.is_microsoft());
                assert!(c.issuer.is_some());
            }
            other => panic!("expected Trusted, got {other:?}"),
        }
    }

    #[test]
    fn parse_unsigned() {
        assert_eq!(
            parse_authenticode("STATUS=NotSigned\n"),
            SignatureStatus::Unsigned
        );
    }

    #[test]
    fn parse_hash_mismatch_is_untrusted_with_cert() {
        let out = "STATUS=HashMismatch\nTHUMB=aa bb cc\nSUBJECT=CN=Acme\n";
        match parse_authenticode(out) {
            SignatureStatus::Untrusted { reason, cert } => {
                assert!(reason.contains("tampered"));
                // Thumbprint folded: separators stripped, uppercased.
                assert_eq!(cert.unwrap().thumbprint, "AABBCC");
            }
            other => panic!("expected Untrusted, got {other:?}"),
        }
    }

    #[test]
    fn parse_not_trusted_root() {
        let out = "STATUS=NotTrusted\nTHUMB=DEAD\nSUBJECT=CN=Self-Signed\n";
        assert!(matches!(
            parse_authenticode(out),
            SignatureStatus::Untrusted { .. }
        ));
    }

    #[test]
    fn parse_unknown_status_failsecure() {
        assert!(matches!(
            parse_authenticode("STATUS=UnknownError\n"),
            SignatureStatus::Untrusted { .. }
        ));
        assert!(matches!(
            parse_authenticode(""),
            SignatureStatus::Unknown(_)
        ));
        assert!(matches!(
            parse_authenticode("STATUS=NotSupportedFileFormat\n"),
            SignatureStatus::Unknown(_)
        ));
    }

    #[test]
    fn authenticode_verifier_falls_back_to_portable_off_windows() {
        // On the Linux CI/dev host run_authenticode returns None, so this must
        // behave exactly like the portable verifier (Unknown on a non-PE).
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.txt");
        std::fs::write(&p, b"plain").unwrap();
        assert!(matches!(
            AuthenticodeVerifier.verify(&p),
            SignatureStatus::Unknown(_)
        ));
    }
}
