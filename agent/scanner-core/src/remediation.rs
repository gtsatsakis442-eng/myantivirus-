//! Context-aware DLL / module false-positive remediation (Module 2).
//!
//! Legitimate third-party DLLs — especially after a vendor update or a fresh
//! local compile — routinely trip the static heuristic and behavioral layers
//! (they import the same process/memory APIs that malware does). Naively
//! whitelisting by **filename or path** would re-open the door to **DLL
//! side-loading / hijacking**, where an attacker drops a malicious `version.dll`
//! next to a trusted signed EXE.
//!
//! This module resolves that tension with two ideas:
//!
//! 1. **A multi-factor intersection key** — a module is only ever considered
//!    "known good" when its `path` **and** `sha256` **and**
//!    `signing-certificate thumbprint` all match a baseline entry. Any single
//!    factor on its own is never sufficient. A pinned-publisher tier additionally
//!    tolerates legitimate *updates* (same cert, new hash) without trusting an
//!    arbitrary file from that publisher dropped at a sensitive path.
//!
//! 2. **A process-context gate** — even a fully-validated module is *not*
//!    suppressed if it was loaded from a high-risk or unverified process-tree
//!    context (a temp dir, a LOLBin script host, an unknown parent). A trusted
//!    binary surfacing in a bad context is the *signature* of side-loading, so
//!    we deny the suppression and escalate to isolation instead.
//!
//! The certificate thumbprint is supplied by the caller (the platform trust
//! layer — see the `talos-trust` crate / Module 1); this module is pure decision
//! logic and carries no `unsafe` and no platform calls, so it is fully testable.

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Result, ScanError};

/// The identity of a module (DLL/EXE) presented for evaluation.
///
/// `cert_thumbprint` is `None` for an unsigned module (some legitimate
/// third-party DLLs are unsigned — those can still be pinned by exact
/// path+hash, just never by publisher).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleIdentity {
    pub path: String,
    pub sha256: String,
    pub cert_thumbprint: Option<String>,
}

impl ModuleIdentity {
    pub fn new(
        path: impl Into<String>,
        sha256: impl Into<String>,
        cert_thumbprint: Option<String>,
    ) -> Self {
        Self {
            path: path.into(),
            sha256: sha256.into(),
            cert_thumbprint: cert_thumbprint.map(|t| fold_thumbprint(&t)),
        }
    }
}

/// One known-good module in the trust baseline.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BaselineEntry {
    pub path: String,
    pub sha256: String,
    /// Signing-certificate thumbprint, or `None` for an exact-path+hash pin of
    /// an unsigned module.
    pub cert_thumbprint: Option<String>,
    /// Friendly publisher name, for reporting only.
    pub publisher: Option<String>,
}

/// How strongly a module is trusted, from the intersection of its factors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustTier {
    /// `path` + `sha256` + `thumbprint` all matched a baseline entry exactly.
    FullyValidated,
    /// The module's signing cert is a pinned trusted publisher, but its exact
    /// path+hash is not in the baseline (e.g. a fresh legitimate update).
    PublisherTrusted,
    /// No match — the module is not known-good by any factor combination.
    Unknown,
}

/// Risk of the process-tree context a module was loaded into. Ordered so the
/// **worst** wins when combining signals (`Trusted` < `Unverified` < `HighRisk`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContextRisk {
    /// Loaded from a system/Program-Files location by an expected parent.
    Trusted,
    /// Lineage or location couldn't be positively classified as safe.
    Unverified,
    /// Loaded from a temp/download dir, or by a LOLBin script host — the kind
    /// of context that characterizes side-loading and living-off-the-land.
    HighRisk,
}

/// The process-tree context in which a module was observed loading.
#[derive(Debug, Clone)]
pub struct ProcessContext {
    /// Where the module itself was loaded from.
    pub load_path: String,
    /// Ancestor process image paths, root-first (e.g. `["explorer.exe", "app.exe"]`).
    pub lineage: Vec<String>,
    pub risk: ContextRisk,
}

impl ProcessContext {
    /// Assess the context risk from the load path and the process lineage,
    /// taking the worst of the two signals.
    pub fn assess(load_path: impl Into<String>, lineage: Vec<String>) -> Self {
        let load_path = load_path.into();
        let risk = path_risk(&load_path).max(lineage_risk(&lineage));
        Self {
            load_path,
            lineage,
            risk,
        }
    }

    /// Build a context with an explicit risk (used when the caller already knows
    /// the risk from richer kernel telemetry).
    pub fn with_risk(
        load_path: impl Into<String>,
        lineage: Vec<String>,
        risk: ContextRisk,
    ) -> Self {
        Self {
            load_path: load_path.into(),
            lineage,
            risk,
        }
    }
}

/// The remediation decision for a heuristic/behavioral alert raised on a module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remediation {
    /// Validated benign activity — the alert is intercepted and suppressed.
    /// This is the false-positive fix.
    SuppressedBenign { tier: TrustTier, reason: String },
    /// A trusted module surfaced in a high-risk/unverified context — the hallmark
    /// of side-loading. Suppression is denied and the module is isolated.
    EnforceIsolation { reason: String },
    /// The module isn't known-good; the original alert flows through the normal
    /// pipeline unchanged.
    AlertStands { reason: String },
}

impl Remediation {
    /// True only when the alert was suppressed as validated-benign.
    pub fn is_suppressed(&self) -> bool {
        matches!(self, Remediation::SuppressedBenign { .. })
    }

    /// True when the decision escalates to isolation.
    pub fn enforces_isolation(&self) -> bool {
        matches!(self, Remediation::EnforceIsolation { .. })
    }

    pub fn reason(&self) -> &str {
        match self {
            Remediation::SuppressedBenign { reason, .. }
            | Remediation::EnforceIsolation { reason }
            | Remediation::AlertStands { reason } => reason,
        }
    }
}

/// The persisted baseline of known-good modules plus pinned publisher certs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TrustBaseline {
    pub entries: Vec<BaselineEntry>,
    /// Certificate thumbprints whose *updates* are tolerated (new hash, same
    /// publisher). Stored folded (uppercase, no separators).
    pub trusted_publishers: HashSet<String>,
}

impl TrustBaseline {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load the baseline from a JSON file, or an empty baseline if absent.
    pub fn load(path: impl AsRef<Path>) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Persist the baseline to a JSON file.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ScanError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| ScanError::Update(format!("serialize baseline: {e}")))?;
        std::fs::write(path, json).map_err(|e| ScanError::Io {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// Add a known-good module to the baseline (deduplicated by the full key).
    pub fn add_entry(&mut self, entry: BaselineEntry) {
        let key = (
            normalize_path(&entry.path),
            entry.sha256.to_ascii_lowercase(),
            entry.cert_thumbprint.as_deref().map(fold_thumbprint),
        );
        let exists = self.entries.iter().any(|e| {
            (
                normalize_path(&e.path),
                e.sha256.to_ascii_lowercase(),
                e.cert_thumbprint.as_deref().map(fold_thumbprint),
            ) == key
        });
        if !exists {
            self.entries.push(entry);
        }
    }

    /// Pin a publisher certificate thumbprint as update-tolerant.
    pub fn trust_publisher(&mut self, thumbprint: &str) {
        self.trusted_publishers.insert(fold_thumbprint(thumbprint));
    }

    /// Classify a module against the baseline by the intersection key.
    pub fn classify(&self, id: &ModuleIdentity) -> TrustTier {
        let want_path = normalize_path(&id.path);
        let want_hash = id.sha256.to_ascii_lowercase();
        let want_thumb = id.cert_thumbprint.as_deref().map(fold_thumbprint);

        let full_match = self.entries.iter().any(|e| {
            normalize_path(&e.path) == want_path
                && e.sha256.to_ascii_lowercase() == want_hash
                && e.cert_thumbprint.as_deref().map(fold_thumbprint) == want_thumb
        });
        if full_match {
            return TrustTier::FullyValidated;
        }

        // Publisher tolerance applies only to a *signed* module whose cert is
        // pinned — never to an unsigned one (which has no publisher to trust).
        if let Some(thumb) = &want_thumb {
            if self.trusted_publishers.contains(thumb) {
                return TrustTier::PublisherTrusted;
            }
        }
        TrustTier::Unknown
    }

    /// Decide what to do with a heuristic/behavioral alert raised on `id`,
    /// given the context it was loaded into. Call this only when an alert fired.
    pub fn evaluate(&self, id: &ModuleIdentity, ctx: &ProcessContext) -> Remediation {
        let tier = self.classify(id);
        match tier {
            TrustTier::Unknown => Remediation::AlertStands {
                reason: "module not in trust baseline — alert flows to normal pipeline".to_string(),
            },
            TrustTier::FullyValidated | TrustTier::PublisherTrusted => {
                if ctx.risk == ContextRisk::Trusted {
                    let how = match tier {
                        TrustTier::FullyValidated => "path+hash+certificate all validated",
                        _ => "pinned-publisher certificate (tolerated update)",
                    };
                    Remediation::SuppressedBenign {
                        tier,
                        reason: format!(
                            "{how}; loaded from trusted context — heuristic suppressed as benign"
                        ),
                    }
                } else {
                    Remediation::EnforceIsolation {
                        reason: format!(
                            "trusted module loaded from {} context ({}) — \
                             possible DLL side-loading; suppression denied, isolating",
                            risk_word(ctx.risk),
                            ctx.load_path
                        ),
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Risk classification (pure, host-independent)
// ---------------------------------------------------------------------------

/// Classify a load path as a trust signal. Windows-primary, but Linux system
/// dirs are recognized too.
pub fn path_risk(path: &str) -> ContextRisk {
    let p = normalize_path(path);
    const HIGH: &[&str] = &[
        "/temp/",
        "/tmp/",
        "/appdata/local/temp/",
        "/downloads/",
        "/users/public/",
        "/dev/shm/",
        "/windows/temp/",
        "/$recycle.bin/",
    ];
    const TRUSTED: &[&str] = &[
        "/program files/",
        "/program files (x86)/",
        "/windows/system32/",
        "/windows/syswow64/",
        "/windows/winsxs/",
        // The Windows directory itself (explorer.exe, etc.); high-risk subdirs
        // like \Windows\Temp are caught by the HIGH check above, which runs first.
        "/windows/",
        "/usr/lib/",
        "/usr/bin/",
        "/usr/sbin/",
        "/lib/",
        "/bin/",
        "/sbin/",
    ];
    if HIGH.iter().any(|h| p.contains(h)) {
        ContextRisk::HighRisk
    } else if TRUSTED.iter().any(|t| p.contains(t)) {
        ContextRisk::Trusted
    } else {
        ContextRisk::Unverified
    }
}

/// Classify the process lineage. A LOLBin script-host ancestor, or any ancestor
/// loaded from a high-risk location, makes the whole context high-risk.
pub fn lineage_risk(lineage: &[String]) -> ContextRisk {
    if lineage.is_empty() {
        return ContextRisk::Unverified;
    }
    // Living-off-the-land binaries frequently used to side-load / inject.
    const LOLBINS: &[&str] = &[
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "wmic.exe",
        "msbuild.exe",
        "installutil.exe",
    ];
    let mut worst = ContextRisk::Trusted;
    for image in lineage {
        let base = normalize_path(image)
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_string();
        if LOLBINS.contains(&base.as_str()) {
            return ContextRisk::HighRisk;
        }
        worst = worst.max(path_risk(image));
    }
    worst
}

// ---------------------------------------------------------------------------
// Normalization helpers
// ---------------------------------------------------------------------------

/// Normalize a path for matching: lowercase, backslashes → forward slashes,
/// collapsed duplicate slashes. Matching is case-insensitive because the
/// primary target (NTFS) is case-insensitive, and an allowlist must not be
/// bypassable by case-flipping a path.
fn normalize_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 1);
    // Lead with a slash so prefix tests like "/temp/" match a leading segment.
    out.push('/');
    let mut last_slash = true;
    for ch in path.chars() {
        let c = if ch == '\\' { '/' } else { ch };
        if c == '/' {
            if !last_slash {
                out.push('/');
            }
            last_slash = true;
        } else {
            for lc in c.to_lowercase() {
                out.push(lc);
            }
            last_slash = false;
        }
    }
    out
}

/// Fold a certificate thumbprint to a canonical form: uppercase hex, no spaces
/// or colons (thumbprints are commonly shown as `aa:bb:cc` or `AA BB CC`).
fn fold_thumbprint(t: &str) -> String {
    t.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_uppercase())
        .collect()
}

fn risk_word(r: ContextRisk) -> &'static str {
    match r {
        ContextRisk::Trusted => "trusted",
        ContextRisk::Unverified => "unverified",
        ContextRisk::HighRisk => "high-risk",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn baseline() -> TrustBaseline {
        let mut b = TrustBaseline::new();
        b.add_entry(BaselineEntry {
            path: "C:\\Program Files\\Acme\\plugin.dll".to_string(),
            sha256: h('a'),
            cert_thumbprint: Some("AA:BB:CC:DD".to_string()),
            publisher: Some("Acme Corp".to_string()),
        });
        b.trust_publisher("AA:BB:CC:DD");
        b
    }

    fn trusted_ctx() -> ProcessContext {
        ProcessContext::assess(
            "C:\\Program Files\\Acme\\plugin.dll",
            vec![
                "C:\\Windows\\explorer.exe".into(),
                "C:\\Program Files\\Acme\\app.exe".into(),
            ],
        )
    }

    #[test]
    fn intersection_key_full_match() {
        let b = baseline();
        let id = ModuleIdentity::new(
            "C:\\Program Files\\Acme\\plugin.dll",
            h('a'),
            Some("aabbccdd".to_string()),
        );
        assert_eq!(b.classify(&id), TrustTier::FullyValidated);
    }

    #[test]
    fn hash_mismatch_is_not_fully_validated() {
        let b = baseline();
        // Same path + same cert, different hash → falls back to publisher tier.
        let id = ModuleIdentity::new(
            "C:\\Program Files\\Acme\\plugin.dll",
            h('b'),
            Some("AABBCCDD".to_string()),
        );
        assert_eq!(b.classify(&id), TrustTier::PublisherTrusted);
    }

    #[test]
    fn path_mismatch_with_pinned_cert_is_publisher_trusted_not_full() {
        let b = baseline();
        // An update installed to a *different* path, same publisher cert.
        let id = ModuleIdentity::new(
            "C:\\Program Files\\Acme\\v2\\plugin.dll",
            h('a'),
            Some("AABBCCDD".to_string()),
        );
        assert_eq!(b.classify(&id), TrustTier::PublisherTrusted);
    }

    #[test]
    fn unknown_cert_is_unknown_even_at_known_path_and_hash() {
        let b = baseline();
        // Attacker drops a file with the right name but a different/forged cert
        // and different hash — never trusted.
        let id = ModuleIdentity::new(
            "C:\\Program Files\\Acme\\plugin.dll",
            h('f'),
            Some("DEADBEEF".to_string()),
        );
        assert_eq!(b.classify(&id), TrustTier::Unknown);
    }

    #[test]
    fn unsigned_module_pins_by_path_and_hash_only() {
        let mut b = TrustBaseline::new();
        b.add_entry(BaselineEntry {
            path: "/opt/app/lib/libplugin.so".to_string(),
            sha256: h('c'),
            cert_thumbprint: None,
            publisher: None,
        });
        let exact = ModuleIdentity::new("/opt/app/lib/libplugin.so", h('c'), None);
        assert_eq!(b.classify(&exact), TrustTier::FullyValidated);
        // Different hash, still unsigned → unknown (no publisher to fall back to).
        let changed = ModuleIdentity::new("/opt/app/lib/libplugin.so", h('d'), None);
        assert_eq!(b.classify(&changed), TrustTier::Unknown);
    }

    #[test]
    fn validated_in_trusted_context_is_suppressed() {
        let b = baseline();
        let id = ModuleIdentity::new(
            "C:\\Program Files\\Acme\\plugin.dll",
            h('a'),
            Some("AABBCCDD".to_string()),
        );
        let r = b.evaluate(&id, &trusted_ctx());
        assert!(r.is_suppressed(), "{r:?}");
        if let Remediation::SuppressedBenign { tier, .. } = r {
            assert_eq!(tier, TrustTier::FullyValidated);
        }
    }

    #[test]
    fn validated_in_highrisk_context_is_isolated() {
        let b = baseline();
        let id = ModuleIdentity::new(
            "C:\\Program Files\\Acme\\plugin.dll",
            h('a'),
            Some("AABBCCDD".to_string()),
        );
        // Loaded out of a temp dir by powershell — classic side-loading.
        let ctx = ProcessContext::assess(
            "C:\\Users\\bob\\AppData\\Local\\Temp\\plugin.dll",
            vec!["C:\\Windows\\System32\\powershell.exe".into()],
        );
        let r = b.evaluate(&id, &ctx);
        assert!(r.enforces_isolation(), "{r:?}");
    }

    #[test]
    fn publisher_trusted_update_suppressed_in_trusted_context() {
        let b = baseline();
        // Fresh update: new hash, same pinned cert, installed under Program Files.
        let id = ModuleIdentity::new(
            "C:\\Program Files\\Acme\\plugin.dll",
            h('e'),
            Some("AABBCCDD".to_string()),
        );
        let r = b.evaluate(&id, &trusted_ctx());
        assert!(r.is_suppressed(), "{r:?}");
        if let Remediation::SuppressedBenign { tier, .. } = r {
            assert_eq!(tier, TrustTier::PublisherTrusted);
        }
    }

    #[test]
    fn publisher_trusted_in_unverified_context_is_isolated() {
        let b = baseline();
        let id = ModuleIdentity::new(
            "D:\\random\\plugin.dll",
            h('e'),
            Some("AABBCCDD".to_string()),
        );
        let ctx = ProcessContext::assess("D:\\random\\plugin.dll", vec![]);
        assert_eq!(ctx.risk, ContextRisk::Unverified);
        let r = b.evaluate(&id, &ctx);
        assert!(r.enforces_isolation(), "{r:?}");
    }

    #[test]
    fn unknown_module_alert_stands() {
        let b = baseline();
        let id = ModuleIdentity::new("C:\\evil\\mal.dll", h('9'), Some("9999".to_string()));
        let r = b.evaluate(&id, &trusted_ctx());
        assert!(matches!(r, Remediation::AlertStands { .. }), "{r:?}");
    }

    #[test]
    fn path_risk_classification() {
        assert_eq!(
            path_risk("C:\\Windows\\System32\\ntdll.dll"),
            ContextRisk::Trusted
        );
        assert_eq!(
            path_risk("C:\\Users\\bob\\AppData\\Local\\Temp\\x.dll"),
            ContextRisk::HighRisk
        );
        assert_eq!(
            path_risk("C:\\Users\\bob\\Downloads\\x.dll"),
            ContextRisk::HighRisk
        );
        assert_eq!(path_risk("/usr/lib/libc.so.6"), ContextRisk::Trusted);
        assert_eq!(path_risk("/tmp/payload.so"), ContextRisk::HighRisk);
        assert_eq!(path_risk("D:\\games\\game.dll"), ContextRisk::Unverified);
    }

    #[test]
    fn lolbin_parent_makes_context_high_risk() {
        assert_eq!(
            lineage_risk(&["C:\\Windows\\System32\\cmd.exe".into()]),
            ContextRisk::HighRisk
        );
        assert_eq!(
            lineage_risk(&["C:\\Program Files\\App\\app.exe".into()]),
            ContextRisk::Trusted
        );
        assert_eq!(lineage_risk(&[]), ContextRisk::Unverified);
    }

    #[test]
    fn assess_takes_worst_of_path_and_lineage() {
        // Trusted load path, but a LOLBin parent → high-risk overall.
        let ctx = ProcessContext::assess(
            "C:\\Program Files\\App\\plugin.dll",
            vec!["C:\\Windows\\System32\\rundll32.exe".into()],
        );
        assert_eq!(ctx.risk, ContextRisk::HighRisk);
    }

    #[test]
    fn normalize_path_is_case_and_separator_insensitive() {
        assert_eq!(
            normalize_path("C:\\Program Files\\Acme\\PLUGIN.DLL"),
            normalize_path("c:/program files/acme/plugin.dll")
        );
    }

    #[test]
    fn fold_thumbprint_strips_separators_and_case() {
        assert_eq!(fold_thumbprint("aa:bb:cc"), "AABBCC");
        assert_eq!(fold_thumbprint("AA BB CC"), "AABBCC");
        assert_eq!(fold_thumbprint("aabbcc"), "AABBCC");
    }

    #[test]
    fn add_entry_dedupes() {
        let mut b = TrustBaseline::new();
        let e = BaselineEntry {
            path: "C:\\x\\a.dll".to_string(),
            sha256: h('a'),
            cert_thumbprint: Some("AA".to_string()),
            publisher: None,
        };
        b.add_entry(e.clone());
        b.add_entry(e);
        assert_eq!(b.entries.len(), 1);
    }

    #[test]
    fn baseline_round_trips_through_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        let b = baseline();
        b.save(&path).unwrap();
        let loaded = TrustBaseline::load(&path);
        assert_eq!(loaded.entries.len(), 1);
        assert!(loaded.trusted_publishers.contains("AABBCCDD"));
        // The loaded baseline classifies identically.
        let id = ModuleIdentity::new(
            "C:\\Program Files\\Acme\\plugin.dll",
            h('a'),
            Some("AABBCCDD".to_string()),
        );
        assert_eq!(loaded.classify(&id), TrustTier::FullyValidated);
    }
}
