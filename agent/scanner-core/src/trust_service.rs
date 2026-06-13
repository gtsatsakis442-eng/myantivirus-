//! Cryptographic-trust + multi-source threat-intel orchestration (Module 1).
//!
//! The decision pipeline for "is this binary legitimate?", ordered cheapest-
//! first and **fail-secure** throughout:
//!
//! 1. **Native certificate validation** — ask the OS verifier first. A binary
//!    that chains to a trusted root (e.g. the Microsoft Windows Publisher) is
//!    declared [`TrustOutcome::NativelyTrusted`] with **no network overhead**.
//! 2. **Rate-limited threat intel** — for unsigned/untrusted files, a token is
//!    drawn from a [`TokenBucket`] before any request, so provider quotas are
//!    never exceeded. If the bucket is empty we fail secure immediately.
//! 3. **Tight timeout** — the (caller-supplied, network-bound) intel lookup runs
//!    on a worker thread and is abandoned after the policy timeout (default
//!    500 ms). A timeout or error fails secure to local behavioral analysis —
//!    the verdict never hangs on a slow or unreachable provider.
//!
//! Keeping the intel call as an injected closure means this orchestration carries
//! no HTTP dependency and is fully unit-testable without a network.

use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::ratelimit::TokenBucket;
use crate::trust::{CertInfo, SignatureStatus, TrustVerifier};

/// Aggregated multi-provider threat-intel result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntelSummary {
    /// True when at least one provider attests the sample is malicious.
    pub malicious: bool,
    /// Providers that returned a record for the hash.
    pub detections: u32,
    /// Providers queried.
    pub total: u32,
    /// Names of providers that had a record (for the audit trail).
    pub sources: Vec<String>,
}

/// Where the pipeline falls back when cloud reputation is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalFallback {
    /// Defer to the local static behavioral / heuristic layers.
    BehavioralAnalysis,
}

/// The outcome of a trust assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustOutcome {
    /// OS signature validated to a trusted root — legitimate, no network used.
    NativelyTrusted { cert: CertInfo },
    /// Threat intel returned a verdict.
    IntelVerdict(IntelSummary),
    /// Cloud reputation was unavailable (rate-limited, timed out, or errored);
    /// the caller must fail secure to `fallback`.
    FailSecureLocal {
        reason: String,
        fallback: LocalFallback,
    },
}

impl TrustOutcome {
    /// True when the sample is established legitimate and needs no further work.
    pub fn is_legitimate(&self) -> bool {
        matches!(self, TrustOutcome::NativelyTrusted { .. })
    }

    /// True when the pipeline fell back to local analysis (no cloud verdict).
    pub fn is_fail_secure(&self) -> bool {
        matches!(self, TrustOutcome::FailSecureLocal { .. })
    }
}

/// Policy knobs for the trust pipeline.
#[derive(Debug, Clone)]
pub struct TrustPolicy {
    /// Hard ceiling on a single threat-intel lookup.
    pub network_timeout: Duration,
    /// When `true`, only a Microsoft-published signature short-circuits as
    /// natively trusted; other valid-root signatures still go to threat intel
    /// (defense-in-depth for third-party signed malware). When `false`, any
    /// OS-trusted signature short-circuits.
    pub microsoft_fast_path_only: bool,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self {
            network_timeout: Duration::from_millis(500),
            microsoft_fast_path_only: false,
        }
    }
}

/// Orchestrates local trust verification, rate limiting, and bounded threat-intel
/// lookups. Borrows its verifier and bucket so one of each is shared process-wide.
pub struct TrustService<'a> {
    verifier: &'a dyn TrustVerifier,
    bucket: &'a TokenBucket,
    policy: TrustPolicy,
}

impl<'a> TrustService<'a> {
    pub fn new(verifier: &'a dyn TrustVerifier, bucket: &'a TokenBucket) -> Self {
        Self {
            verifier,
            bucket,
            policy: TrustPolicy::default(),
        }
    }

    pub fn with_policy(
        verifier: &'a dyn TrustVerifier,
        bucket: &'a TokenBucket,
        policy: TrustPolicy,
    ) -> Self {
        Self {
            verifier,
            bucket,
            policy,
        }
    }

    /// Assess a file. `intel` performs the (network) multi-provider lookup and
    /// is invoked **only** when local verification doesn't establish trust and a
    /// rate-limit token is available; it is bounded by the policy timeout.
    pub fn assess<F>(&self, path: &Path, intel: F) -> TrustOutcome
    where
        F: FnOnce() -> Result<IntelSummary, String> + Send + 'static,
    {
        // 1. Native certificate validation — short-circuit trusted binaries.
        if let SignatureStatus::Trusted(cert) = self.verifier.verify(path) {
            let fast_path = !self.policy.microsoft_fast_path_only || cert.is_microsoft();
            if fast_path {
                return TrustOutcome::NativelyTrusted { cert };
            }
        }

        // 2. Rate-limit gate before any outbound request.
        if !self.bucket.try_acquire() {
            return TrustOutcome::FailSecureLocal {
                reason: "threat-intel rate limit reached".to_string(),
                fallback: LocalFallback::BehavioralAnalysis,
            };
        }

        // 3. Bounded lookup; fail secure on timeout or error.
        self.run_with_timeout(intel)
    }

    fn run_with_timeout<F>(&self, intel: F) -> TrustOutcome
    where
        F: FnOnce() -> Result<IntelSummary, String> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        // Detached worker: if it overruns the deadline we stop waiting on it; the
        // underlying HTTP client carries its own hard transfer timeout too.
        thread::spawn(move || {
            let _ = tx.send(intel());
        });
        match rx.recv_timeout(self.policy.network_timeout) {
            Ok(Ok(summary)) => TrustOutcome::IntelVerdict(summary),
            Ok(Err(e)) => TrustOutcome::FailSecureLocal {
                reason: format!("threat-intel error: {e}"),
                fallback: LocalFallback::BehavioralAnalysis,
            },
            Err(_) => TrustOutcome::FailSecureLocal {
                reason: format!(
                    "threat-intel timed out after {} ms",
                    self.policy.network_timeout.as_millis()
                ),
                fallback: LocalFallback::BehavioralAnalysis,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    /// A verifier that returns a preset status, for testing the pipeline.
    struct MockVerifier(SignatureStatus);
    impl TrustVerifier for MockVerifier {
        fn verify(&self, _path: &Path) -> SignatureStatus {
            self.0.clone()
        }
    }

    fn ms_cert() -> CertInfo {
        CertInfo {
            thumbprint: "AABB".into(),
            subject: "Microsoft Windows Publisher".into(),
            issuer: None,
        }
    }

    fn malicious_summary() -> IntelSummary {
        IntelSummary {
            malicious: true,
            detections: 2,
            total: 3,
            sources: vec!["VirusTotal".into(), "MalwareBazaar".into()],
        }
    }

    #[test]
    fn trusted_binary_short_circuits_without_network() {
        let v = MockVerifier(SignatureStatus::Trusted(ms_cert()));
        let bucket = TokenBucket::new(10, 0.0);
        let svc = TrustService::new(&v, &bucket);
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);

        let outcome = svc.assess(Path::new("C:/Windows/System32/ntdll.dll"), move || {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(malicious_summary())
        });

        assert!(outcome.is_legitimate(), "{outcome:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "intel must not be queried");
    }

    #[test]
    fn unsigned_binary_gets_intel_verdict() {
        let v = MockVerifier(SignatureStatus::Unsigned);
        let bucket = TokenBucket::new(10, 0.0);
        let svc = TrustService::new(&v, &bucket);
        let outcome = svc.assess(Path::new("/tmp/x.exe"), || Ok(malicious_summary()));
        match outcome {
            TrustOutcome::IntelVerdict(s) => assert!(s.malicious),
            other => panic!("expected intel verdict, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_fails_secure_without_calling_intel() {
        let v = MockVerifier(SignatureStatus::Unsigned);
        let bucket = TokenBucket::new(0, 0.0); // no tokens
        let svc = TrustService::new(&v, &bucket);
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let outcome = svc.assess(Path::new("/tmp/x.exe"), move || {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(malicious_summary())
        });
        assert!(outcome.is_fail_secure(), "{outcome:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        if let TrustOutcome::FailSecureLocal { reason, .. } = outcome {
            assert!(reason.contains("rate limit"), "{reason}");
        }
    }

    #[test]
    fn slow_intel_times_out_and_fails_secure_promptly() {
        let v = MockVerifier(SignatureStatus::Unsigned);
        let bucket = TokenBucket::new(10, 0.0);
        let policy = TrustPolicy {
            network_timeout: Duration::from_millis(80),
            microsoft_fast_path_only: false,
        };
        let svc = TrustService::with_policy(&v, &bucket, policy);
        let started = Instant::now();
        let outcome = svc.assess(Path::new("/tmp/x.exe"), || {
            thread::sleep(Duration::from_secs(3));
            Ok(malicious_summary())
        });
        let waited = started.elapsed();
        assert!(outcome.is_fail_secure(), "{outcome:?}");
        assert!(
            waited < Duration::from_secs(1),
            "must abandon slow lookup promptly, waited {waited:?}"
        );
        if let TrustOutcome::FailSecureLocal { reason, .. } = outcome {
            assert!(reason.contains("timed out"), "{reason}");
        }
    }

    #[test]
    fn intel_error_fails_secure() {
        let v = MockVerifier(SignatureStatus::Unsigned);
        let bucket = TokenBucket::new(10, 0.0);
        let svc = TrustService::new(&v, &bucket);
        let outcome = svc.assess(Path::new("/tmp/x.exe"), || Err("network down".to_string()));
        assert!(outcome.is_fail_secure(), "{outcome:?}");
    }

    #[test]
    fn trusted_nonmicrosoft_still_queries_intel_under_strict_policy() {
        let cert = CertInfo {
            thumbprint: "CCDD".into(),
            subject: "Acme Software Inc".into(),
            issuer: None,
        };
        let v = MockVerifier(SignatureStatus::Trusted(cert));
        let bucket = TokenBucket::new(10, 0.0);
        let policy = TrustPolicy {
            network_timeout: Duration::from_millis(500),
            microsoft_fast_path_only: true,
        };
        let svc = TrustService::with_policy(&v, &bucket, policy);
        let outcome = svc.assess(Path::new("/tmp/acme.exe"), || Ok(malicious_summary()));
        // Not Microsoft + strict policy → does NOT short-circuit; consults intel.
        assert!(
            matches!(outcome, TrustOutcome::IntelVerdict(_)),
            "{outcome:?}"
        );
    }
}
