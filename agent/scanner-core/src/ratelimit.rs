//! A thread-safe **token-bucket rate limiter** (Module 1).
//!
//! Threat-intel providers enforce strict per-minute quotas (VirusTotal's free
//! tier is famously 4 requests/minute). Hammering them gets the endpoint's key
//! throttled or banned, which would silently blind the cloud-reputation layer.
//! This bucket caps the outbound request rate locally: each lookup must acquire
//! a token, tokens refill continuously at a fixed rate, and a burst up to the
//! capacity is allowed. When the bucket is empty the caller fails secure to
//! local analysis rather than blocking or exceeding quota.

use std::sync::Mutex;
use std::time::Instant;

/// A continuously-refilling token bucket. Cheap to share across threads
/// (one short mutex hold per acquire); construct once and wrap in an `Arc`.
pub struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    state: Mutex<State>,
}

struct State {
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// A bucket holding up to `capacity` tokens, refilling `refill_per_sec`
    /// tokens each second. Starts full so the first burst is immediately served.
    pub fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            capacity: capacity as f64,
            refill_per_sec: refill_per_sec.max(0.0),
            state: Mutex::new(State {
                tokens: capacity as f64,
                last: Instant::now(),
            }),
        }
    }

    /// Convenience constructor from a per-minute quota (e.g. VirusTotal free
    /// tier = 4/min). Capacity equals the per-minute allowance (a full-minute
    /// burst), refilling smoothly so the long-run rate matches the quota.
    pub fn per_minute(requests_per_minute: u32) -> Self {
        Self::new(
            requests_per_minute.max(1),
            requests_per_minute as f64 / 60.0,
        )
    }

    /// Try to take one token. Returns `true` if a token was available.
    pub fn try_acquire(&self) -> bool {
        self.try_acquire_at(Instant::now())
    }

    /// Tokens currently available (after refill), for display/telemetry.
    pub fn available(&self) -> f64 {
        let now = Instant::now();
        let mut s = self.state.lock().unwrap();
        s.tokens = refill(
            s.tokens,
            self.capacity,
            self.refill_per_sec,
            elapsed(s.last, now),
        );
        s.last = now;
        s.tokens
    }

    fn try_acquire_at(&self, now: Instant) -> bool {
        let mut s = self.state.lock().unwrap();
        s.tokens = refill(
            s.tokens,
            self.capacity,
            self.refill_per_sec,
            elapsed(s.last, now),
        );
        s.last = now;
        if s.tokens >= 1.0 {
            s.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

fn elapsed(from: Instant, to: Instant) -> f64 {
    to.saturating_duration_since(from).as_secs_f64()
}

/// Pure refill math, split out so it can be unit-tested without a clock.
fn refill(tokens: f64, capacity: f64, rate: f64, elapsed_secs: f64) -> f64 {
    (tokens + elapsed_secs * rate).min(capacity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn refill_is_capped_at_capacity() {
        assert_eq!(refill(0.0, 4.0, 1.0, 2.0), 2.0);
        assert_eq!(refill(0.0, 4.0, 1.0, 100.0), 4.0); // capped
        assert_eq!(refill(3.5, 4.0, 1.0, 1.0), 4.0); // capped
    }

    #[test]
    fn drains_then_denies_with_no_refill() {
        let b = TokenBucket::new(3, 0.0);
        assert!(b.try_acquire());
        assert!(b.try_acquire());
        assert!(b.try_acquire());
        assert!(!b.try_acquire(), "4th acquire must fail — bucket empty");
        assert!(!b.try_acquire());
    }

    #[test]
    fn empty_bucket_denies_immediately() {
        let b = TokenBucket::new(0, 0.0);
        assert!(!b.try_acquire());
    }

    #[test]
    fn refills_over_time() {
        let start = Instant::now();
        let b = TokenBucket::new(2, 1.0); // 1 token/sec, cap 2
                                          // Drain both (refill at ~start is negligible).
        assert!(b.try_acquire_at(start));
        assert!(b.try_acquire_at(start));
        assert!(!b.try_acquire_at(start));
        // 2 seconds later, two tokens have refilled.
        let later = start + Duration::from_secs(2);
        assert!(b.try_acquire_at(later));
        assert!(b.try_acquire_at(later));
        assert!(!b.try_acquire_at(later));
    }

    #[test]
    fn per_minute_quota_allows_initial_burst() {
        let b = TokenBucket::per_minute(4);
        // Full-minute burst up to the quota is served immediately.
        for _ in 0..4 {
            assert!(b.try_acquire());
        }
        assert!(!b.try_acquire(), "5th within the minute must be throttled");
    }
}
