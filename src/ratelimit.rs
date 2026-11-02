//! Sliding-window rate limits per tool.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use serde::Deserialize;

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    pub calls: u32,
    pub per_secs: u64,
}

/// Remembers the timestamps of recent calls, so a burst can never exceed
/// `calls` inside any window of `per_secs` (unlike a fixed-window counter,
/// which allows up to twice that across a window boundary).
#[derive(Debug, Default)]
pub struct RateLimiter {
    windows: HashMap<String, VecDeque<Instant>>,
}

impl RateLimiter {
    pub fn try_acquire(&mut self, key: &str, limit: RateLimit, now: Instant) -> bool {
        let window = Duration::from_secs(limit.per_secs);
        let calls = self.windows.entry(key.to_owned()).or_default();
        while calls
            .front()
            .is_some_and(|&t| now.saturating_duration_since(t) >= window)
        {
            calls.pop_front();
        }
        if calls.len() >= limit.calls as usize {
            return false;
        }
        calls.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_limit_within_window_and_recovers() {
        let limit = RateLimit {
            calls: 2,
            per_secs: 10,
        };
        let mut limiter = RateLimiter::default();
        let t0 = Instant::now();
        assert!(limiter.try_acquire("t", limit, t0));
        assert!(limiter.try_acquire("t", limit, t0 + Duration::from_secs(1)));
        assert!(!limiter.try_acquire("t", limit, t0 + Duration::from_secs(9)));
        assert!(limiter.try_acquire("other", limit, t0 + Duration::from_secs(9)));
        // The first call has left the window, freeing one slot.
        assert!(limiter.try_acquire("t", limit, t0 + Duration::from_secs(10)));
        assert!(!limiter.try_acquire("t", limit, t0 + Duration::from_secs(10)));
    }
}
