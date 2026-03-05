#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitBucket {
    pub attempts: u32,
    pub first_attempt: u64,
    pub last_attempt: u64,
}

pub struct RateLimitConfig {
    pub max_attempts: u32,
    pub window_seconds: u64,
}

pub fn is_rate_limited(bucket: Option<&RateLimitBucket>, config: &RateLimitConfig) -> bool {
    let Some(bucket) = bucket else { return false };
    let window_start = now().saturating_sub(config.window_seconds);
    bucket.last_attempt >= window_start && bucket.attempts >= config.max_attempts
}

pub fn record_attempt(
    bucket: Option<&RateLimitBucket>,
    config: &RateLimitConfig,
) -> RateLimitBucket {
    let current = now();
    let window_start = current.saturating_sub(config.window_seconds);
    match bucket {
        Some(b) if b.last_attempt >= window_start => RateLimitBucket {
            attempts: b.attempts + 1,
            last_attempt: current,
            first_attempt: b.first_attempt,
        },
        _ => RateLimitBucket {
            attempts: 1,
            first_attempt: current,
            last_attempt: current,
        },
    }
}

pub fn get_rate_limit_reset_time(
    bucket: Option<&RateLimitBucket>,
    config: &RateLimitConfig,
) -> u64 {
    let Some(bucket) = bucket else { return 0 };
    let window_start = now().saturating_sub(config.window_seconds);
    if bucket.last_attempt < window_start {
        return 0;
    }
    let reset = bucket.first_attempt + config.window_seconds;
    reset.saturating_sub(now())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> RateLimitConfig {
        RateLimitConfig {
            max_attempts: 5,
            window_seconds: 60,
        }
    }

    #[test]
    fn test_is_rate_limited_no_bucket() {
        let config = create_test_config();
        // No bucket means not rate limited
        assert!(!is_rate_limited(None, &config));
    }

    #[test]
    fn test_is_rate_limited_under_limit() {
        let config = create_test_config();
        let bucket = RateLimitBucket {
            attempts: 3,
            first_attempt: now(),
            last_attempt: now(),
        };
        assert!(!is_rate_limited(Some(&bucket), &config));
    }

    #[test]
    fn test_is_rate_limited_at_limit() {
        let config = create_test_config();
        let bucket = RateLimitBucket {
            attempts: 5,
            first_attempt: now(),
            last_attempt: now(),
        };
        assert!(is_rate_limited(Some(&bucket), &config));
    }

    #[test]
    fn test_is_rate_limited_over_limit() {
        let config = create_test_config();
        let bucket = RateLimitBucket {
            attempts: 10,
            first_attempt: now(),
            last_attempt: now(),
        };
        assert!(is_rate_limited(Some(&bucket), &config));
    }

    #[test]
    fn test_is_rate_limited_expired_window() {
        let config = create_test_config();
        let bucket = RateLimitBucket {
            attempts: 100,                            // Way over limit
            first_attempt: now().saturating_sub(120), // 2 minutes ago
            last_attempt: now().saturating_sub(120),
        };
        // Window has expired, so not rate limited
        assert!(!is_rate_limited(Some(&bucket), &config));
    }

    #[test]
    fn test_record_attempt_new_bucket() {
        let config = create_test_config();
        let current = now();

        let bucket = record_attempt(None, &config);
        assert_eq!(bucket.attempts, 1);
        assert!(bucket.first_attempt >= current);
        assert!(bucket.last_attempt >= current);
    }

    #[test]
    fn test_record_attempt_increment() {
        let config = create_test_config();
        let existing = RateLimitBucket {
            attempts: 3,
            first_attempt: now(),
            last_attempt: now(),
        };

        let bucket = record_attempt(Some(&existing), &config);
        assert_eq!(bucket.attempts, 4);
        assert_eq!(bucket.first_attempt, existing.first_attempt);
        assert!(bucket.last_attempt >= existing.last_attempt);
    }

    #[test]
    fn test_record_attempt_expired_window() {
        let config = create_test_config();
        let existing = RateLimitBucket {
            attempts: 100,
            first_attempt: now().saturating_sub(120),
            last_attempt: now().saturating_sub(120),
        };

        // Window expired, should reset
        let bucket = record_attempt(Some(&existing), &config);
        assert_eq!(bucket.attempts, 1);
        assert!(bucket.first_attempt > existing.first_attempt);
    }

    #[test]
    fn test_get_rate_limit_reset_time_no_bucket() {
        let config = create_test_config();
        assert_eq!(get_rate_limit_reset_time(None, &config), 0);
    }

    #[test]
    fn test_get_rate_limit_reset_time_expired() {
        let config = create_test_config();
        let bucket = RateLimitBucket {
            attempts: 5,
            first_attempt: now().saturating_sub(120),
            last_attempt: now().saturating_sub(120),
        };
        // Window expired, no reset needed
        assert_eq!(get_rate_limit_reset_time(Some(&bucket), &config), 0);
    }

    #[test]
    fn test_get_rate_limit_reset_time_active() {
        let config = RateLimitConfig {
            max_attempts: 5,
            window_seconds: 60,
        };
        let bucket = RateLimitBucket {
            attempts: 5,
            first_attempt: now(),
            last_attempt: now(),
        };
        let reset_time = get_rate_limit_reset_time(Some(&bucket), &config);
        // Should be approximately 60 seconds (minus any elapsed time)
        assert!(reset_time > 0);
        assert!(reset_time <= 60);
    }

    #[test]
    fn test_rate_limit_bucket_serialization() {
        let bucket = RateLimitBucket {
            attempts: 5,
            first_attempt: 1234567890,
            last_attempt: 1234567891,
        };

        let json = serde_json::to_string(&bucket).unwrap();
        let deserialized: RateLimitBucket = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.attempts, 5);
        assert_eq!(deserialized.first_attempt, 1234567890);
        assert_eq!(deserialized.last_attempt, 1234567891);
    }

    #[test]
    fn test_full_rate_limit_flow() {
        let config = RateLimitConfig {
            max_attempts: 3,
            window_seconds: 60,
        };

        // Start with no bucket
        let mut bucket: Option<RateLimitBucket> = None;

        // First 3 attempts should not be rate limited
        for i in 1..=3 {
            assert!(!is_rate_limited(bucket.as_ref(), &config));
            bucket = Some(record_attempt(bucket.as_ref(), &config));
            assert_eq!(bucket.as_ref().unwrap().attempts, i);
        }

        // 4th attempt should be rate limited
        assert!(is_rate_limited(bucket.as_ref(), &config));

        // Check reset time
        let reset = get_rate_limit_reset_time(bucket.as_ref(), &config);
        assert!(reset > 0);
        assert!(reset <= 60);
    }

    #[test]
    fn test_now() {
        let t1 = now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = now();
        assert!(t2 >= t1);
        assert!(t1 > 1_700_000_000); // Should be after 2023
    }
}
