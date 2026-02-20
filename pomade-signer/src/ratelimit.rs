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
