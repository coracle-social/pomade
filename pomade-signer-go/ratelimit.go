package main

import "time"

type RateLimitBucket struct {
	Attempts     uint32 `json:"attempts"`
	FirstAttempt uint64 `json:"first_attempt"`
	LastAttempt  uint64 `json:"last_attempt"`
}

type RateLimitConfig struct {
	MaxAttempts   uint32
	WindowSeconds uint64
}

func nowSec() uint64 {
	return uint64(time.Now().Unix())
}

func isRateLimited(bucket *RateLimitBucket, config RateLimitConfig) bool {
	if bucket == nil {
		return false
	}
	windowStart := nowSec() - config.WindowSeconds
	return bucket.LastAttempt >= windowStart && bucket.Attempts >= config.MaxAttempts
}

func recordAttempt(bucket *RateLimitBucket, config RateLimitConfig) RateLimitBucket {
	current := nowSec()
	windowStart := current - config.WindowSeconds
	if bucket != nil && bucket.LastAttempt >= windowStart {
		return RateLimitBucket{
			Attempts:     bucket.Attempts + 1,
			FirstAttempt: bucket.FirstAttempt,
			LastAttempt:  current,
		}
	}
	return RateLimitBucket{Attempts: 1, FirstAttempt: current, LastAttempt: current}
}
