import {now, ago} from "@welshman/lib"
import {ICollection} from "./storage.js"

/**
 * Rate limit bucket tracking attempts within a time window
 */
export type RateLimitBucket = {
  attempts: number
  first_attempt: number
  last_attempt: number
}

/**
 * Rate limit configuration
 */
export type RateLimitConfig = {
  maxAttempts: number
  windowSeconds: number
}

/**
 * Check if a rate limit has been exceeded
 */
export function isRateLimited(
  bucket: RateLimitBucket | undefined,
  config: RateLimitConfig,
): boolean {
  if (!bucket) return false

  const windowStart = ago(config.windowSeconds)

  // If the bucket is outside the current window, it's not rate limited
  if (bucket.last_attempt < windowStart) {
    return false
  }

  // Check if attempts exceed the limit within the window
  return bucket.attempts >= config.maxAttempts
}

/**
 * Record an attempt and update the rate limit bucket
 */
export function recordAttempt(
  bucket: RateLimitBucket | undefined,
  config: RateLimitConfig,
): RateLimitBucket {
  const currentTime = now()
  const windowStart = ago(config.windowSeconds)

  // If no bucket exists or the bucket is outside the current window, create a new one
  if (!bucket || bucket.last_attempt < windowStart) {
    return {
      attempts: 1,
      first_attempt: currentTime,
      last_attempt: currentTime,
    }
  }

  // Increment attempts within the current window
  return {
    ...bucket,
    attempts: bucket.attempts + 1,
    last_attempt: currentTime,
  }
}

/**
 * Get remaining time until rate limit expires (in seconds)
 */
export function getRateLimitResetTime(
  bucket: RateLimitBucket | undefined,
  config: RateLimitConfig,
): number {
  if (!bucket) return 0

  const windowStart = ago(config.windowSeconds)

  if (bucket.last_attempt < windowStart) {
    return 0
  }

  const resetTime = bucket.first_attempt + config.windowSeconds
  return Math.max(0, resetTime - now())
}

/**
 * Clean up old rate limit buckets outside the window
 */
export async function cleanupRateLimits<T extends RateLimitBucket>(
  collection: ICollection<T>,
  windowSeconds: number,
): Promise<void> {
  const cutoff = ago(windowSeconds)

  for (const [key, bucket] of await collection.entries()) {
    if (bucket.last_attempt < cutoff) {
      await collection.delete(key)
    }
  }
}
