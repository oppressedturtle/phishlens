/**
 * Redis sliding-window rate limiter for PhishLens.
 *
 * Uses a single atomic Lua script (ZREMRANGEBYSCORE + ZCARD + ZADD + PEXPIRE)
 * so concurrent requests can't race past the limit (no TOCTOU window). Each
 * caller key gets its own sorted set of request timestamps.
 */
import { redis } from "./redis";

export interface RateLimitResult {
  success: boolean;
  /** Requests remaining in the current window. */
  remaining: number;
  /** Unix epoch (ms) when the window resets / oldest entry expires. */
  reset: number;
}

// KEYS[1] = bucket key
// ARGV[1] = now (ms), ARGV[2] = window (ms), ARGV[3] = limit, ARGV[4] = member
const SCRIPT = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count < limit then
  redis.call('ZADD', key, now, member)
  redis.call('PEXPIRE', key, window)
  return {1, limit - count - 1}
end
return {0, 0}
`;

/**
 * Apply a sliding-window rate limit.
 *
 * @param key      Logical bucket key (e.g. `submit:<ipHash>`).
 * @param limit    Max requests allowed within the window.
 * @param windowMs Window length in milliseconds.
 *
 * Fails open (returns success) if Redis is unreachable — availability is
 * preferred over hard-blocking legitimate users on an infra outage.
 */
export async function rateLimit(
  key: string,
  limit: number,
  windowMs: number,
): Promise<RateLimitResult> {
  const now = Date.now();
  const member = `${now}-${Math.random().toString(36).slice(2)}`;

  try {
    const [allowed, remaining] = (await redis.eval(
      SCRIPT,
      1,
      `ratelimit:${key}`,
      now,
      windowMs,
      limit,
      member,
    )) as [number, number];

    return {
      success: allowed === 1,
      remaining,
      reset: now + windowMs,
    };
  } catch {
    // Fail open on Redis failure.
    return { success: true, remaining: limit - 1, reset: now + windowMs };
  }
}
