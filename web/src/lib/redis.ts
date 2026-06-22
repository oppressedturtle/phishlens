/**
 * ioredis singleton for PhishLens (cache + rate limiting).
 *
 * Uses the same globalThis pattern as the Prisma client so Next.js dev
 * hot-reloads don't open a new connection on every file change. Redis errors
 * are emitted (not thrown) — callers must treat failed ops as non-fatal and
 * degrade gracefully (cache miss, fail-open rate limit where appropriate).
 */
import Redis from "ioredis";
import { env } from "./env";

const globalForRedis = globalThis as unknown as { redis?: Redis };

function createRedisClient(): Redis {
  const client = new Redis(env.REDIS_URL, {
    maxRetriesPerRequest: null,
    enableOfflineQueue: false,
    lazyConnect: false,
  });

  client.on("error", (err: Error) => {
    console.error("[redis] connection error", err.message);
  });

  return client;
}

export const redis: Redis = globalForRedis.redis ?? createRedisClient();

if (env.NODE_ENV !== "production") {
  globalForRedis.redis = redis;
}

/** PING Redis — useful in healthcheck endpoints to verify the connection. */
export async function ping(): Promise<string> {
  return redis.ping();
}
