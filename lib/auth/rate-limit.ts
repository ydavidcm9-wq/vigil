import { getRedisClient } from "@/lib/cache/redis-client";

interface RateLimitInput {
  namespace: string;
  key: string;
  windowSec: number;
  maxAttempts: number;
}

interface RateLimitResult {
  allowed: boolean;
  retryAfter?: number;
  remaining: number;
  backend: "redis" | "memory";
}

const memoryRateLimit = new Map<string, { count: number; resetAt: number }>();

function consumeMemoryLimit(input: RateLimitInput): RateLimitResult {
  const now = Date.now();
  const mapKey = `${input.namespace}:${input.key}`;
  const current = memoryRateLimit.get(mapKey);
  const windowMs = input.windowSec * 1000;

  if (!current || now > current.resetAt) {
    memoryRateLimit.set(mapKey, { count: 1, resetAt: now + windowMs });
    return {
      allowed: true,
      remaining: Math.max(0, input.maxAttempts - 1),
      backend: "memory",
    };
  }

  if (current.count >= input.maxAttempts) {
    return {
      allowed: false,
      retryAfter: Math.max(1, Math.ceil((current.resetAt - now) / 1000)),
      remaining: 0,
      backend: "memory",
    };
  }

  current.count += 1;
  return {
    allowed: true,
    remaining: Math.max(0, input.maxAttempts - current.count),
    backend: "memory",
  };
}

export async function consumeRateLimit(
  input: RateLimitInput
): Promise<RateLimitResult> {
  const redis = await getRedisClient();
  const redisKey = `rate_limit:${input.namespace}:${input.key}`;

  if (redis) {
    try {
      const count = await redis.incr(redisKey);
      if (count === 1) {
        await redis.expire(redisKey, input.windowSec);
      }
      const ttl = await redis.ttl(redisKey);
      const retryAfter = ttl > 0 ? ttl : input.windowSec;
      if (count > input.maxAttempts) {
        return {
          allowed: false,
          retryAfter,
          remaining: 0,
          backend: "redis",
        };
      }
      return {
        allowed: true,
        remaining: Math.max(0, input.maxAttempts - count),
        backend: "redis",
      };
    } catch (err) {
      console.error("[auth/rate-limit] redis warning:", (err as Error).message);
    }
  }

  return consumeMemoryLimit(input);
}

export async function clearRateLimit(
  namespace: string,
  key: string
): Promise<void> {
  const redis = await getRedisClient();
  const redisKey = `rate_limit:${namespace}:${key}`;
  if (redis) {
    try {
      await redis.del(redisKey);
      return;
    } catch (err) {
      console.error("[auth/rate-limit] redis clear warning:", (err as Error).message);
    }
  }
  memoryRateLimit.delete(`${namespace}:${key}`);
}
