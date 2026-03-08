import crypto from "crypto";
import { execute, queryOne } from "@/lib/db/pool";
import { getRedisClient } from "@/lib/cache/redis-client";

export interface CachedResponse {
  response: string;
  sources: Array<{ title: string; source_type: string; score: number }>;
}

function redisCacheKey(userId: string, model: string, cacheKey: string): string {
  return `ai:resp:v1:${userId}:${model}:${cacheKey}`;
}

function parseRedisCachedResponse(raw: string | null): CachedResponse | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as CachedResponse;
    if (!parsed || typeof parsed.response !== "string") return null;
    return {
      response: parsed.response,
      sources: Array.isArray(parsed.sources) ? parsed.sources : [],
    };
  } catch {
    return null;
  }
}

export async function ensureAiResponseCacheTable(): Promise<void> {
  await execute(`
    CREATE TABLE IF NOT EXISTS ai_response_cache (
      user_id UUID NOT NULL,
      model TEXT NOT NULL,
      cache_key TEXT NOT NULL,
      response TEXT NOT NULL,
      sources JSONB NOT NULL DEFAULT '[]'::jsonb,
      hits INT NOT NULL DEFAULT 0,
      last_hit_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      PRIMARY KEY (user_id, model, cache_key)
    )
  `);

  await execute(`
    CREATE INDEX IF NOT EXISTS idx_ai_response_cache_expiry
    ON ai_response_cache (expires_at)
  `);
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(obj[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function buildChatCacheKey(input: {
  message: string;
  history: Array<{ role: string; content: string }>;
}): string {
  const normalized = stableStringify({
    message: input.message.trim(),
    history: input.history.map((item) => ({
      role: item.role,
      content: item.content.trim(),
    })),
  });

  return crypto.createHash("sha256").update(normalized).digest("hex");
}

export async function getCachedResponse(
  userId: string,
  model: string,
  cacheKey: string
): Promise<CachedResponse | null> {
  const redis = await getRedisClient();
  if (redis) {
    const cached = parseRedisCachedResponse(
      await redis.get(redisCacheKey(userId, model, cacheKey)).catch(() => null)
    );
    if (cached) {
      return cached;
    }
  }

  const row = await queryOne<{
    response: string;
    sources: Array<{ title: string; source_type: string; score: number }> | null;
  }>(
    `SELECT response, sources
     FROM ai_response_cache
     WHERE user_id = $1
       AND model = $2
       AND cache_key = $3
       AND expires_at > NOW()`,
    [userId, model, cacheKey]
  );

  if (!row) return null;

  await execute(
    `UPDATE ai_response_cache
     SET hits = hits + 1,
         last_hit_at = NOW()
     WHERE user_id = $1 AND model = $2 AND cache_key = $3`,
    [userId, model, cacheKey]
  );

  const value = {
    response: row.response,
    sources: Array.isArray(row.sources) ? row.sources : [],
  };

  if (redis) {
    await redis
      .set(redisCacheKey(userId, model, cacheKey), JSON.stringify(value), {
        EX: 6 * 60 * 60,
      })
      .catch(() => undefined);
  }
  return value;
}

export async function setCachedResponse(input: {
  userId: string;
  model: string;
  cacheKey: string;
  response: string;
  sources: Array<{ title: string; source_type: string; score: number }>;
  ttlSeconds?: number;
}): Promise<void> {
  const ttl = Math.max(60, Math.min(7 * 24 * 60 * 60, input.ttlSeconds ?? 6 * 60 * 60));

  await execute(
    `INSERT INTO ai_response_cache (user_id, model, cache_key, response, sources, expires_at)
     VALUES ($1, $2, $3, $4, $5::jsonb, NOW() + ($6 || ' seconds')::interval)
     ON CONFLICT (user_id, model, cache_key)
     DO UPDATE SET
       response = EXCLUDED.response,
       sources = EXCLUDED.sources,
       expires_at = EXCLUDED.expires_at,
       last_hit_at = NOW()`,
    [
      input.userId,
      input.model,
      input.cacheKey,
      input.response,
      JSON.stringify(input.sources || []),
      String(ttl),
    ]
  );

  const redis = await getRedisClient();
  if (redis) {
    await redis
      .set(
        redisCacheKey(input.userId, input.model, input.cacheKey),
        JSON.stringify({
          response: input.response,
          sources: input.sources || [],
        }),
        { EX: ttl }
      )
      .catch(() => undefined);
  }
}
