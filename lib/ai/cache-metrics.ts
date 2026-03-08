import { execute, queryOne, query } from "@/lib/db/pool";

export interface CacheEventInput {
  userId: string;
  provider: string;
  model: string;
  cacheHit: boolean;
  cacheHitType: "none" | "exact" | "semantic";
  degraded: boolean;
  durationMs: number;
  promptChars: number;
  responseChars: number;
  estimatedTokens: number;
  estimatedCostUsd: number;
}

export interface CacheAnalyticsSummary {
  total_requests: number;
  cache_hits: number;
  exact_hits: number;
  semantic_hits: number;
  misses: number;
  hit_ratio_pct: number;
  avg_hit_ms: number;
  avg_miss_ms: number;
  latency_saved_ms: number;
  tokens_saved: number;
  cost_saved_usd: number;
}

export interface CacheAnalyticsSeriesPoint {
  day: string;
  total_requests: number;
  exact_hits: number;
  semantic_hits: number;
  misses: number;
  avg_duration_ms: number;
}

export async function ensureAiCacheMetricsTable(): Promise<void> {
  await execute(`
    CREATE TABLE IF NOT EXISTS ai_cache_events (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      provider VARCHAR(32) NOT NULL DEFAULT 'ollama',
      model TEXT NOT NULL,
      cache_hit BOOLEAN NOT NULL DEFAULT FALSE,
      cache_hit_type VARCHAR(16) NOT NULL DEFAULT 'none' CHECK (cache_hit_type IN ('none','exact','semantic')),
      degraded BOOLEAN NOT NULL DEFAULT FALSE,
      duration_ms INTEGER NOT NULL DEFAULT 0,
      prompt_chars INTEGER NOT NULL DEFAULT 0,
      response_chars INTEGER NOT NULL DEFAULT 0,
      estimated_tokens INTEGER NOT NULL DEFAULT 0,
      estimated_cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await execute(`
    CREATE INDEX IF NOT EXISTS idx_ai_cache_events_user_created
    ON ai_cache_events (user_id, created_at DESC)
  `);
}

export async function recordCacheEvent(event: CacheEventInput): Promise<void> {
  await execute(
    `INSERT INTO ai_cache_events (
      user_id, provider, model, cache_hit, cache_hit_type, degraded,
      duration_ms, prompt_chars, response_chars, estimated_tokens, estimated_cost_usd
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [
      event.userId,
      event.provider,
      event.model,
      event.cacheHit,
      event.cacheHitType,
      event.degraded,
      Math.max(0, Math.floor(event.durationMs)),
      Math.max(0, Math.floor(event.promptChars)),
      Math.max(0, Math.floor(event.responseChars)),
      Math.max(0, Math.floor(event.estimatedTokens)),
      Math.max(0, Number(event.estimatedCostUsd || 0)),
    ]
  );
}

export async function getCacheAnalytics(
  userId: string,
  hours = 24
): Promise<{ summary: CacheAnalyticsSummary; series: CacheAnalyticsSeriesPoint[] }> {
  const boundedHours = Math.max(1, Math.min(24 * 30, Math.floor(hours)));

  const summary = await queryOne<CacheAnalyticsSummary>(
    `WITH span AS (
       SELECT *
       FROM ai_cache_events
       WHERE user_id = $1
         AND created_at >= NOW() - ($2 || ' hours')::interval
     ),
     baseline AS (
       SELECT COALESCE(AVG(duration_ms) FILTER (WHERE cache_hit = FALSE AND degraded = FALSE), 0)::numeric AS miss_avg
       FROM span
     )
     SELECT
       COUNT(*)::int AS total_requests,
       COUNT(*) FILTER (WHERE cache_hit = TRUE)::int AS cache_hits,
       COUNT(*) FILTER (WHERE cache_hit_type = 'exact')::int AS exact_hits,
       COUNT(*) FILTER (WHERE cache_hit_type = 'semantic')::int AS semantic_hits,
       COUNT(*) FILTER (WHERE cache_hit = FALSE)::int AS misses,
       COALESCE(ROUND((COUNT(*) FILTER (WHERE cache_hit = TRUE)::numeric / NULLIF(COUNT(*),0)) * 100, 2), 0)::numeric AS hit_ratio_pct,
       COALESCE(ROUND(AVG(duration_ms) FILTER (WHERE cache_hit = TRUE), 2), 0)::numeric AS avg_hit_ms,
       COALESCE(ROUND(AVG(duration_ms) FILTER (WHERE cache_hit = FALSE), 2), 0)::numeric AS avg_miss_ms,
       COALESCE(
         ROUND(
           SUM(
             CASE
               WHEN cache_hit = TRUE
               THEN GREATEST((SELECT miss_avg FROM baseline) - duration_ms, 0)
               ELSE 0
             END
           ), 2
         ),
         0
       )::numeric AS latency_saved_ms,
       COALESCE(SUM(CASE WHEN cache_hit = TRUE THEN estimated_tokens ELSE 0 END), 0)::int AS tokens_saved,
       COALESCE(ROUND(SUM(CASE WHEN cache_hit = TRUE THEN estimated_cost_usd ELSE 0 END), 6), 0)::numeric AS cost_saved_usd
     FROM span`,
    [userId, boundedHours]
  );

  const series = await query<CacheAnalyticsSeriesPoint>(
    `SELECT
       date_trunc('day', created_at)::date::text AS day,
       COUNT(*)::int AS total_requests,
       COUNT(*) FILTER (WHERE cache_hit_type = 'exact')::int AS exact_hits,
       COUNT(*) FILTER (WHERE cache_hit_type = 'semantic')::int AS semantic_hits,
       COUNT(*) FILTER (WHERE cache_hit = FALSE)::int AS misses,
       COALESCE(ROUND(AVG(duration_ms), 2), 0)::numeric AS avg_duration_ms
     FROM ai_cache_events
     WHERE user_id = $1
       AND created_at >= NOW() - ($2 || ' hours')::interval
     GROUP BY 1
     ORDER BY 1 ASC`,
    [userId, boundedHours]
  );

  return {
    summary: summary || {
      total_requests: 0,
      cache_hits: 0,
      exact_hits: 0,
      semantic_hits: 0,
      misses: 0,
      hit_ratio_pct: 0,
      avg_hit_ms: 0,
      avg_miss_ms: 0,
      latency_saved_ms: 0,
      tokens_saved: 0,
      cost_saved_usd: 0,
    },
    series,
  };
}
