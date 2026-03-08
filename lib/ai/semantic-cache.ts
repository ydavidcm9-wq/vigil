import { cosineSimilarity, embedText } from "@/lib/ai/embeddings";
import { getRedisClient } from "@/lib/cache/redis-client";

type SourceRow = { title: string; source_type: string; score: number };

interface SemanticEntry {
  response: string;
  sources: SourceRow[];
  embedding: number[];
  expires_at: number;
}

function semanticIndexKey(userId: string, model: string): string {
  return `ai:sem:index:${userId}:${model}`;
}

function semanticEntryKey(userId: string, model: string, cacheKey: string): string {
  return `ai:sem:entry:${userId}:${model}:${cacheKey}`;
}

function parseEntry(raw: string | null): SemanticEntry | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as SemanticEntry;
    if (
      !parsed ||
      typeof parsed.response !== "string" ||
      !Array.isArray(parsed.embedding) ||
      parsed.embedding.length === 0 ||
      !Number.isFinite(Number(parsed.expires_at))
    ) {
      return null;
    }
    return {
      response: parsed.response,
      sources: Array.isArray(parsed.sources) ? parsed.sources : [],
      embedding: parsed.embedding.map((n) => Number(n)).filter((n) => Number.isFinite(n)),
      expires_at: Number(parsed.expires_at),
    };
  } catch {
    return null;
  }
}

export async function findSemanticCachedResponse(input: {
  userId: string;
  model: string;
  queryText: string;
  minSimilarity?: number;
  maxCandidates?: number;
}): Promise<{ response: string; sources: SourceRow[]; similarity: number } | null> {
  const redis = await getRedisClient();
  if (!redis) return null;

  const queryEmbedding = await embedText(input.queryText);
  if (!queryEmbedding) return null;

  const minSimilarity = input.minSimilarity ?? 0.93;
  const maxCandidates = Math.max(10, Math.min(300, input.maxCandidates ?? 120));
  const indexKey = semanticIndexKey(input.userId, input.model);

  let cacheKeys: string[] = [];
  try {
    cacheKeys = await redis.zRange(indexKey, 0, maxCandidates - 1, { REV: true });
  } catch {
    return null;
  }
  if (cacheKeys.length === 0) return null;

  const multi = redis.multi();
  for (const cacheKey of cacheKeys) {
    multi.get(semanticEntryKey(input.userId, input.model, cacheKey));
  }
  const rows = await multi.exec();
  if (!rows) return null;

  let best: { response: string; sources: SourceRow[]; similarity: number } | null = null;
  let stale = 0;
  const now = Date.now();

  for (let i = 0; i < rows.length; i += 1) {
    const value = rows[i] as string | null;
    const row = parseEntry(value);
    if (!row || row.expires_at <= now) {
      stale += 1;
      continue;
    }

    const similarity = cosineSimilarity(queryEmbedding, row.embedding);
    if (similarity < minSimilarity) continue;

    if (!best || similarity > best.similarity) {
      best = {
        response: row.response,
        sources: row.sources,
        similarity,
      };
    }
  }

  if (stale > 0) {
    // Best effort cleanup.
    const keep = await redis.zRange(indexKey, 0, -1).catch(() => []);
    if (Array.isArray(keep) && keep.length > 600) {
      await redis.zRemRangeByRank(indexKey, 0, keep.length - 601).catch(() => undefined);
    }
  }

  return best;
}

export async function setSemanticCachedResponse(input: {
  userId: string;
  model: string;
  cacheKey: string;
  queryText: string;
  response: string;
  sources: SourceRow[];
  ttlSeconds?: number;
}): Promise<void> {
  const redis = await getRedisClient();
  if (!redis) return;

  const embedding = await embedText(input.queryText);
  if (!embedding) return;

  const ttl = Math.max(60, Math.min(7 * 24 * 60 * 60, input.ttlSeconds ?? 6 * 60 * 60));
  const expiresAt = Date.now() + ttl * 1000;
  const entryKey = semanticEntryKey(input.userId, input.model, input.cacheKey);
  const indexKey = semanticIndexKey(input.userId, input.model);

  await redis
    .multi()
    .set(
      entryKey,
      JSON.stringify({
        response: input.response,
        sources: input.sources,
        embedding,
        expires_at: expiresAt,
      }),
      { EX: ttl }
    )
    .zAdd(indexKey, [{ score: Date.now(), value: input.cacheKey }])
    .zRemRangeByRank(indexKey, 0, -601)
    .exec();
}
