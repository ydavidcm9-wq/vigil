import { createHash } from "crypto";
import { execute, query, queryOne } from "@/lib/db/pool";
import { getLLMSettings } from "@/lib/settings/llm";
import { embedText as embedVector } from "@/lib/ai/embeddings";

export type KnowledgeSourceType = "faq" | "note" | "conversation" | "manual";

export interface KnowledgeChunk {
  id: string;
  user_id: string;
  source_type: KnowledgeSourceType;
  source_id: string;
  title: string;
  content: string;
  tags: string[];
  chunk_index: number;
  embedding: number[] | null;
  embedding_model: string | null;
  updated_at: string;
}

export interface KnowledgeHit {
  chunk_id: string;
  source_type: KnowledgeSourceType;
  source_id: string;
  title: string;
  content: string;
  tags: string[];
  score: number;
  semantic_score: number;
  lexical_score: number;
}

const DEFAULT_CHUNK_SIZE = 900;
const DEFAULT_TOP_K = 6;
let ensured = false;

interface LlmKnowledgeSettings {
  embedding_model: string;
  knowledge_enabled: boolean;
  knowledge_top_k: number;
}

interface ChunkRow {
  id: string;
  source_type: KnowledgeSourceType;
  source_id: string;
  title: string;
  content: string;
  tags: string[] | null;
  embedding: unknown;
  updated_at: string;
}

function normalizeText(input: string): string {
  return input.replace(/\r/g, "").replace(/\s+/g, " ").trim();
}

function splitIntoChunks(content: string, chunkSize: number = DEFAULT_CHUNK_SIZE): string[] {
  const text = normalizeText(content);
  if (!text) return [];

  const chunks: string[] = [];
  let start = 0;
  while (start < text.length) {
    let end = Math.min(start + chunkSize, text.length);
    if (end < text.length) {
      const boundary = text.lastIndexOf(" ", end);
      if (boundary > start + Math.floor(chunkSize * 0.6)) {
        end = boundary;
      }
    }
    const chunk = text.slice(start, end).trim();
    if (chunk.length > 0) chunks.push(chunk);
    start = end;
  }
  return chunks;
}

function getKeywords(input: string): string[] {
  return Array.from(
    new Set(
      input
        .toLowerCase()
        .split(/[^a-z0-9]+/g)
        .filter((token) => token.length >= 3)
    )
  ).slice(0, 10);
}

function lexicalScore(content: string, title: string, keywords: string[]): number {
  if (keywords.length === 0) return 0;
  const haystack = `${title} ${content}`.toLowerCase();
  let hits = 0;
  for (const keyword of keywords) {
    if (haystack.includes(keyword)) hits += 1;
  }
  return hits / keywords.length;
}

function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length === 0 || b.length === 0 || a.length !== b.length) return 0;
  let dot = 0;
  let magA = 0;
  let magB = 0;
  for (let i = 0; i < a.length; i += 1) {
    dot += a[i] * b[i];
    magA += a[i] * a[i];
    magB += b[i] * b[i];
  }
  if (magA === 0 || magB === 0) return 0;
  return dot / (Math.sqrt(magA) * Math.sqrt(magB));
}

function parseEmbedding(raw: unknown): number[] | null {
  if (!raw) return null;
  if (Array.isArray(raw) && raw.every((v) => typeof v === "number")) {
    return raw as number[];
  }
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (Array.isArray(parsed) && parsed.every((v) => typeof v === "number")) {
        return parsed as number[];
      }
      return null;
    } catch {
      return null;
    }
  }
  return null;
}

async function getKnowledgeSettings(): Promise<LlmKnowledgeSettings> {
  const settings = await getLLMSettings();
  return {
    embedding_model: settings.embedding_model || "nomic-embed-text:latest",
    knowledge_enabled: settings.knowledge_enabled ?? true,
    knowledge_top_k: settings.knowledge_top_k ?? DEFAULT_TOP_K,
  };
}

async function embedText(text: string, model: string): Promise<number[] | null> {
  // Keep model arg for compatibility; embedding backend uses settings-selected model.
  void model;
  return embedVector(text);
}

export async function ensureAiKnowledgeTables(): Promise<void> {
  if (ensured) return;

  await execute(`
    CREATE TABLE IF NOT EXISTS ai_faq_entries (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      category VARCHAR(120) NOT NULL DEFAULT 'General',
      question TEXT NOT NULL,
      answer TEXT NOT NULL,
      tags TEXT[] NOT NULL DEFAULT '{}',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, question)
    )
  `);

  await execute(`
    CREATE TABLE IF NOT EXISTS ai_knowledge_chunks (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      source_type VARCHAR(32) NOT NULL,
      source_id TEXT NOT NULL,
      source_hash TEXT,
      title VARCHAR(255) NOT NULL,
      content TEXT NOT NULL,
      tags TEXT[] NOT NULL DEFAULT '{}',
      chunk_index INTEGER NOT NULL DEFAULT 0,
      embedding JSONB,
      embedding_model VARCHAR(200),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT ai_knowledge_source_type_check
        CHECK (source_type IN ('faq', 'note', 'conversation', 'manual'))
    )
  `);

  await execute(`
    CREATE INDEX IF NOT EXISTS idx_ai_faq_user_updated
    ON ai_faq_entries(user_id, updated_at DESC)
  `);

  await execute(`
    CREATE INDEX IF NOT EXISTS idx_ai_faq_category
    ON ai_faq_entries(user_id, category)
  `);

  await execute(`
    CREATE INDEX IF NOT EXISTS idx_ai_knowledge_user_source
    ON ai_knowledge_chunks(user_id, source_type, source_id)
  `);

  await execute(`
    CREATE INDEX IF NOT EXISTS idx_ai_knowledge_updated
    ON ai_knowledge_chunks(user_id, updated_at DESC)
  `);

  await execute(`
    CREATE INDEX IF NOT EXISTS idx_ai_knowledge_source_hash
    ON ai_knowledge_chunks(source_hash)
  `);

  ensured = true;
}

export async function removeKnowledgeSource(
  userId: string,
  sourceType: KnowledgeSourceType,
  sourceId: string
): Promise<void> {
  await ensureAiKnowledgeTables();
  await execute(
    `DELETE FROM ai_knowledge_chunks
     WHERE user_id = $1 AND source_type = $2 AND source_id = $3`,
    [userId, sourceType, sourceId]
  );
}

export async function upsertKnowledgeSource(input: {
  userId: string;
  sourceType: KnowledgeSourceType;
  sourceId: string;
  title: string;
  content: string;
  tags?: string[];
}): Promise<void> {
  await ensureAiKnowledgeTables();

  const normalizedTitle = normalizeText(input.title).slice(0, 255) || "Knowledge";
  const normalizedContent = normalizeText(input.content);
  if (!normalizedContent) {
    await removeKnowledgeSource(input.userId, input.sourceType, input.sourceId);
    return;
  }

  const contentHash = createHash("sha256")
    .update(`${normalizedTitle}\n${normalizedContent}`)
    .digest("hex");

  const existing = await queryOne<{ source_hash: string | null }>(
    `SELECT source_hash
     FROM ai_knowledge_chunks
     WHERE user_id = $1 AND source_type = $2 AND source_id = $3
     LIMIT 1`,
    [input.userId, input.sourceType, input.sourceId]
  );

  if (existing?.source_hash === contentHash) {
    return;
  }

  await removeKnowledgeSource(input.userId, input.sourceType, input.sourceId);

  const chunks = splitIntoChunks(normalizedContent);
  if (chunks.length === 0) return;

  const settings = await getKnowledgeSettings();
  const tags = (input.tags || []).slice(0, 16);

  for (let i = 0; i < chunks.length; i += 1) {
    const chunkContent = chunks[i];
    const embedding = settings.knowledge_enabled
      ? await embedText(chunkContent, settings.embedding_model)
      : null;

    await execute(
      `INSERT INTO ai_knowledge_chunks (
        user_id, source_type, source_id, source_hash, title, content, tags, chunk_index, embedding, embedding_model
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7::text[], $8, $9::jsonb, $10)`,
      [
        input.userId,
        input.sourceType,
        input.sourceId,
        contentHash,
        normalizedTitle,
        chunkContent,
        tags,
        i,
        embedding ? JSON.stringify(embedding) : null,
        embedding ? settings.embedding_model : null,
      ]
    );
  }
}

export async function appendConversationKnowledge(input: {
  userId: string;
  conversationId: string;
  title: string;
  userMessage: string;
  assistantMessage: string;
}): Promise<void> {
  const sourceId = `${input.conversationId}:${Date.now()}`;
  await upsertKnowledgeSource({
    userId: input.userId,
    sourceType: "conversation",
    sourceId,
    title: input.title || "Conversation",
    content: `User:\n${input.userMessage}\n\nAssistant:\n${input.assistantMessage}`,
    tags: ["chat", "conversation"],
  });
}

export async function purgeConversationKnowledge(
  userId: string,
  conversationId: string
): Promise<void> {
  await ensureAiKnowledgeTables();
  await execute(
    `DELETE FROM ai_knowledge_chunks
     WHERE user_id = $1
       AND source_type = 'conversation'
       AND source_id LIKE $2`,
    [userId, `${conversationId}:%`]
  );
}

export async function searchKnowledge(
  userId: string,
  userQuery: string,
  options?: { topK?: number; sourceTypes?: KnowledgeSourceType[] }
): Promise<KnowledgeHit[]> {
  await ensureAiKnowledgeTables();

  const cleanedQuery = normalizeText(userQuery);
  if (!cleanedQuery) return [];

  const settings = await getKnowledgeSettings();
  const topK = Math.max(1, Math.min(options?.topK ?? settings.knowledge_top_k ?? DEFAULT_TOP_K, 20));
  const keywords = getKeywords(cleanedQuery);
  const filteredSourceTypes = options?.sourceTypes?.length
    ? options.sourceTypes
    : null;

  const params: unknown[] = [userId];
  const predicates: string[] = ["user_id = $1"];
  let paramIdx = 2;

  if (filteredSourceTypes) {
    params.push(filteredSourceTypes);
    predicates.push(`source_type = ANY($${paramIdx}::text[])`);
    paramIdx += 1;
  }

  if (keywords.length > 0) {
    const keywordClauses: string[] = [];
    for (const keyword of keywords) {
      params.push(`%${keyword}%`);
      keywordClauses.push(
        `(title ILIKE $${paramIdx} OR content ILIKE $${paramIdx})`
      );
      paramIdx += 1;
    }
    predicates.push(`(${keywordClauses.join(" OR ")})`);
  }

  params.push(180);
  const sql = `
    SELECT id, source_type, source_id, title, content, tags, embedding, updated_at
    FROM ai_knowledge_chunks
    WHERE ${predicates.join(" AND ")}
    ORDER BY updated_at DESC
    LIMIT $${paramIdx}
  `;

  let rows = await query<ChunkRow>(sql, params);
  if (rows.length === 0 && keywords.length > 0) {
    // Fallback: broad recency query when keyword filter is too narrow.
    rows = await query<ChunkRow>(
      `SELECT id, source_type, source_id, title, content, tags, embedding, updated_at
       FROM ai_knowledge_chunks
       WHERE user_id = $1
       ORDER BY updated_at DESC
       LIMIT 120`,
      [userId]
    );
  }

  if (rows.length === 0) return [];

  const queryEmbedding = settings.knowledge_enabled
    ? await embedText(cleanedQuery, settings.embedding_model)
    : null;

  const scored = rows.map<KnowledgeHit>((row) => {
    const lexical = lexicalScore(row.content, row.title, keywords);
    const semantic = queryEmbedding
      ? cosineSimilarity(queryEmbedding, parseEmbedding(row.embedding) || [])
      : 0;

    const score = semantic > 0
      ? semantic * 0.72 + lexical * 0.28
      : lexical;

    return {
      chunk_id: row.id,
      source_type: row.source_type,
      source_id: row.source_id,
      title: row.title,
      content: row.content,
      tags: row.tags || [],
      score,
      semantic_score: semantic,
      lexical_score: lexical,
    };
  });

  return scored.sort((a, b) => b.score - a.score).slice(0, topK);
}

export function buildKnowledgeContext(hits: KnowledgeHit[]): string {
  if (hits.length === 0) return "";
  const lines: string[] = [
    "Use relevant local knowledge below when it helps the current user request.",
    "If a knowledge item is not relevant, ignore it.",
  ];

  for (const hit of hits) {
    lines.push(
      `- [${hit.source_type.toUpperCase()}] ${hit.title}: ${hit.content}`
    );
  }
  return lines.join("\n");
}
