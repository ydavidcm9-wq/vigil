import { getLLMSettings } from "@/lib/settings/llm";

const EMBED_TIMEOUT_MS = 12_000;

interface EmbeddingResponse {
  embedding?: unknown;
}

function asNumberArray(value: unknown): number[] | null {
  if (!Array.isArray(value)) return null;
  const out: number[] = [];
  for (const item of value) {
    const n = Number(item);
    if (!Number.isFinite(n)) return null;
    out.push(n);
  }
  return out.length > 0 ? out : null;
}

function normalizeBaseUrl(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, "");
}

function embeddingModelFromEnv(): string {
  const value =
    process.env.VLLM_EMBEDDING_MODEL?.trim() ||
    process.env.OLLAMA_EMBEDDING_MODEL?.trim();
  return value || "nomic-embed-text:latest";
}

export async function embedText(input: string): Promise<number[] | null> {
  const trimmed = input.trim();
  if (!trimmed) return null;

  const settings = await getLLMSettings().catch(() => null);
  const provider = settings?.provider || "ollama";
  const baseUrl =
    settings?.base_url ||
    process.env.VLLM_BASE_URL ||
    process.env.OLLAMA_BASE_URL ||
    "http://localhost:11434";
  const model = settings?.embedding_model || embeddingModelFromEnv();
  const apiKey = settings?.api_key || process.env.VLLM_API_KEY || process.env.HF_API_KEY || null;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), EMBED_TIMEOUT_MS);

  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (provider === "vllm" && apiKey) {
      headers.Authorization = `Bearer ${apiKey}`;
    }

    const route =
      provider === "vllm" ? "/v1/embeddings" : "/api/embeddings";
    const body =
      provider === "vllm"
        ? JSON.stringify({
            model,
            input: trimmed.slice(0, 8000),
          })
        : JSON.stringify({
            model,
            prompt: trimmed.slice(0, 8000),
          });

    const res = await fetch(`${normalizeBaseUrl(baseUrl)}${route}`, {
      method: "POST",
      headers,
      body,
      signal: controller.signal,
    });

    if (!res.ok) return null;
    const payload = (await res.json()) as Record<string, unknown>;

    if (provider === "vllm") {
      const data = payload.data;
      const first =
        Array.isArray(data) && data.length > 0 && data[0] && typeof data[0] === "object"
          ? (data[0] as { embedding?: unknown })
          : null;
      return asNumberArray(first?.embedding ?? null);
    }
    return asNumberArray((payload as EmbeddingResponse).embedding ?? null);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export function cosineSimilarity(a: number[], b: number[]): number {
  const len = Math.min(a.length, b.length);
  if (len === 0) return 0;

  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < len; i += 1) {
    const av = a[i];
    const bv = b[i];
    dot += av * bv;
    normA += av * av;
    normB += bv * bv;
  }
  if (normA <= 0 || normB <= 0) return 0;
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}
