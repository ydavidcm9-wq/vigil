import { getLLMSettings } from "@/lib/settings/llm";

export interface OllamaRuntimeModel {
  name: string;
  size: number;
  size_vram: number;
  expires_at: string | null;
}

export interface OllamaRuntimeSnapshot {
  provider: "ollama";
  base_url: string;
  keep_alive: string;
  num_parallel: number;
  max_loaded_models: number;
  max_queue: number;
  kv_cache_type: string;
  loaded_models: number;
  models: OllamaRuntimeModel[];
  error: string | null;
}

function normalizeBaseUrl(url: string): string {
  return url.replace(/\/+$/, "");
}

function envInt(name: string, fallback: number): number {
  const parsed = Number.parseInt(process.env[name] || "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export async function getOllamaRuntimeSnapshot(): Promise<OllamaRuntimeSnapshot | null> {
  const llmSettings = await getLLMSettings().catch(() => null);
  const provider =
    llmSettings?.provider ||
    ((process.env.LLM_PROVIDER || "").trim().toLowerCase() === "vllm"
      ? "vllm"
      : "ollama");
  if (provider !== "ollama") return null;

  const baseUrl = normalizeBaseUrl(
    llmSettings?.base_url || process.env.OLLAMA_BASE_URL || "http://localhost:11434"
  );
  const keepAlive = (process.env.OLLAMA_KEEP_ALIVE || "45m").trim() || "45m";
  const snapshot: OllamaRuntimeSnapshot = {
    provider: "ollama",
    base_url: baseUrl,
    keep_alive: keepAlive,
    num_parallel: envInt("OLLAMA_NUM_PARALLEL", 2),
    max_loaded_models: envInt("OLLAMA_MAX_LOADED_MODELS", 2),
    max_queue: envInt("OLLAMA_MAX_QUEUE", 512),
    kv_cache_type: (process.env.OLLAMA_KV_CACHE_TYPE || "q8_0").trim() || "q8_0",
    loaded_models: 0,
    models: [],
    error: null,
  };

  try {
    const response = await fetch(`${baseUrl}/api/ps`, {
      signal: AbortSignal.timeout(3000),
    });
    if (!response.ok) {
      snapshot.error = `Runtime query failed (${response.status})`;
      return snapshot;
    }

    const payload = (await response.json()) as { models?: unknown };
    if (!Array.isArray(payload.models)) {
      return snapshot;
    }

    snapshot.models = payload.models
      .map((row) => {
        if (!row || typeof row !== "object") return null;
        const model = row as Record<string, unknown>;
        return {
          name: typeof model.name === "string" ? model.name : "unknown",
          size: typeof model.size === "number" ? model.size : 0,
          size_vram: typeof model.size_vram === "number" ? model.size_vram : 0,
          expires_at:
            typeof model.expires_at === "string" ? model.expires_at : null,
        };
      })
      .filter((model): model is OllamaRuntimeModel => Boolean(model));
    snapshot.loaded_models = snapshot.models.length;
    return snapshot;
  } catch (err) {
    snapshot.error = (err as Error).message || "Runtime query failed";
    return snapshot;
  }
}
