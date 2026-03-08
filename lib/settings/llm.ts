import { z } from "zod";
import { getSecureSetting, setSecureSetting } from "@/lib/settings/secure-store";

function envBool(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  return value.toLowerCase() !== "false";
}

function envNumber(
  value: string | undefined,
  fallback: number,
  min: number,
  max: number
): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function envInt(
  value: string | undefined,
  fallback: number,
  min: number,
  max: number
): number {
  return Math.floor(envNumber(value, fallback, min, max));
}

export const llmSettingsSchema = z.object({
  provider: z.enum(["ollama", "vllm"]).default("ollama"),
  base_url: z.string().url(),
  default_model: z.string().min(1).max(200),
  embedding_model: z.string().min(1).max(200).default("nomic-embed-text:latest"),
  api_key: z.string().min(1).max(4096).nullable().default(null),
  knowledge_enabled: z.boolean().default(true),
  knowledge_top_k: z.number().int().min(1).max(20).default(6),
  temperature: z.number().min(0).max(2).default(0.3),
  request_timeout_ms: z.number().int().min(1000).max(600000).default(120000),
  cache_enabled: z.boolean().default(true),
  cache_ttl_sec: z.number().int().min(60).max(604800).default(21600),
  semantic_cache_enabled: z.boolean().default(true),
  semantic_cache_threshold: z.number().min(0.7).max(0.999).default(0.9),
  cache_bypass_realtime: z.boolean().default(true),
  cache_bypass_incident: z.boolean().default(true),
  cost_per_1k_tokens: z.number().min(0).max(100).default(0.003),
});

export type LLMSettings = z.infer<typeof llmSettingsSchema>;
export type PublicLLMSettings = Omit<LLMSettings, "api_key"> & {
  has_api_key: boolean;
};

export function redactLLMSettings(settings: LLMSettings): PublicLLMSettings {
  const { api_key, ...rest } = settings;
  return {
    ...rest,
    has_api_key: Boolean(api_key),
  };
}

function getDefaultSettings(): LLMSettings {
  const provider =
    (process.env.LLM_PROVIDER || "").trim().toLowerCase() === "vllm"
      ? "vllm"
      : "ollama";
  const ollamaBase = process.env.OLLAMA_BASE_URL || "http://localhost:11434";
  const vllmBase = process.env.VLLM_BASE_URL || ollamaBase;
  const baseUrl = provider === "vllm" ? vllmBase : ollamaBase;
  const defaultModel =
    process.env.VLLM_MODEL || process.env.OLLAMA_MODEL || "qwen3:8b";
  const embeddingModel =
    process.env.VLLM_EMBEDDING_MODEL ||
    process.env.OLLAMA_EMBEDDING_MODEL ||
    "nomic-embed-text:latest";

  return {
    provider,
    base_url: baseUrl,
    default_model: defaultModel,
    embedding_model: embeddingModel,
    api_key:
      process.env.VLLM_API_KEY?.trim() ||
      process.env.HF_API_KEY?.trim() ||
      null,
    knowledge_enabled: true,
    knowledge_top_k: 6,
    temperature: envNumber(process.env.LLM_TEMPERATURE, 0.3, 0, 2),
    request_timeout_ms: envInt(
      process.env.OLLAMA_CHAT_TIMEOUT_MS || process.env.LLM_REQUEST_TIMEOUT_MS,
      120000,
      1000,
      600000
    ),
    cache_enabled: envBool(process.env.AI_RESPONSE_CACHE, true),
    cache_ttl_sec: envInt(
      process.env.AI_RESPONSE_CACHE_TTL_SEC,
      21600,
      60,
      604800
    ),
    semantic_cache_enabled: envBool(process.env.AI_SEMANTIC_CACHE, true),
    semantic_cache_threshold: envNumber(
      process.env.AI_SEMANTIC_SIM_THRESHOLD,
      0.9,
      0.7,
      0.999
    ),
    cache_bypass_realtime: envBool(process.env.AI_CACHE_BYPASS_REALTIME, true),
    cache_bypass_incident: envBool(process.env.AI_CACHE_BYPASS_INCIDENT, true),
    cost_per_1k_tokens: envNumber(
      process.env.AI_COST_PER_1K_TOKENS,
      0.003,
      0,
      100
    ),
  };
}

export async function getLLMSettings(): Promise<LLMSettings> {
  const raw = await getSecureSetting<unknown>("llm", getDefaultSettings());
  const parsed = llmSettingsSchema.safeParse(raw);
  if (parsed.success) return parsed.data;
  return getDefaultSettings();
}

export async function saveLLMSettings(
  input: Partial<LLMSettings>,
  updatedBy: string | null = null
): Promise<LLMSettings> {
  const current = await getLLMSettings();
  const next = llmSettingsSchema.parse({
    ...current,
    ...input,
  });
  await setSecureSetting("llm", next, updatedBy);
  return next;
}
