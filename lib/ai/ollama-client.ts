import crypto from "crypto";
import { Ollama } from "ollama";
import { getLLMSettings } from "@/lib/settings/llm";

type Provider = "ollama" | "vllm";

interface RuntimeSettings {
  provider: Provider;
  base_url: string;
  default_model: string;
  embedding_model: string;
  temperature: number;
  request_timeout_ms: number;
  api_key: string | null;
}

let client: Ollama | null = null;
let clientHost: string | null = null;
let resolvedModelKey: string | null = null;
let resolvedModelValue: string | null = null;

const DEFAULT_CHAT_TIMEOUT_MS = 90000;
const DEFAULT_NUM_PREDICT = 120;
const DEFAULT_NUM_CTX = 2048;
const DEFAULT_KEEP_ALIVE = "45m";

const inflightOllamaChats = new Map<string, Promise<string>>();

function envProvider(): Provider {
  return process.env.LLM_PROVIDER?.trim().toLowerCase() === "vllm"
    ? "vllm"
    : "ollama";
}

function envBaseUrl(provider: Provider): string {
  if (provider === "vllm") {
    return process.env.VLLM_BASE_URL || process.env.OLLAMA_BASE_URL || "http://localhost:11434";
  }
  return process.env.OLLAMA_BASE_URL || "http://localhost:11434";
}

function envModel(provider: Provider): string {
  if (provider === "vllm") {
    return process.env.VLLM_MODEL || process.env.OLLAMA_MODEL || "qwen3:8b";
  }
  return process.env.OLLAMA_MODEL || "qwen3:8b";
}

function envEmbeddingModel(provider: Provider): string {
  if (provider === "vllm") {
    return (
      process.env.VLLM_EMBEDDING_MODEL ||
      process.env.OLLAMA_EMBEDDING_MODEL ||
      "nomic-embed-text:latest"
    );
  }
  return process.env.OLLAMA_EMBEDDING_MODEL || "nomic-embed-text:latest";
}

function envApiKey(): string | null {
  return process.env.VLLM_API_KEY?.trim() || process.env.HF_API_KEY?.trim() || null;
}

function normalizeBaseUrl(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, "");
}

function clampPositiveInt(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.floor(parsed);
}

function resolveThinkOption(): boolean | "low" | "medium" | "high" {
  const raw = (process.env.OLLAMA_THINK || "").trim().toLowerCase();
  if (raw === "true") return true;
  if (raw === "low" || raw === "medium" || raw === "high") return raw;
  return false;
}

function resolveKeepAliveOption(): string | number {
  const raw = (process.env.OLLAMA_KEEP_ALIVE || "").trim();
  if (!raw) return DEFAULT_KEEP_ALIVE;
  if (/^\d+$/.test(raw)) return Number(raw);
  return raw;
}

function isInflightDedupeEnabled(): boolean {
  const raw = (process.env.OLLAMA_DEDUPE_INFLIGHT || "true").trim().toLowerCase();
  return raw !== "false";
}

function buildInflightChatKey(input: {
  baseUrl: string;
  model: string;
  messages: Array<{ role: string; content: string }>;
  temperature: number;
  numPredict: number;
  numCtx: number;
  think: boolean | "low" | "medium" | "high";
  keepAlive: string | number;
}): string {
  return crypto.createHash("sha256").update(JSON.stringify(input)).digest("hex");
}

function modelCacheKey(settings: RuntimeSettings): string {
  return `${settings.provider}|${settings.base_url}|${settings.default_model}`;
}

async function getRuntimeSettings(): Promise<RuntimeSettings> {
  try {
    const settings = await getLLMSettings();
    return {
      provider: settings.provider,
      base_url: settings.base_url,
      default_model: settings.default_model,
      embedding_model: settings.embedding_model,
      temperature: settings.temperature,
      request_timeout_ms: settings.request_timeout_ms,
      api_key: settings.api_key,
    };
  } catch {
    const provider = envProvider();
    return {
      provider,
      base_url: envBaseUrl(provider),
      default_model: envModel(provider),
      embedding_model: envEmbeddingModel(provider),
      temperature: 0.3,
      request_timeout_ms: clampPositiveInt(
        process.env.OLLAMA_CHAT_TIMEOUT_MS || process.env.LLM_REQUEST_TIMEOUT_MS,
        DEFAULT_CHAT_TIMEOUT_MS
      ),
      api_key: envApiKey(),
    };
  }
}

async function defaultTemperature(): Promise<number> {
  const settings = await getRuntimeSettings();
  return settings.temperature ?? 0.3;
}

async function postJson(
  baseUrl: string,
  path: string,
  body: Record<string, unknown>,
  timeoutMs: number,
  apiKey: string | null = null
): Promise<Record<string, unknown>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (apiKey) headers.Authorization = `Bearer ${apiKey}`;

    const res = await fetch(`${normalizeBaseUrl(baseUrl)}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      throw new Error(
        `LLM request failed (${res.status})${errText ? `: ${errText.slice(0, 200)}` : ""}`
      );
    }
    return (await res.json()) as Record<string, unknown>;
  } catch (err) {
    if ((err as Error).name === "AbortError") {
      throw new Error(`LLM request timed out after ${timeoutMs}ms`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

async function getJson(
  baseUrl: string,
  path: string,
  timeoutMs: number,
  apiKey: string | null = null
): Promise<Record<string, unknown>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers: Record<string, string> = {};
    if (apiKey) headers.Authorization = `Bearer ${apiKey}`;
    const res = await fetch(`${normalizeBaseUrl(baseUrl)}${path}`, {
      method: "GET",
      headers,
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`LLM request failed (${res.status})`);
    }
    return (await res.json()) as Record<string, unknown>;
  } finally {
    clearTimeout(timer);
  }
}

function extractOpenAIMessageContent(payload: Record<string, unknown>): string | null {
  const choices = payload.choices;
  if (!Array.isArray(choices) || choices.length === 0) return null;
  const first = choices[0] as Record<string, unknown>;
  const message = first.message as Record<string, unknown> | undefined;
  const content = message?.content;

  if (typeof content === "string" && content.trim()) {
    return content;
  }

  if (Array.isArray(content)) {
    const parts = content
      .map((part) => {
        if (!part || typeof part !== "object") return "";
        const row = part as Record<string, unknown>;
        return typeof row.text === "string" ? row.text : "";
      })
      .filter(Boolean);
    return parts.length > 0 ? parts.join("") : null;
  }
  return null;
}

async function runChatRequest(input: {
  settings: RuntimeSettings;
  model: string;
  messages: ChatMessage[];
  temperature: number;
  timeoutMs: number;
  numPredict: number;
  numCtx: number;
}): Promise<string> {
  if (input.settings.provider === "vllm") {
    const payload = await postJson(
      input.settings.base_url,
      "/v1/chat/completions",
      {
        model: input.model,
        messages: input.messages,
        stream: false,
        temperature: input.temperature,
        max_tokens: input.numPredict,
      },
      input.timeoutMs,
      input.settings.api_key
    );
    const content = extractOpenAIMessageContent(payload);
    if (!content) {
      throw new Error("vLLM response did not include message content");
    }
    return content;
  }

  const think = resolveThinkOption();
  const keepAlive = resolveKeepAliveOption();
  const run = async (): Promise<string> => {
    const payload = await postJson(
      input.settings.base_url,
      "/api/chat",
      {
        model: input.model,
        messages: input.messages,
        stream: false,
        think,
        keep_alive: keepAlive,
        options: {
          temperature: input.temperature,
          num_predict: input.numPredict,
          num_ctx: input.numCtx,
        },
      },
      input.timeoutMs
    );

    const message = payload.message as { content?: unknown } | undefined;
    const content = typeof message?.content === "string" ? message.content : null;
    if (!content) {
      throw new Error("Ollama response did not include message content");
    }
    return content;
  };

  if (!isInflightDedupeEnabled()) {
    return run();
  }

  const inflightKey = buildInflightChatKey({
    baseUrl: normalizeBaseUrl(input.settings.base_url),
    model: input.model,
    messages: input.messages,
    temperature: input.temperature,
    numPredict: input.numPredict,
    numCtx: input.numCtx,
    think,
    keepAlive,
  });
  const pending = inflightOllamaChats.get(inflightKey);
  if (pending) return pending;

  const task = run().finally(() => {
    inflightOllamaChats.delete(inflightKey);
  });
  inflightOllamaChats.set(inflightKey, task);
  return task;
}

export async function getOllamaClient(): Promise<Ollama> {
  const settings = await getRuntimeSettings();
  if (!client || clientHost !== settings.base_url) {
    client = new Ollama({ host: settings.base_url });
    clientHost = settings.base_url;
  }
  return client;
}

export function getModel(): string {
  return resolvedModelValue || envModel(envProvider());
}

export async function resolveModel(): Promise<string> {
  const settings = await getRuntimeSettings();
  const cacheKey = modelCacheKey(settings);
  if (resolvedModelValue && resolvedModelKey === cacheKey) {
    return resolvedModelValue;
  }

  const preferred = settings.default_model || envModel(settings.provider);

  if (settings.provider === "vllm") {
    try {
      const payload = await getJson(
        settings.base_url,
        "/v1/models",
        settings.request_timeout_ms || DEFAULT_CHAT_TIMEOUT_MS,
        settings.api_key
      );
      const data = payload.data;
      if (Array.isArray(data) && data.length > 0) {
        const names = data
          .map((item) => {
            if (!item || typeof item !== "object") return null;
            const row = item as Record<string, unknown>;
            return typeof row.id === "string" ? row.id : null;
          })
          .filter((name): name is string => Boolean(name));
        if (names.length > 0) {
          const picked = names.find((name) => name === preferred) || names[0];
          resolvedModelKey = cacheKey;
          resolvedModelValue = picked;
          return picked;
        }
      }
    } catch {
      // Fallback to preferred model.
    }
    resolvedModelKey = cacheKey;
    resolvedModelValue = preferred;
    return preferred;
  }

  try {
    const ollama = await getOllamaClient();
    const list = await ollama.list();
    const names = list.models.map((m) => m.name);

    if (names.length === 0) {
      console.log("[ollama] No models found, pulling qwen3:8b...");
      await ollama.pull({ model: "qwen3:8b" });
      resolvedModelKey = cacheKey;
      resolvedModelValue = "qwen3:8b";
      return "qwen3:8b";
    }

    const exact = names.find(
      (n) => n === preferred || n.startsWith(preferred.split(":")[0] + ":")
    );

    resolvedModelKey = cacheKey;
    resolvedModelValue = exact || names[0];
    if (!exact) {
      console.log(
        `[ollama] Configured model "${preferred}" not found, using "${resolvedModelValue}"`
      );
    }
    return resolvedModelValue;
  } catch {
    resolvedModelKey = cacheKey;
    resolvedModelValue = preferred;
    return preferred;
  }
}

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export async function chat(
  messages: ChatMessage[],
  options?: { temperature?: number; stream?: boolean }
): Promise<string> {
  const settings = await getRuntimeSettings();
  const model = await resolveModel();
  const temperature = options?.temperature ?? (await defaultTemperature());
  const timeoutMs = clampPositiveInt(
    process.env.OLLAMA_CHAT_TIMEOUT_MS,
    settings.request_timeout_ms || DEFAULT_CHAT_TIMEOUT_MS
  );
  const numPredict = clampPositiveInt(
    process.env.OLLAMA_NUM_PREDICT,
    DEFAULT_NUM_PREDICT
  );
  const numCtx = clampPositiveInt(process.env.OLLAMA_NUM_CTX, DEFAULT_NUM_CTX);

  return runChatRequest({
    settings,
    model,
    messages,
    temperature,
    timeoutMs,
    numPredict,
    numCtx,
  });
}

export async function chatStream(
  messages: ChatMessage[],
  onChunk: (text: string) => void
): Promise<string> {
  const settings = await getRuntimeSettings();
  if (settings.provider === "vllm") {
    const full = await chat(messages);
    onChunk(full);
    return full;
  }

  const ollama = await getOllamaClient();
  const model = await resolveModel();
  const temperature = await defaultTemperature();
  const numPredict = clampPositiveInt(
    process.env.OLLAMA_NUM_PREDICT,
    DEFAULT_NUM_PREDICT
  );
  const numCtx = clampPositiveInt(process.env.OLLAMA_NUM_CTX, DEFAULT_NUM_CTX);
  const keepAlive = resolveKeepAliveOption();
  const stream = await ollama.chat({
    model,
    messages,
    stream: true,
    think: resolveThinkOption(),
    keep_alive: keepAlive,
    options: {
      temperature,
      num_predict: numPredict,
      num_ctx: numCtx,
    },
  });

  let fullResponse = "";
  for await (const chunk of stream) {
    const text = chunk.message.content;
    fullResponse += text;
    onChunk(text);
  }
  return fullResponse;
}

export async function isOllamaAvailable(): Promise<boolean> {
  try {
    const settings = await getRuntimeSettings();
    if (settings.provider === "vllm") {
      await getJson(
        settings.base_url,
        "/v1/models",
        settings.request_timeout_ms || DEFAULT_CHAT_TIMEOUT_MS,
        settings.api_key
      );
      return true;
    }
    const ollama = await getOllamaClient();
    await ollama.list();
    return true;
  } catch {
    return false;
  }
}

export async function listModels(): Promise<string[]> {
  try {
    const settings = await getRuntimeSettings();
    if (settings.provider === "vllm") {
      const payload = await getJson(
        settings.base_url,
        "/v1/models",
        settings.request_timeout_ms || DEFAULT_CHAT_TIMEOUT_MS,
        settings.api_key
      );
      const data = payload.data;
      if (!Array.isArray(data)) return [];
      return data
        .map((item) => {
          if (!item || typeof item !== "object") return null;
          const row = item as Record<string, unknown>;
          return typeof row.id === "string" ? row.id : null;
        })
        .filter((name): name is string => Boolean(name));
    }

    const ollama = await getOllamaClient();
    const list = await ollama.list();
    return list.models.map((m) => m.name);
  } catch {
    return [];
  }
}

export async function pullModel(model: string): Promise<void> {
  const settings = await getRuntimeSettings();
  if (settings.provider === "vllm") {
    throw new Error("Model pull is not supported for vLLM provider");
  }
  const ollama = await getOllamaClient();
  await ollama.pull({ model });
}

export async function chatWithPurpose(
  messages: ChatMessage[],
  purpose: string,
  options?: { temperature?: number }
): Promise<{ response: string; model: string; durationMs: number }> {
  const settings = await getRuntimeSettings();
  let modelName = await resolveModel();

  if (settings.provider === "ollama") {
    try {
      const { getModelCache } = await import("./model-cache");
      const cache = getModelCache();
      modelName = await cache.getModelForPurpose(purpose);
    } catch {
      // Cache unavailable, use resolved model.
    }
  }

  const start = Date.now();
  const temperature = options?.temperature ?? (await defaultTemperature());
  const timeoutMs = clampPositiveInt(
    process.env.OLLAMA_CHAT_TIMEOUT_MS,
    settings.request_timeout_ms || DEFAULT_CHAT_TIMEOUT_MS
  );
  const numPredict = clampPositiveInt(
    process.env.OLLAMA_NUM_PREDICT,
    DEFAULT_NUM_PREDICT
  );
  const numCtx = clampPositiveInt(process.env.OLLAMA_NUM_CTX, DEFAULT_NUM_CTX);
  const response = await runChatRequest({
    settings,
    model: modelName,
    messages,
    temperature,
    timeoutMs,
    numPredict,
    numCtx,
  });
  const durationMs = Date.now() - start;

  return {
    response,
    model: modelName,
    durationMs,
  };
}
