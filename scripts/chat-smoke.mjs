#!/usr/bin/env node

/**
 * End-to-end smoke test for AI chat response + persistence.
 */

import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { randomUUID } from "crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");

function loadEnvFile() {
  const envPath = resolve(ROOT, ".env.local");
  try {
    const content = readFileSync(envPath, "utf-8");
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eqIdx = trimmed.indexOf("=");
      if (eqIdx === -1) continue;
      const key = trimmed.substring(0, eqIdx).trim();
      const value = trimmed.substring(eqIdx + 1).trim().replace(/^["']|["']$/g, "");
      if (!process.env[key]) process.env[key] = value;
    }
  } catch {
    // Optional local env file.
  }
}

loadEnvFile();

const BASE_URL = process.env.BASE_URL || "http://127.0.0.1:4100";
const EMAIL = process.env.ADMIN_EMAIL || "admin@security.local";
const PASSWORD = process.env.ADMIN_PASSWORD || "changeme123";

const cookieJar = new Map();

function fail(message) {
  console.error(`CHAT_SMOKE_FAIL: ${message}`);
  process.exit(1);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function updateCookies(res) {
  const headerFn = res.headers.getSetCookie;
  const setCookies =
    typeof headerFn === "function"
      ? headerFn.call(res.headers)
      : (() => {
          const one = res.headers.get("set-cookie");
          return one ? [one] : [];
        })();

  for (const raw of setCookies) {
    const pair = raw.split(";")[0];
    const idx = pair.indexOf("=");
    if (idx === -1) continue;
    const key = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    if (key && value) cookieJar.set(key, value);
  }
}

function cookieHeader() {
  return Array.from(cookieJar.entries())
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
}

async function api(path, init = {}) {
  const headers = new Headers(init.headers || {});
  headers.set("Content-Type", "application/json");
  const cookie = cookieHeader();
  if (cookie) headers.set("Cookie", cookie);
  const method = String(init.method || "GET").toUpperCase();
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrf = cookieJar.get("security_csrf");
    if (csrf) headers.set("x-csrf-token", csrf);
  }

  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers,
  });
  updateCookies(res);
  return res;
}

async function patchLLMSettings(patch) {
  const res = await api("/api/settings/llm", {
    method: "POST",
    body: JSON.stringify(patch),
  });
  const body = await res.json().catch(() => ({}));
  assert(res.ok, `LLM settings update failed (${res.status}): ${JSON.stringify(body)}`);
  return body;
}

async function main() {
  console.log(`[chat-smoke] Base URL: ${BASE_URL}`);

  const loginRes = await api("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  const loginBody = await loginRes.json().catch(() => ({}));
  assert(loginRes.ok, `Login failed (${loginRes.status}): ${JSON.stringify(loginBody)}`);
  assert(!loginBody.requires2FA, "2FA-enabled account is not supported by this smoke test.");

  const llmSettingsRes = await api("/api/settings/llm");
  const llmSettingsBody = await llmSettingsRes.json().catch(() => ({}));
  assert(llmSettingsRes.ok, `LLM settings GET failed (${llmSettingsRes.status}): ${JSON.stringify(llmSettingsBody)}`);
  const restorePatch = {
    cache_enabled:
      typeof llmSettingsBody?.cache_enabled === "boolean" ? llmSettingsBody.cache_enabled : true,
    semantic_cache_enabled:
      typeof llmSettingsBody?.semantic_cache_enabled === "boolean" ? llmSettingsBody.semantic_cache_enabled : true,
    semantic_cache_threshold:
      typeof llmSettingsBody?.semantic_cache_threshold === "number"
        ? llmSettingsBody.semantic_cache_threshold
        : 0.9,
    cache_bypass_realtime:
      typeof llmSettingsBody?.cache_bypass_realtime === "boolean" ? llmSettingsBody.cache_bypass_realtime : true,
    cache_bypass_incident:
      typeof llmSettingsBody?.cache_bypass_incident === "boolean" ? llmSettingsBody.cache_bypass_incident : true,
  };

  let chatBody = {};
  let chatBody2 = {};
  let chatBodySeed = {};
  let chatBody3 = {};
  let degradedMode = false;
  let conversationId = "";
  let conversationId2 = "";
  let conversationId3 = "";
  let messages = [];

  try {
    await patchLLMSettings({
      cache_enabled: true,
      semantic_cache_enabled: false,
      cache_bypass_realtime: false,
      cache_bypass_incident: false,
    });

    const nonceA = randomUUID();
    const nonceB = randomUUID();
    const prompt =
      `Smoke cache check ${new Date().toISOString()} nonceA=${nonceA} nonceB=${nonceB}: ` +
      `summarize exactly 2 immediate SaaS security actions and include nonceA ${nonceA} in one line.`;

    const chatRes = await api("/api/ai/chat", {
      method: "POST",
      body: JSON.stringify({ message: prompt }),
    });
    chatBody = await chatRes.json().catch(() => ({}));
    assert(chatRes.ok, `Chat POST failed (${chatRes.status}): ${JSON.stringify(chatBody)}`);
    assert(typeof chatBody?.message === "string" && chatBody.message.length > 0, "Chat response is empty.");
    degradedMode = chatBody?.degraded === true;
    if (degradedMode) {
      console.warn("[chat-smoke] Running in degraded model mode; cache assertions are skipped.");
    }
    conversationId = chatBody?.conversation_id;
    assert(conversationId, "Chat response missing conversation_id.");

    const chatRes2 = await api("/api/ai/chat", {
      method: "POST",
      body: JSON.stringify({ message: prompt }),
    });
    chatBody2 = await chatRes2.json().catch(() => ({}));
    assert(chatRes2.ok, `Second chat POST failed (${chatRes2.status}): ${JSON.stringify(chatBody2)}`);
    assert(typeof chatBody2?.message === "string" && chatBody2.message.length > 0, "Second chat response is empty.");
    if (!degradedMode) {
      assert(chatBody2?.degraded === false, "Second chat response is degraded (model fallback).");
      assert(chatBody2?.cache_hit === true, "Second chat did not use response cache.");
      assert(chatBody2?.cache_hit_type === "exact", "Second chat should be exact cache hit.");
    }
    conversationId2 = chatBody2?.conversation_id;
    assert(conversationId2, "Second chat response missing conversation_id.");

    await patchLLMSettings({
      semantic_cache_enabled: true,
      semantic_cache_threshold: 0.7,
    });

    const semanticSeedPrompt =
      `Semantic seed ${new Date().toISOString()} nonceA=${nonceA} nonceB=${nonceB}: ` +
      `summarize exactly 2 immediate SaaS security actions and include nonceA ${nonceA} in one line.`;
    const seedRes = await api("/api/ai/chat", {
      method: "POST",
      body: JSON.stringify({ message: semanticSeedPrompt }),
    });
    chatBodySeed = await seedRes.json().catch(() => ({}));
    assert(seedRes.ok, `Semantic seed POST failed (${seedRes.status}): ${JSON.stringify(chatBodySeed)}`);
    assert(typeof chatBodySeed?.message === "string" && chatBodySeed.message.length > 0, "Semantic seed response is empty.");
    if (!degradedMode) {
      assert(chatBodySeed?.degraded === false, "Semantic seed response is degraded (model fallback).");
    }

    const semanticPrompt = semanticSeedPrompt.replace("summarize", "outline");
    const chatRes3 = await api("/api/ai/chat", {
      method: "POST",
      body: JSON.stringify({ message: semanticPrompt }),
    });
    chatBody3 = await chatRes3.json().catch(() => ({}));
    assert(chatRes3.ok, `Third chat POST failed (${chatRes3.status}): ${JSON.stringify(chatBody3)}`);
    assert(typeof chatBody3?.message === "string" && chatBody3.message.length > 0, "Third chat response is empty.");
    if (!degradedMode) {
      assert(chatBody3?.degraded === false, "Third chat response is degraded (model fallback).");
      assert(chatBody3?.cache_hit === true, "Third chat did not use cache.");
      assert(chatBody3?.cache_hit_type === "semantic", "Third chat should be semantic cache hit.");
    }
    conversationId3 = chatBody3?.conversation_id;
    assert(conversationId3, "Third chat response missing conversation_id.");

    const convRes = await api(`/api/ai/chat?conversation_id=${encodeURIComponent(conversationId)}`);
    const convBody = await convRes.json().catch(() => ({}));
    assert(convRes.ok, `Conversation GET failed (${convRes.status}).`);
    messages = Array.isArray(convBody?.messages) ? convBody.messages : [];
    const hasPrompt = messages.some(
      (message) => message?.role === "user" && String(message?.content || "").includes("Smoke cache check")
    );
    const hasAssistant = messages.some((message) => message?.role === "assistant");
    assert(hasPrompt, "Persisted user prompt not found in conversation history.");
    assert(hasAssistant, "Persisted assistant message not found in conversation history.");
  } finally {
    await patchLLMSettings(restorePatch).catch(() => {});
  }

  console.log(
    JSON.stringify(
      {
        ok: true,
        conversation_id: conversationId,
        second_conversation_id: conversationId2,
        third_conversation_id: conversationId3,
        degraded_mode: degradedMode,
        degraded: Boolean(chatBody?.degraded),
        cache_hit_first: Boolean(chatBody?.cache_hit),
        cache_hit_type_first: chatBody?.cache_hit_type || "none",
        cache_hit_second: Boolean(chatBody2?.cache_hit),
        cache_hit_type_second: chatBody2?.cache_hit_type || "none",
        cache_hit_seed: Boolean(chatBodySeed?.cache_hit),
        cache_hit_type_seed: chatBodySeed?.cache_hit_type || "none",
        cache_hit_type_third: chatBody3?.cache_hit_type || "none",
        model: chatBody?.model || "unknown",
        messages_persisted: messages.length,
      },
      null,
      2
    )
  );
}

main().catch((err) => fail(err instanceof Error ? err.message : String(err)));
