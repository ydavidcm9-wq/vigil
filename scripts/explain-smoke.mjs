#!/usr/bin/env node

/**
 * End-to-end smoke test for Explain HUD generative endpoint + cache behavior.
 */

import { readFileSync } from "fs";
import { dirname, resolve } from "path";
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
  console.error(`EXPLAIN_SMOKE_FAIL: ${message}`);
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

function assertExplainPayload(explanation) {
  assert(explanation && typeof explanation === "object", "Missing explanation payload.");
  assert(typeof explanation.headline === "string" && explanation.headline.length > 5, "Invalid headline.");
  assert(
    ["low", "medium", "high", "critical"].includes(explanation.risk_level),
    "Invalid risk_level."
  );
  assert(
    typeof explanation.what_happened === "string" && explanation.what_happened.length > 10,
    "Invalid what_happened."
  );
  assert(
    typeof explanation.why_it_matters === "string" && explanation.why_it_matters.length > 10,
    "Invalid why_it_matters."
  );
  assert(
    Array.isArray(explanation.operator_actions) && explanation.operator_actions.length >= 3,
    "operator_actions must include at least 3 actions."
  );
  assert(
    typeof explanation.suggested_note_markdown === "string" &&
      explanation.suggested_note_markdown.length > 20,
    "Invalid suggested_note_markdown."
  );
  assert(typeof explanation.model === "string" && explanation.model.length > 0, "Invalid model.");
}

async function main() {
  console.log(`[explain-smoke] Base URL: ${BASE_URL}`);

  const loginRes = await api("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  const loginBody = await loginRes.json().catch(() => ({}));
  assert(loginRes.ok, `Login failed (${loginRes.status}): ${JSON.stringify(loginBody)}`);
  assert(!loginBody.requires2FA, "2FA-enabled account is not supported by this smoke test.");

  const nonce = randomUUID();
  const input = {
    page: "/brain",
    page_title: "Autonomous Brain",
    interaction: {
      label: `Risk Velocity chart ${nonce}`,
      role: "chart",
      section: "Risk Velocity",
      text_excerpt:
        "Scan count and finding load over 14 days. Forecast level high. Critical open 2. Intel throughput rising.",
      metrics: ["Critical Open: 2", "Forecast Score: 82", "Intel Throughput: 38"],
      actions: ["Refresh", "Run Full Autopilot", "Open New Calendar Event"],
      links: ["https://www.bleepingcomputer.com/feed/"],
      clicked_at: new Date().toISOString(),
    },
    telemetry: {
      health_summary: "Services online: 3/3",
      threat_headlines: [
        "CVE actively exploited in SaaS edge proxy",
        "OAuth token replay campaign detected",
      ],
    },
  };

  const firstRes = await api("/api/ai/explain", {
    method: "POST",
    body: JSON.stringify(input),
  });
  const firstBody = await firstRes.json().catch(() => ({}));
  assert(firstRes.ok, `First explain call failed (${firstRes.status}): ${JSON.stringify(firstBody)}`);
  assertExplainPayload(firstBody?.explanation);

  const secondRes = await api("/api/ai/explain", {
    method: "POST",
    body: JSON.stringify(input),
  });
  const secondBody = await secondRes.json().catch(() => ({}));
  assert(
    secondRes.ok,
    `Second explain call failed (${secondRes.status}): ${JSON.stringify(secondBody)}`
  );
  assertExplainPayload(secondBody?.explanation);

  const firstSource = String(firstBody?.explanation?.cache_source || "unknown");
  const secondIsServerHit =
    secondBody?.explanation?.cache_hit === true &&
    String(secondBody?.explanation?.cache_source || "") === "server";
  if (firstSource === "llm" || firstSource === "server") {
    assert(secondIsServerHit, "Expected server cache hit on second explain request.");
  } else if (!secondIsServerHit) {
    console.warn(
      `[explain-smoke] Cache hit not enforced because first source was "${firstSource}" (likely fallback mode).`
    );
  }

  const forceRes = await api("/api/ai/explain", {
    method: "POST",
    body: JSON.stringify({
      ...input,
      force_refresh: true,
    }),
  });
  const forceBody = await forceRes.json().catch(() => ({}));
  assert(
    forceRes.ok,
    `Force refresh explain call failed (${forceRes.status}): ${JSON.stringify(forceBody)}`
  );
  assertExplainPayload(forceBody?.explanation);
  assert(forceBody?.explanation?.cache_hit === false, "Force refresh should bypass server cache.");

  console.log(
    JSON.stringify(
      {
        ok: true,
        first_cache_hit: Boolean(firstBody?.explanation?.cache_hit),
        first_cache_source: firstBody?.explanation?.cache_source || "unknown",
        second_cache_hit: Boolean(secondBody?.explanation?.cache_hit),
        second_cache_source: secondBody?.explanation?.cache_source || "unknown",
        force_cache_hit: Boolean(forceBody?.explanation?.cache_hit),
        force_cache_source: forceBody?.explanation?.cache_source || "unknown",
        model: firstBody?.explanation?.model || "unknown",
      },
      null,
      2
    )
  );
}

main().catch((err) => fail(err instanceof Error ? err.message : String(err)));
