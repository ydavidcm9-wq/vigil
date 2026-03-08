#!/usr/bin/env node

/**
 * Beta breaker:
 * sustained concurrent API traffic + periodic autonomous campaign launches.
 * Goal: expose race conditions, auth/session faults, timeout behavior, and queue pressure.
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
const PRIMARY_TARGET_URL = process.env.PRIMARY_TARGET_URL || "https://example.com";
const SECONDARY_TARGET_URL =
  process.env.SECONDARY_TARGET_URL || "https://demo.example.com";

const DURATION_SEC = Math.max(
  60,
  Number.parseInt(process.env.STRESS_DURATION_SEC || "420", 10) || 420
);
const CONCURRENCY = Math.max(
  2,
  Number.parseInt(process.env.STRESS_CONCURRENCY || "10", 10) || 10
);
const CAMPAIGN_INTERVAL_SEC = Math.max(
  20,
  Number.parseInt(process.env.STRESS_CAMPAIGN_INTERVAL_SEC || "75", 10) || 75
);

const cookieJar = new Map();
const csrfHeaderName = "x-csrf-token";
const deadline = Date.now() + DURATION_SEC * 1000;
let stop = false;

const stats = {
  started_at: new Date().toISOString(),
  duration_sec: DURATION_SEC,
  concurrency: CONCURRENCY,
  total_requests: 0,
  total_ok: 0,
  total_fail: 0,
  by_endpoint: {},
  errors: [],
  campaign_launches: 0,
  campaign_failures: 0,
};

function endpointStats(path) {
  if (!stats.by_endpoint[path]) {
    stats.by_endpoint[path] = {
      requests: 0,
      ok: 0,
      fail: 0,
      statuses: {},
      latencies_ms: [],
    };
  }
  return stats.by_endpoint[path];
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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function login() {
  const res = await fetch(`${BASE_URL}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  updateCookies(res);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(`Login failed (${res.status}): ${JSON.stringify(body)}`);
  }
  if (body.requires2FA) {
    throw new Error("2FA-enabled account is not supported by beta-breaker.");
  }
}

async function api(path, init = {}) {
  const headers = new Headers(init.headers || {});
  const method = String(init.method || "GET").toUpperCase();
  headers.set("Content-Type", "application/json");
  const cookie = cookieHeader();
  if (cookie) headers.set("Cookie", cookie);
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrf = cookieJar.get("security_csrf");
    if (csrf) headers.set(csrfHeaderName, csrf);
  }
  const start = Date.now();
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    method,
    headers,
  });
  const latency = Date.now() - start;
  updateCookies(res);
  const body = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, latency, body };
}

function weightedPick(ops) {
  const totalWeight = ops.reduce((acc, op) => acc + op.weight, 0);
  let roll = Math.random() * totalWeight;
  for (const op of ops) {
    if (roll < op.weight) return op;
    roll -= op.weight;
  }
  return ops[0];
}

const operations = [
  {
    name: "GET /api/health",
    weight: 12,
    run: () => api("/api/health"),
  },
  {
    name: "GET /api/audit/evidence",
    weight: 10,
    run: () => api("/api/audit/evidence"),
  },
  {
    name: "GET /api/agents",
    weight: 10,
    run: () => api("/api/agents"),
  },
  {
    name: "GET /api/scans",
    weight: 8,
    run: () => api("/api/scans?limit=20"),
  },
  {
    name: "GET /api/findings",
    weight: 8,
    run: () => api("/api/findings?limit=20"),
  },
  {
    name: "GET /api/brain/insights",
    weight: 8,
    run: () => api("/api/brain/insights"),
  },
  {
    name: "POST /api/intel/google/traffic",
    weight: 8,
    run: () =>
      api("/api/intel/google/traffic", {
        method: "POST",
        body: JSON.stringify({
          window_days: 7,
          points: [
            {
              date: "2026-03-01",
              sessions: 1200,
              signups: 90,
              paid: 20,
              failed_logins: 25,
              bot_ratio: 0.15,
              error_rate_5xx: 0.012,
            },
            {
              date: "2026-03-02",
              sessions: 940,
              signups: 51,
              paid: 9,
              failed_logins: 67,
              bot_ratio: 0.34,
              error_rate_5xx: 0.061,
            },
          ],
        }),
      }),
  },
  {
    name: "POST /api/ai/chat",
    weight: 6,
    run: () =>
      api("/api/ai/chat", {
        method: "POST",
        body: JSON.stringify({
          message: `beta-breaker-${randomUUID()}: summarize two immediate remediation priorities for ${PRIMARY_TARGET_URL} and ${SECONDARY_TARGET_URL}.`,
        }),
      }),
  },
  {
    name: "GET /api/reports",
    weight: 4,
    run: () => api("/api/reports?limit=20"),
  },
];

async function worker(id) {
  while (!stop && Date.now() < deadline) {
    const op = weightedPick(operations);
    let result;
    try {
      result = await op.run();
      if (result.status === 401) {
        await login();
        result = await op.run();
      }
    } catch (err) {
      const entry = endpointStats(op.name);
      entry.requests += 1;
      entry.fail += 1;
      entry.statuses["ERR"] = (entry.statuses["ERR"] || 0) + 1;
      stats.total_requests += 1;
      stats.total_fail += 1;
      if (stats.errors.length < 30) {
        stats.errors.push({
          worker: id,
          endpoint: op.name,
          error: err instanceof Error ? err.message : String(err),
          at: new Date().toISOString(),
        });
      }
      await sleep(80 + Math.floor(Math.random() * 120));
      continue;
    }

    const entry = endpointStats(op.name);
    entry.requests += 1;
    entry.latencies_ms.push(result.latency);
    entry.statuses[String(result.status)] =
      (entry.statuses[String(result.status)] || 0) + 1;

    stats.total_requests += 1;
    if (result.ok) {
      entry.ok += 1;
      stats.total_ok += 1;
    } else {
      entry.fail += 1;
      stats.total_fail += 1;
      if (stats.errors.length < 30) {
        stats.errors.push({
          worker: id,
          endpoint: op.name,
          status: result.status,
          body: result.body,
          at: new Date().toISOString(),
        });
      }
    }

    await sleep(40 + Math.floor(Math.random() * 100));
  }
}

async function periodicCampaignLauncher() {
  while (!stop && Date.now() < deadline) {
    try {
      const result = await api("/api/agent-campaigns", {
        method: "POST",
        body: JSON.stringify({
          goal: `Stress campaign (${new Date().toISOString()}): evaluate auth/session boundary hardening for ${PRIMARY_TARGET_URL} and ${SECONDARY_TARGET_URL}.`,
          max_agents: 3,
        }),
      });
      if (result.ok) {
        stats.campaign_launches += 1;
      } else {
        stats.campaign_failures += 1;
        if (stats.errors.length < 30) {
          stats.errors.push({
            endpoint: "POST /api/agent-campaigns",
            status: result.status,
            body: result.body,
            at: new Date().toISOString(),
          });
        }
      }
    } catch (err) {
      stats.campaign_failures += 1;
      if (stats.errors.length < 30) {
        stats.errors.push({
          endpoint: "POST /api/agent-campaigns",
          error: err instanceof Error ? err.message : String(err),
          at: new Date().toISOString(),
        });
      }
    }
    await sleep(CAMPAIGN_INTERVAL_SEC * 1000);
  }
}

function summarizeLatency(values) {
  if (!values.length) return { p50: null, p95: null, max: null };
  const sorted = [...values].sort((a, b) => a - b);
  const idx50 = Math.floor(sorted.length * 0.5);
  const idx95 = Math.floor(sorted.length * 0.95);
  return {
    p50: sorted[idx50] ?? null,
    p95: sorted[idx95] ?? null,
    max: sorted[sorted.length - 1] ?? null,
  };
}

async function main() {
  console.log(
    `[beta-breaker] base=${BASE_URL} duration=${DURATION_SEC}s concurrency=${CONCURRENCY}`
  );
  await login();

  const workers = [];
  for (let i = 0; i < CONCURRENCY; i += 1) {
    workers.push(worker(i + 1));
  }
  const launcher = periodicCampaignLauncher();

  await Promise.all(workers);
  stop = true;
  await launcher.catch(() => {});

  const endpointSummary = Object.entries(stats.by_endpoint).map(([name, entry]) => ({
    endpoint: name,
    requests: entry.requests,
    ok: entry.ok,
    fail: entry.fail,
    statuses: entry.statuses,
    latency_ms: summarizeLatency(entry.latencies_ms),
  }));

  const report = {
    ok: true,
    started_at: stats.started_at,
    completed_at: new Date().toISOString(),
    duration_sec: DURATION_SEC,
    concurrency: CONCURRENCY,
    totals: {
      requests: stats.total_requests,
      ok: stats.total_ok,
      fail: stats.total_fail,
      error_rate:
        stats.total_requests > 0
          ? Number((stats.total_fail / stats.total_requests).toFixed(4))
          : 0,
      campaign_launches: stats.campaign_launches,
      campaign_failures: stats.campaign_failures,
    },
    endpoints: endpointSummary,
    errors_sample: stats.errors,
  };

  console.log(JSON.stringify(report, null, 2));
}

main().catch((err) => {
  console.error(`BETA_BREAKER_FAIL: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
