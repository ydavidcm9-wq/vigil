#!/usr/bin/env node

/**
 * Smoke test for autonomous campaign scheduling + cron execution.
 * Creates a one-time schedule, triggers cron, and validates campaign launch.
 */

import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

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
const CRON_SECRET = process.env.CRON_SECRET || "";

const cookieJar = new Map();

function fail(message) {
  console.error(`SCHEDULER_SMOKE_FAIL: ${message}`);
  process.exit(1);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

async function cron(path) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${CRON_SECRET}`,
    },
  });
  return res;
}

async function main() {
  assert(CRON_SECRET.length > 0, "CRON_SECRET must be set for scheduler smoke test.");

  const loginRes = await api("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  const loginBody = await loginRes.json().catch(() => ({}));
  assert(loginRes.ok, `Login failed (${loginRes.status}): ${JSON.stringify(loginBody)}`);
  assert(!loginBody.requires2FA, "2FA-enabled account is not supported by this test.");

  const runAt = new Date(Date.now() + 20_000).toISOString();
  const scheduleRes = await api("/api/agent-campaign-schedules", {
    method: "POST",
    body: JSON.stringify({
      title: "Smoke: Once schedule",
      goal: "Run scheduled autonomous campaign for example.com and demo.example.com, prioritize auth/session boundaries and SaaS API abuse prevention.",
      max_agents: 4,
      schedule_type: "once",
      schedule_config: { run_at: runAt },
      timezone: "America/Chicago",
      enabled: true,
      web_agent_template: "ghost-recon",
      web_agent_config: { depth: "deep" },
      sync_calendar_event: true,
    }),
  });
  const scheduleBody = await scheduleRes.json().catch(() => ({}));
  assert(
    scheduleRes.ok,
    `Schedule creation failed (${scheduleRes.status}): ${JSON.stringify(scheduleBody)}`
  );
  const scheduleId = scheduleBody?.schedule?.id;
  assert(scheduleId, "Created schedule missing id.");

  const waitMs = Math.max(0, new Date(runAt).getTime() - Date.now() + 4_000);
  await sleep(waitMs);

  const cronRes = await cron("/api/cron/agent-campaign-schedules");
  const cronBody = await cronRes.json().catch(() => ({}));
  assert(cronRes.ok, `Cron trigger failed (${cronRes.status}): ${JSON.stringify(cronBody)}`);

  let schedule = null;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    await sleep(3000);
    const statusRes = await api(`/api/agent-campaign-schedules/${encodeURIComponent(scheduleId)}`);
    const statusBody = await statusRes.json().catch(() => ({}));
    assert(statusRes.ok, `Schedule status failed (${statusRes.status})`);
    schedule = statusBody?.schedule || null;
    if (schedule?.run_count >= 1 && schedule?.last_campaign_id) break;
  }

  assert(schedule, "Schedule status not found.");
  assert(schedule.run_count >= 1, "Schedule did not execute.");
  assert(schedule.last_campaign_id, "Schedule missing launched campaign id.");
  assert(schedule.enabled === false, "One-time schedule should be disabled after run.");

  const campaignRes = await api(
    `/api/agent-campaigns?campaign_id=${encodeURIComponent(schedule.last_campaign_id)}`
  );
  const campaignBody = await campaignRes.json().catch(() => ({}));
  assert(
    campaignRes.ok,
    `Campaign fetch failed (${campaignRes.status}): ${JSON.stringify(campaignBody)}`
  );

  const deleteRes = await api(`/api/agent-campaign-schedules/${encodeURIComponent(scheduleId)}`, {
    method: "DELETE",
  });
  assert(deleteRes.ok, `Schedule cleanup failed (${deleteRes.status}).`);

  console.log(
    JSON.stringify(
      {
        ok: true,
        schedule_id: scheduleId,
        last_campaign_id: schedule.last_campaign_id,
        cron_checked: cronBody?.checked ?? null,
        cron_launched: cronBody?.launched ?? null,
        schedule_run_count: schedule.run_count,
      },
      null,
      2
    )
  );
}

main().catch((err) => fail(err instanceof Error ? err.message : String(err)));
