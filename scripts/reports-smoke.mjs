#!/usr/bin/env node

/**
 * Reports smoke (1-5):
 * 1) login
 * 2) read completed scans
 * 3) generate report (single scan)
 * 4) generate report (multi-scan) + parallel burst
 * 5) validate created report and delete it
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
const TIMEOUT_MS = Math.max(
  30000,
  Number.parseInt(process.env.REPORT_SMOKE_TIMEOUT_MS || "120000", 10) || 120000
);

const cookieJar = new Map();

function fail(message) {
  console.error(`REPORT_SMOKE_FAIL: ${message}`);
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
  const method = String(init.method || "GET").toUpperCase();
  const headers = new Headers(init.headers || {});
  if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const cookie = cookieHeader();
  if (cookie) headers.set("Cookie", cookie);
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrf = cookieJar.get("security_csrf");
    if (csrf) headers.set("x-csrf-token", csrf);
  }

  const start = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      ...init,
      method,
      headers,
      signal: controller.signal,
    });
    const durationMs = Date.now() - start;
    updateCookies(res);
    const body = await res.json().catch(() => ({}));
    return {
      ok: res.ok,
      status: res.status,
      durationMs,
      body,
    };
  } finally {
    clearTimeout(timer);
  }
}

function summarizeDurations(values) {
  if (!values.length) return { min: 0, max: 0, avg: 0 };
  const sum = values.reduce((acc, n) => acc + n, 0);
  return {
    min: Math.min(...values),
    max: Math.max(...values),
    avg: Math.round(sum / values.length),
  };
}

async function main() {
  const createdIds = [];

  // 1) login
  const loginRes = await api("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  assert(loginRes.ok, `Login failed (${loginRes.status}).`);
  assert(!loginRes.body?.requires2FA, "2FA-enabled account is unsupported by reports-smoke.");

  // 2) read completed scans
  const scansRes = await api("/api/scans?limit=50");
  assert(scansRes.ok, `Read scans failed (${scansRes.status}).`);
  const scans = Array.isArray(scansRes.body?.scans)
    ? scansRes.body.scans
    : Array.isArray(scansRes.body)
      ? scansRes.body
      : [];
  const completed = scans.filter((scan) => scan?.status === "completed");
  assert(completed.length > 0, "No completed scans available for report generation.");
  const scanIds = completed.slice(0, 5).map((scan) => scan.id);

  const generate = async (name, ids) => {
    const res = await api("/api/reports", {
      method: "POST",
      body: JSON.stringify({
        report_type: "full_audit",
        title: `[reports-smoke] ${name} ${new Date().toISOString()}`,
        scan_ids: ids,
      }),
    });
    if (res.ok && res.body?.id) createdIds.push(res.body.id);
    return res;
  };

  // 3) generate single-scan report
  const single = await generate("single", [scanIds[0]]);
  assert(single.ok, `Single report generation failed (${single.status}): ${JSON.stringify(single.body)}`);

  // 4) multi-scan + burst
  const multi = await generate("multi", scanIds.slice(0, Math.min(3, scanIds.length)));
  assert(multi.ok, `Multi report generation failed (${multi.status}): ${JSON.stringify(multi.body)}`);

  const burstPayloads = [
    [scanIds[0]],
    [scanIds[Math.min(1, scanIds.length - 1)]],
    [scanIds[Math.min(2, scanIds.length - 1)]],
  ];
  const burst = await Promise.all(
    burstPayloads.map((ids, index) => generate(`burst-${index + 1}`, ids))
  );
  const burstFailures = burst.filter((item) => !item.ok);
  assert(
    burstFailures.length === 0,
    `Burst generation had ${burstFailures.length} failure(s): ${JSON.stringify(
      burstFailures.map((item) => ({ status: item.status, body: item.body }))
    )}`
  );

  // 5) read + delete created reports
  const reportsRes = await api("/api/reports");
  assert(reportsRes.ok, `Read reports failed (${reportsRes.status}).`);
  const reportList = Array.isArray(reportsRes.body?.reports)
    ? reportsRes.body.reports
    : Array.isArray(reportsRes.body)
      ? reportsRes.body
      : [];

  const foundCount = createdIds.filter((id) =>
    reportList.some((report) => report?.id === id)
  ).length;
  assert(foundCount > 0, "Created reports were not returned by GET /api/reports.");

  let deleteFailures = 0;
  for (const id of createdIds) {
    const del = await api(`/api/reports/${id}`, { method: "DELETE" });
    if (!del.ok && del.status !== 404) deleteFailures += 1;
  }
  assert(deleteFailures === 0, `Delete failed for ${deleteFailures} report(s).`);

  const durations = [single.durationMs, multi.durationMs, ...burst.map((item) => item.durationMs)];
  console.log(
    JSON.stringify(
      {
        ok: true,
        test: "reports-smoke-1-5",
        base_url: BASE_URL,
        timeout_ms: TIMEOUT_MS,
        completed_scans_available: completed.length,
        generated_reports: createdIds.length,
        timings_ms: {
          single: single.durationMs,
          multi: multi.durationMs,
          burst: burst.map((item) => item.durationMs),
          summary: summarizeDurations(durations),
        },
      },
      null,
      2
    )
  );
}

main().catch((err) => fail(err instanceof Error ? err.message : String(err)));

