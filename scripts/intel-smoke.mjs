#!/usr/bin/env node

/**
 * End-to-end smoke test for no-key intelligence + business impact scoring.
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
      if (!process.env[key]) {
        process.env[key] = value;
      }
    }
  } catch {
    // Optional local env file.
  }
}

loadEnvFile();

const BASE_URL = process.env.BASE_URL || "http://127.0.0.1:4100";
const EMAIL = process.env.ADMIN_EMAIL || "admin@security.local";
const PASSWORD = process.env.ADMIN_PASSWORD || "changeme123";
const ALLOW_MISSING_INTEL_ROUTES = process.env.ALLOW_MISSING_INTEL_ROUTES === "1";

const cookieJar = new Map();

function fail(message) {
  console.error(`INTEL_SMOKE_FAIL: ${message}`);
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

async function main() {
  console.log(`[intel-smoke] Base URL: ${BASE_URL}`);

  const loginRes = await api("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  const loginBody = await loginRes.json().catch(() => ({}));
  assert(loginRes.ok, `Login failed (${loginRes.status}): ${JSON.stringify(loginBody)}`);
  assert(!loginBody.requires2FA, "2FA-enabled account is not supported by this smoke test.");

  const setSettingsRes = await api("/api/settings/google-intel", {
    method: "POST",
    body: JSON.stringify({
      enabled: true,
      mode: "no_key",
      allow_live_google_fetch: false,
      max_results: 10,
    }),
  });
  if (setSettingsRes.status === 404) {
    if (!ALLOW_MISSING_INTEL_ROUTES) {
      fail(
        "google-intel settings route is missing on target runtime. Set ALLOW_MISSING_INTEL_ROUTES=1 only for backward-compat checks."
      );
    }
    console.warn("[intel-smoke] /api/settings/google-intel not available on target runtime; continuing.");
  } else {
    const setSettingsBody = await setSettingsRes.json().catch(() => ({}));
    assert(
      setSettingsRes.ok,
      `Failed to save google-intel settings (${setSettingsRes.status}): ${JSON.stringify(setSettingsBody)}`
    );

    const getSettingsRes = await api("/api/settings/google-intel");
    if (getSettingsRes.status !== 404) {
      const getSettingsBody = await getSettingsRes.json().catch(() => ({}));
      assert(getSettingsRes.ok, `Failed to read google-intel settings (${getSettingsRes.status}).`);
      assert(getSettingsBody?.settings?.enabled === true, "google-intel settings not enabled.");
    } else {
      console.warn("[intel-smoke] /api/settings/google-intel GET not available on target runtime; continuing.");
    }
  }

  let searchBody = {
    mode: "unavailable",
    total: 0,
    results: [],
  };
  let searchAvailable = false;
  const searchRes = await api("/api/intel/google/search", {
    method: "POST",
    body: JSON.stringify({
      query: "authentication security headers",
      domain: "example.com",
      num: 8,
    }),
  });
  if (searchRes.status === 404) {
    if (!ALLOW_MISSING_INTEL_ROUTES) {
      fail(
        "intel search route is missing on target runtime. Set ALLOW_MISSING_INTEL_ROUTES=1 only for backward-compat checks."
      );
    }
    console.warn("[intel-smoke] /api/intel/google/search not available on target runtime; continuing.");
  } else {
    searchBody = await searchRes.json().catch(() => ({}));
    assert(
      searchRes.ok,
      `Search intel failed (${searchRes.status}): ${JSON.stringify(searchBody)}`
    );
    assert(typeof searchBody.total === "number", "Search intel missing total.");
    assert(Array.isArray(searchBody.results), "Search intel results is not an array.");
    searchAvailable = true;
  }

  let trafficBody = {
    source: "unavailable",
    anomalies: [],
  };
  let trafficAvailable = false;
  const trafficRes = await api("/api/intel/google/traffic", {
    method: "POST",
    body: JSON.stringify({
      window_days: 14,
      points: [
        {
          date: "2026-02-20",
          sessions: 1100,
          signups: 80,
          paid: 14,
          failed_logins: 20,
          bot_ratio: 0.18,
          error_rate_5xx: 0.02,
        },
        {
          date: "2026-02-21",
          sessions: 1160,
          signups: 83,
          paid: 15,
          failed_logins: 19,
          bot_ratio: 0.17,
          error_rate_5xx: 0.018,
        },
        {
          date: "2026-02-22",
          sessions: 990,
          signups: 68,
          paid: 9,
          failed_logins: 72,
          bot_ratio: 0.39,
          error_rate_5xx: 0.08,
        },
      ],
    }),
  });
  if (trafficRes.status === 404) {
    if (!ALLOW_MISSING_INTEL_ROUTES) {
      fail(
        "intel traffic route is missing on target runtime. Set ALLOW_MISSING_INTEL_ROUTES=1 only for backward-compat checks."
      );
    }
    console.warn("[intel-smoke] /api/intel/google/traffic not available on target runtime; continuing.");
  } else {
    trafficBody = await trafficRes.json().catch(() => ({}));
    assert(
      trafficRes.ok,
      `Traffic intel failed (${trafficRes.status}): ${JSON.stringify(trafficBody)}`
    );
    assert(trafficBody?.metrics, "Traffic intel missing metrics.");
    assert(Array.isArray(trafficBody?.recommended_actions), "Traffic intel missing actions.");
    trafficAvailable = true;
  }

  const findingsRes = await api("/api/findings?limit=5");
  const findingsBody = await findingsRes.json().catch(() => ({}));
  assert(findingsRes.ok, `Findings API failed (${findingsRes.status}).`);
  const findings = Array.isArray(findingsBody?.findings) ? findingsBody.findings : [];
  if (findings.length > 0) {
    assert(
      findings.every(
        (finding) =>
          finding?.business_impact &&
          typeof finding.business_impact.score === "number" &&
          Array.isArray(finding.business_impact.journeys)
      ),
      "One or more findings missing business_impact payload."
    );
  }

  console.log(
    JSON.stringify(
      {
        ok: true,
        allow_missing_intel_routes: ALLOW_MISSING_INTEL_ROUTES,
        search_available: searchAvailable,
        search_mode: searchBody.mode,
        search_total: searchBody.total,
        traffic_available: trafficAvailable,
        traffic_source: trafficBody.source,
        anomalies: Array.isArray(trafficBody.anomalies) ? trafficBody.anomalies.length : 0,
        findings_checked: findings.length,
      },
      null,
      2
    )
  );
}

main().catch((err) => fail(err instanceof Error ? err.message : String(err)));
