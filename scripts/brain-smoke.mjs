#!/usr/bin/env node

/**
 * End-to-end smoke test for Autonomous Brain APIs.
 * Validates feed CRUD/refresh, calendar CRUD, and insights payload.
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
const FEED_CANDIDATES = [
  {
    name: "CISA ICS Advisories",
    url: "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
  },
  {
    name: "BleepingComputer Security",
    url: "https://www.bleepingcomputer.com/feed/",
  },
  {
    name: "The Hacker News",
    url: "https://feeds.feedburner.com/TheHackersNews",
  },
  {
    name: "Krebs on Security",
    url: "https://krebsonsecurity.com/feed/",
  },
  {
    name: "SANS Internet Storm Center",
    url: "https://isc.sans.edu/rssfeed.xml",
  },
];

const cookieJar = new Map();

function fail(message) {
  console.error(`BRAIN_SMOKE_FAIL: ${message}`);
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

function normalizeUrl(value) {
  return String(value || "")
    .trim()
    .replace(/\/+$/, "");
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
  console.log(`[brain-smoke] Base URL: ${BASE_URL}`);

  const loginRes = await api("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  const loginBody = await loginRes.json().catch(() => ({}));
  assert(loginRes.ok, `Login failed (${loginRes.status}): ${JSON.stringify(loginBody)}`);
  assert(!loginBody.requires2FA, "2FA-enabled account is not supported by this smoke test.");

  const feedsInitialRes = await api("/api/brain/feeds?items_limit=10");
  const feedsInitialBody = await feedsInitialRes.json().catch(() => ({}));
  assert(feedsInitialRes.ok, `Initial feeds GET failed (${feedsInitialRes.status}).`);
  let existingFeeds = Array.isArray(feedsInitialBody.feeds) ? feedsInitialBody.feeds : [];

  for (const feed of existingFeeds) {
    const name = String(feed?.name || "");
    const url = String(feed?.url || "");
    if (/smoke/i.test(name) || /smoke/i.test(url)) {
      await api(`/api/brain/feeds?id=${encodeURIComponent(feed.id)}`, { method: "DELETE" });
    }
  }

  const refreshedFeedsRes = await api("/api/brain/feeds?items_limit=10");
  const refreshedFeedsBody = await refreshedFeedsRes.json().catch(() => ({}));
  assert(refreshedFeedsRes.ok, `Post-cleanup feeds GET failed (${refreshedFeedsRes.status}).`);
  existingFeeds = Array.isArray(refreshedFeedsBody.feeds) ? refreshedFeedsBody.feeds : [];

  const existingByUrl = new Map(
    existingFeeds.map((feed) => [normalizeUrl(feed?.url), feed])
  );

  const ensuredFeeds = [];
  for (const candidate of FEED_CANDIDATES) {
    const wantedUrl = normalizeUrl(candidate.url);
    let feed = existingByUrl.get(wantedUrl) || null;

    if (!feed) {
      const createFeedRes = await api("/api/brain/feeds", {
        method: "POST",
        body: JSON.stringify({
          name: candidate.name,
          url: candidate.url,
          category: "threat-intel",
          refresh_interval_min: 180,
        }),
      });
      const createFeedBody = await createFeedRes.json().catch(() => ({}));
      assert(
        createFeedRes.ok || createFeedRes.status === 400,
        `Feed create failed (${createFeedRes.status}): ${JSON.stringify(createFeedBody)}`
      );

      const listRes = await api("/api/brain/feeds?items_limit=30");
      const listBody = await listRes.json().catch(() => ({}));
      assert(listRes.ok, `Feed list refresh failed (${listRes.status}).`);
      const list = Array.isArray(listBody.feeds) ? listBody.feeds : [];
      feed = list.find((row) => normalizeUrl(row?.url) === wantedUrl) || null;
    }

    assert(feed?.id, `Missing feed id for ${candidate.name}.`);
    ensuredFeeds.push({
      id: String(feed.id),
      name: String(feed.name || candidate.name),
      url: String(feed.url || candidate.url),
    });
  }

  assert(ensuredFeeds.length >= 5, "Failed to ensure all 5 live threat feeds.");

  const refreshResults = [];
  for (const feed of ensuredFeeds) {
    const refreshRes = await api(`/api/brain/feeds/${encodeURIComponent(feed.id)}/refresh`, {
      method: "POST",
    });
    const refreshBody = await refreshRes.json().catch(() => ({}));
    if (refreshRes.ok && refreshBody.success === true) {
      refreshResults.push({
        id: feed.id,
        name: feed.name,
        imported: Number(refreshBody.imported || 0),
      });
    } else {
      refreshResults.push({
        id: feed.id,
        name: feed.name,
        imported: 0,
        error: refreshBody?.error || `HTTP ${refreshRes.status}`,
      });
    }
  }

  const refreshSuccessCount = refreshResults.filter((row) => !row.error).length;
  assert(refreshSuccessCount >= 3, "Less than 3 live feeds refreshed successfully.");

  const refreshAllRes = await api("/api/brain/feeds/refresh", {
    method: "POST",
  });
  const refreshAllBody = await refreshAllRes.json().catch(() => ({}));
  assert(
    refreshAllRes.ok,
    `Bulk feed refresh failed (${refreshAllRes.status}): ${JSON.stringify(refreshAllBody)}`
  );
  assert(refreshAllBody.success === true, "Bulk feed refresh did not return success=true.");

  const now = Date.now();
  const start = new Date(now + 30 * 60 * 1000).toISOString();
  const end = new Date(now + 90 * 60 * 1000).toISOString();

  const createEventRes = await api("/api/brain/calendar", {
    method: "POST",
    body: JSON.stringify({
      title: `Validation Event ${now}`,
      description: "Proof of persistence from automated brain test",
      start_time: start,
      end_time: end,
      category: "ops-review",
      status: "planned",
      priority: "high",
    }),
  });
  const createEventBody = await createEventRes.json().catch(() => ({}));
  assert(
    createEventRes.ok,
    `Calendar create failed (${createEventRes.status}): ${JSON.stringify(createEventBody)}`
  );
  const eventId = createEventBody?.event?.id;
  assert(eventId, "Calendar create did not return event id.");

  const patchEventRes = await api("/api/brain/calendar", {
    method: "PATCH",
    body: JSON.stringify({
      id: eventId,
      status: "in_progress",
      priority: "critical",
    }),
  });
  const patchEventBody = await patchEventRes.json().catch(() => ({}));
  assert(
    patchEventRes.ok,
    `Calendar patch failed (${patchEventRes.status}): ${JSON.stringify(patchEventBody)}`
  );
  assert(
    patchEventBody?.event?.status === "in_progress",
    "Calendar patch did not persist status."
  );

  const listEventRes = await api(`/api/brain/calendar?limit=30&from=${encodeURIComponent(new Date(now - 3600_000).toISOString())}`);
  const listEventBody = await listEventRes.json().catch(() => ({}));
  assert(listEventRes.ok, `Calendar list failed (${listEventRes.status}).`);
  const events = Array.isArray(listEventBody.events) ? listEventBody.events : [];
  assert(events.some((event) => event?.id === eventId), "Created event missing from calendar list.");

  const insightsRes = await api("/api/brain/insights");
  const insightsBody = await insightsRes.json().catch(() => ({}));
  assert(insightsRes.ok, `Insights GET failed (${insightsRes.status}).`);
  assert(insightsBody?.summary, "Insights payload missing summary.");
  assert(insightsBody?.forecast, "Insights payload missing forecast.");
  assert(Array.isArray(insightsBody?.top_feed_items), "Insights top_feed_items is not an array.");

  const deleteEventRes = await api(`/api/brain/calendar?id=${encodeURIComponent(eventId)}`, {
    method: "DELETE",
  });
  assert(deleteEventRes.ok, `Calendar delete failed (${deleteEventRes.status}).`);

  console.log(
    JSON.stringify(
      {
        ok: true,
        feeds_configured: ensuredFeeds.length,
        feed_refresh_success_count: refreshSuccessCount,
        feed_refresh_results: refreshResults,
        bulk_processed: Number(refreshAllBody.processed || 0),
        calendar_event_id: eventId,
        forecast_level: insightsBody?.forecast?.level || "unknown",
        top_feed_items: Array.isArray(insightsBody?.top_feed_items)
          ? insightsBody.top_feed_items.length
          : 0,
      },
      null,
      2
    )
  );
}

main().catch((err) => fail(err instanceof Error ? err.message : String(err)));
