#!/usr/bin/env node

/**
 * Human-style stress flow:
 * login -> health -> chat -> notes -> next-actions -> agent campaign -> optional pentest.
 *
 * This script is intended for authorized targets only.
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
const TARGET_URL = process.env.TARGET_URL || "https://example.com";
const ADDITIONAL_TARGETS = String(process.env.ADDITIONAL_TARGETS || "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);
const RUN_PENTEST = String(process.env.RUN_PENTEST || "0") === "1";
const PENTEST_TIMEOUT_SEC = Math.max(
  60,
  Number.parseInt(process.env.PENTEST_TIMEOUT_SEC || "1200", 10) || 1200
);
const STRICT_PENTEST = String(process.env.STRICT_PENTEST || "0") === "1";
const CAMPAIGN_TIMEOUT_SEC = Math.max(
  30,
  Number.parseInt(process.env.CAMPAIGN_TIMEOUT_SEC || "300", 10) || 300
);

const cookieJar = new Map();

function fail(message) {
  console.error(`HUMAN_STRESS_FAIL: ${message}`);
  process.exit(1);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function unique(items) {
  return Array.from(new Set(items));
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

async function pollCampaign(campaignId) {
  let status = "queued";
  let attempts = 0;
  const maxAttempts = CAMPAIGN_TIMEOUT_SEC;

  while (
    (status === "queued" || status === "running") &&
    attempts < maxAttempts
  ) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    const res = await api(`/api/agent-campaigns?campaign_id=${encodeURIComponent(campaignId)}`);
    const body = await res.json().catch(() => ({}));
    assert(res.ok, `Failed campaign status check (${res.status}).`);
    status = body?.campaign?.status || status;
    attempts += 1;
  }

  return { status, attempts, timedOut: attempts >= maxAttempts && (status === "queued" || status === "running") };
}

async function pollPentest() {
  let phase = "running";
  let progress = 0;
  let findings = 0;
  let elapsed = 0;
  let attempts = 0;
  const maxAttempts = Math.ceil(PENTEST_TIMEOUT_SEC / 5);

  while (phase !== "complete" && attempts < maxAttempts) {
    await new Promise((resolve) => setTimeout(resolve, 5000));
    const res = await api("/api/pentest");
    const body = await res.json().catch(() => ({}));
    assert(res.ok, `Failed pentest status check (${res.status}).`);
    phase = body?.phase || phase;
    progress = Number(body?.progress || progress);
    findings = Number(body?.findings_count || findings);
    elapsed = Number(body?.elapsed || elapsed);
    attempts += 1;
  }

  const timedOut = phase !== "complete";
  return { phase, progress, findings, elapsed, attempts, timedOut };
}

async function main() {
  const targetUrls = unique([TARGET_URL, ...ADDITIONAL_TARGETS]);
  const targetScope = targetUrls.join(", ");

  console.log(`[human-stress] Base URL: ${BASE_URL}`);
  console.log(`[human-stress] Target Scope: ${targetScope}`);

  const loginRes = await api("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  const loginBody = await loginRes.json().catch(() => ({}));
  assert(loginRes.ok, `Login failed (${loginRes.status}): ${JSON.stringify(loginBody)}`);
  assert(!loginBody.requires2FA, "2FA-enabled account is not supported by this script.");

  const healthRes = await api("/api/health", { method: "GET" });
  const healthBody = await healthRes.json().catch(() => ({}));
  assert(healthRes.ok, `Health check failed (${healthRes.status}).`);

  const firstPrompt = `I am testing authorized SaaS targets: ${targetScope}. Build a practical kickoff checklist and prioritize high-risk checks that impact end-user trust first.`;
  const chatRes = await api("/api/ai/chat", {
    method: "POST",
    body: JSON.stringify({ message: firstPrompt }),
  });
  const chatBody = await chatRes.json().catch(() => ({}));
  assert(chatRes.ok, `Chat failed (${chatRes.status}): ${JSON.stringify(chatBody)}`);
  assert(typeof chatBody?.message === "string" && chatBody.message.length > 0, "Chat response is empty.");
  const conversationId = chatBody?.conversation_id;
  assert(conversationId, "Chat response missing conversation_id.");

  const followupPrompt = `For targets ${targetScope}, identify likely cross-surface attack paths (public site to admin plane), detection signals, and fastest hardening tasks for this week.`;
  const followupChatRes = await api("/api/ai/chat", {
    method: "POST",
    body: JSON.stringify({ message: followupPrompt, conversation_id: conversationId }),
  });
  const followupChatBody = await followupChatRes.json().catch(() => ({}));
  assert(
    followupChatRes.ok,
    `Follow-up chat failed (${followupChatRes.status}): ${JSON.stringify(followupChatBody)}`
  );
  assert(
    typeof followupChatBody?.message === "string" && followupChatBody.message.length > 0,
    "Follow-up chat response is empty."
  );

  const noteRes = await api("/api/ai/notes", {
    method: "POST",
    body: JSON.stringify({
      title: `Human Stress Run - ${new Date().toISOString()}`,
      content: `Targets: ${targetScope}\nHealth: ${healthBody?.status || "unknown"}\nChat model: ${chatBody?.model || "unknown"}\nFollow-up model: ${followupChatBody?.model || "unknown"}`,
      conversation_id: conversationId,
      pinned: true,
      tags: ["stress-test", "human-flow", "vps"],
    }),
  });
  const noteBody = await noteRes.json().catch(() => ({}));
  assert(noteRes.ok, `Creating note failed (${noteRes.status}): ${JSON.stringify(noteBody)}`);
  const noteId = noteBody?.note?.id;
  assert(noteId, "Note id missing after note creation.");

  const notesReadRes = await api(`/api/ai/notes?conversation_id=${encodeURIComponent(conversationId)}`);
  const notesReadBody = await notesReadRes.json().catch(() => ({}));
  assert(notesReadRes.ok, `Reading notes failed (${notesReadRes.status}).`);
  const notesCount = Array.isArray(notesReadBody?.notes) ? notesReadBody.notes.length : 0;
  assert(notesCount > 0, "Persisted note not found.");

  const nextRes = await api(`/api/ai/next-actions?conversation_id=${encodeURIComponent(conversationId)}`);
  const nextBody = await nextRes.json().catch(() => ({}));
  assert(nextRes.ok, `Next actions failed (${nextRes.status}).`);
  const nextActionsCount = Array.isArray(nextBody?.actions) ? nextBody.actions.length : 0;
  assert(nextActionsCount > 0, "No next actions generated.");

  const campaignRes = await api("/api/agent-campaigns", {
    method: "POST",
    body: JSON.stringify({
      goal: `Run a controlled, authorized multi-domain SaaS security campaign for ${targetScope}. Focus on auth/session boundaries, shared identity risk, and customer-impacting remediation with retest checklist.`,
      max_agents: 6,
    }),
  });
  const campaignBody = await campaignRes.json().catch(() => ({}));
  assert(campaignRes.ok, `Agent campaign launch failed (${campaignRes.status}): ${JSON.stringify(campaignBody)}`);
  const campaignId = campaignBody?.campaign?.id;
  assert(campaignId, "Campaign id missing.");
  const campaignPoll = await pollCampaign(campaignId);

  let pentestResult = null;
  if (RUN_PENTEST) {
    const pentestRes = await api("/api/pentest", {
      method: "POST",
      body: JSON.stringify({
        target_url: TARGET_URL,
        max_pipelines: 2,
      }),
    });
    const pentestBody = await pentestRes.json().catch(() => ({}));
    if (!pentestRes.ok && pentestRes.status === 409) {
      // Existing run in progress, continue polling status.
      pentestResult = await pollPentest();
    } else {
      assert(
        pentestRes.ok,
        `Pentest launch failed (${pentestRes.status}): ${JSON.stringify(pentestBody)}`
      );
      pentestResult = await pollPentest();
    }

    if (STRICT_PENTEST && pentestResult?.timedOut) {
      fail(`Pentest timed out after ${PENTEST_TIMEOUT_SEC}s.`);
    }
  }

  console.log(
    JSON.stringify(
      {
        ok: true,
        target_url: TARGET_URL,
        target_scope: targetScope,
        health_status: healthBody?.status || "unknown",
        health_online_services: Array.isArray(healthBody?.services)
          ? healthBody.services.filter((service) => service.status === "online").length
          : 0,
        conversation_id: conversationId,
        followup_conversation_id: followupChatBody?.conversation_id || conversationId,
        note_id: noteId,
        notes_persisted: notesCount,
        next_actions: nextActionsCount,
        campaign_id: campaignId,
        campaign_status: campaignPoll.status,
        campaign_timed_out: campaignPoll.timedOut,
        run_pentest: RUN_PENTEST,
        pentest: pentestResult,
      },
      null,
      2
    )
  );
}

main().catch((err) => fail(err instanceof Error ? err.message : String(err)));
