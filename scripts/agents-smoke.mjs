#!/usr/bin/env node

/**
 * End-to-end smoke test for the agent fleet API.
 * Requires a running app instance and a valid user account.
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
const PRIMARY_TARGET_URL = process.env.PRIMARY_TARGET_URL || "https://example.com";
const SECONDARY_TARGET_URL =
  process.env.SECONDARY_TARGET_URL || "https://demo.example.com";
const RUN_TIMEOUT_SEC = Math.max(
  60,
  Number.parseInt(process.env.AGENT_RUN_TIMEOUT_SEC || "180", 10) || 180
);
const CAMPAIGN_TIMEOUT_SEC = Math.max(
  60,
  Number.parseInt(process.env.CAMPAIGN_TIMEOUT_SEC || "180", 10) || 180
);

const cookieJar = new Map();

function fail(message) {
  console.error(`SMOKE_FAIL: ${message}`);
  process.exit(1);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function toHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
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
  console.log(`[agents-smoke] Base URL: ${BASE_URL}`);
  console.log(
    `[agents-smoke] Targets: ${PRIMARY_TARGET_URL}, ${SECONDARY_TARGET_URL}`
  );
  const targetDomains = Array.from(
    new Set([toHostname(PRIMARY_TARGET_URL), toHostname(SECONDARY_TARGET_URL)].filter(Boolean))
  );
  const campaignScope = [PRIMARY_TARGET_URL, SECONDARY_TARGET_URL]
    .filter(Boolean)
    .join(" and ");

  const login = await api("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  const loginBody = await login.json().catch(() => ({}));
  assert(login.ok, `Login failed (${login.status}): ${JSON.stringify(loginBody)}`);
  assert(!loginBody.requires2FA, "2FA is enabled for this user; smoke test requires non-2FA account.");
  assert(loginBody.success === true, "Login did not return success=true.");

  const agentsRes = await api("/api/agents");
  const agentsBody = await agentsRes.json().catch(() => ({}));
  assert(agentsRes.ok, `Failed to fetch agents (${agentsRes.status}).`);
  const agents = Array.isArray(agentsBody.agents) ? agentsBody.agents : [];
  assert(agents.length >= 50, `Expected >= 50 agents but got ${agents.length}.`);

  const agent =
    agents.find(
      (candidate) =>
        Array.isArray(candidate.tools_allowed) &&
        candidate.tools_allowed.some((tool) => ["dns", "osint"].includes(String(tool).toLowerCase()))
    ) || agents[0];
  assert(agent?.id, "No agent id found.");

  const syntheticSecret = `cf_test_token_${Date.now()}`;
  const cloudDnsSaveRes = await api("/api/settings/cloud-dns", {
    method: "POST",
    body: JSON.stringify({
      cloudflare: {
        enabled: true,
        api_token: syntheticSecret,
        zone_allowlist: targetDomains.length > 0 ? targetDomains : ["example.com"],
      },
      gcp: {
        enabled: false,
        service_account_json: null,
      },
      safety: {
        never_send_cloud_credentials_to_llm: true,
        redact_provider_identifiers: true,
      },
    }),
  });
  assert(cloudDnsSaveRes.ok, "Failed to save cloud DNS settings.");
  const cloudDnsReadRes = await api("/api/settings/cloud-dns");
  const cloudDnsReadBody = await cloudDnsReadRes.json().catch(() => ({}));
  assert(cloudDnsReadRes.ok, "Failed to read cloud DNS settings.");
  assert(
    cloudDnsReadBody?.settings?.cloudflare?.has_api_token === true,
    "Cloud DNS settings did not report token presence."
  );
  assert(
    !JSON.stringify(cloudDnsReadBody).includes(syntheticSecret),
    "Cloud DNS GET leaked raw secret."
  );

  const patchRes = await api(`/api/agents/${agent.id}`, {
    method: "PATCH",
    body: JSON.stringify({
      description: `${agent.description} [smoke-${Date.now()}]`,
    }),
  });
  assert(patchRes.ok, `Failed to patch agent (${patchRes.status}).`);

  const runRes = await api(`/api/agents/${agent.id}/run`, {
    method: "POST",
    body: JSON.stringify({
      input: `Assess ${campaignScope} for security gaps. Include DNS/IP target intel, auth boundary risk, and remediation priorities for SaaS users.`,
    }),
  });
  const runBody = await runRes.json().catch(() => ({}));
  assert(runRes.ok, `Failed to enqueue run (${runRes.status}): ${JSON.stringify(runBody)}`);
  const runId = runBody?.run?.id;
  assert(runId, "Run id missing from run response.");

  let runStatus = "queued";
  let attempts = 0;
  while (
    (runStatus === "queued" || runStatus === "running") &&
    attempts < RUN_TIMEOUT_SEC
  ) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    const detailRes = await api(`/api/agent-runs/${runId}`);
    const detailBody = await detailRes.json().catch(() => ({}));
    assert(detailRes.ok, `Run detail failed (${detailRes.status}).`);
    runStatus = detailBody?.run?.status || "unknown";
    attempts++;
  }
  assert(
    !(runStatus === "queued" || runStatus === "running"),
    `Run ${runId} timed out after ${RUN_TIMEOUT_SEC}s with status=${runStatus}.`
  );

  assert(
    ["completed", "blocked", "failed"].includes(runStatus),
    `Unexpected terminal status: ${runStatus}`
  );

  const noteRes = await api(`/api/agent-runs/${runId}/notes`, {
    method: "POST",
    body: JSON.stringify({
      title: "Smoke Evidence",
      content: `Run reached status=${runStatus} in ${attempts}s.`,
    }),
  });
  assert(noteRes.ok, `Failed to create run note (${noteRes.status}).`);

  const detailAfterNoteRes = await api(`/api/agent-runs/${runId}`);
  const detailAfterNote = await detailAfterNoteRes.json().catch(() => ({}));
  assert(detailAfterNoteRes.ok, "Failed to load run detail after note creation.");
  const persistedNotes = Array.isArray(detailAfterNote.notes)
    ? detailAfterNote.notes
    : [];
  assert(persistedNotes.length > 0, "Run note persistence check failed.");
  const artifacts = Array.isArray(detailAfterNote.artifacts)
    ? detailAfterNote.artifacts
    : [];
  const hasTargetIntelArtifact = artifacts.some(
    (artifact) => artifact?.artifact_type === "target-intel"
  );
  assert(hasTargetIntelArtifact, "Target-intel artifact was not generated.");
  assert(
    !JSON.stringify(detailAfterNote).includes(syntheticSecret),
    "Run detail leaked cloud DNS secret."
  );

  const evalRes = await api(`/api/agents/${agent.id}/evaluate`, {
    method: "POST",
    body: JSON.stringify({ run_id: runId }),
  });
  const evalBody = await evalRes.json().catch(() => ({}));
  assert(evalRes.ok, `Evaluation failed (${evalRes.status}).`);
  assert(
    typeof evalBody?.evaluation?.score === "number",
    "Evaluation score missing."
  );

  const autoRes = await api("/api/agent-campaigns", {
    method: "POST",
    body: JSON.stringify({
      goal: `Autonomously run a multi-agent SaaS security campaign for ${campaignScope}. Prioritize auth/session boundaries, API abuse risk, and evidence-backed remediation with retest criteria.`,
      max_agents: 4,
    }),
  });
  const autoBody = await autoRes.json().catch(() => ({}));
  assert(autoRes.ok, `Autonomous launch failed (${autoRes.status}).`);
  const campaignId = autoBody?.campaign?.id;
  assert(campaignId, "Autonomous campaign id missing.");
  assert(
    Array.isArray(autoBody?.queued_runs) && autoBody.queued_runs.length > 0,
    "Autonomous campaign queued_runs missing."
  );

  let campaignStatus = autoBody?.campaign?.status || "running";
  let campaignAttempts = 0;
  while (
    (campaignStatus === "queued" || campaignStatus === "running") &&
    campaignAttempts < CAMPAIGN_TIMEOUT_SEC
  ) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    const campaignRes = await api(
      `/api/agent-campaigns?campaign_id=${encodeURIComponent(campaignId)}`
    );
    const campaignBody = await campaignRes.json().catch(() => ({}));
    assert(campaignRes.ok, `Autonomous campaign status failed (${campaignRes.status}).`);
    campaignStatus = campaignBody?.campaign?.status || campaignStatus;
    campaignAttempts++;
  }
  assert(
    !(campaignStatus === "queued" || campaignStatus === "running"),
    `Campaign ${campaignId} timed out after ${CAMPAIGN_TIMEOUT_SEC}s with status=${campaignStatus}.`
  );
  assert(
    ["completed", "failed"].includes(campaignStatus),
    `Unexpected autonomous campaign status: ${campaignStatus}`
  );

  console.log(
    JSON.stringify(
      {
        ok: true,
        agents_count: agents.length,
        run_id: runId,
        run_status: runStatus,
        notes_persisted: persistedNotes.length,
        has_target_intel_artifact: hasTargetIntelArtifact,
        eval_score: evalBody.evaluation.score,
        eval_pass: evalBody.evaluation.pass,
        targets: campaignScope,
        autonomous_campaign_id: campaignId,
        autonomous_campaign_status: campaignStatus,
      },
      null,
      2
    )
  );
}

main().catch((err) => fail(err instanceof Error ? err.message : String(err)));
