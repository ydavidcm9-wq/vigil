import { randomUUID } from "crypto";
import { enqueueAgentRun, getQueueState } from "@/lib/agents/queue";
import { extractTargets } from "@/lib/agents/target-intel";
import {
  addCampaignRun,
  createCampaign,
  createAgentRun,
  listActiveAgents,
  markCampaignStatus,
  type AgentCampaignRecord,
  type AgentListItem,
} from "@/lib/agents/store";

interface AutonomousPlanItem {
  agent_id: string;
  agent_name: string;
  category: string;
  priority: number;
  reason: string;
}

export interface AutonomousLaunchResult {
  campaign: AgentCampaignRecord;
  plan: AutonomousPlanItem[];
  queued_runs: Array<{ run_id: string; agent_id: string; run_order: number }>;
  queue: { pending: number; processing: boolean };
}

interface LaunchOptions {
  maxAgents: number;
  goal: string;
}

type ExtractedTargets = ReturnType<typeof extractTargets>;

const CATEGORY_PRIORITY = [
  "recon",
  "api-security",
  "appsec",
  "cloud-k8s",
  "iam",
  "data-security",
  "dependency-sbom",
  "runtime-detection",
  "compliance",
  "remediation",
];

const KEYWORD_MAP: Array<{ regex: RegExp; categories: string[] }> = [
  { regex: /api|rest|graphql|token|idor|rate/i, categories: ["api-security", "iam"] },
  { regex: /xss|sqli|csrf|input|web|frontend/i, categories: ["appsec"] },
  { regex: /cloud|k8s|kubernetes|container|pod|iam/i, categories: ["cloud-k8s", "iam"] },
  { regex: /pii|privacy|data|encryption|backup/i, categories: ["data-security"] },
  { regex: /dependency|sbom|supply|pipeline|ci\/cd/i, categories: ["dependency-sbom"] },
  { regex: /monitor|alert|incident|detect|soc/i, categories: ["runtime-detection"] },
  { regex: /soc2|nist|iso|audit|compliance/i, categories: ["compliance"] },
  { regex: /fix|remed|patch|verify|retest/i, categories: ["remediation"] },
  { regex: /domain|dns|ip|recon|surface/i, categories: ["recon"] },
  {
    regex: /traffic|analytics|ga4|funnel|conversion|attribution|session replay/i,
    categories: ["runtime-detection", "data-security", "api-security"],
  },
  {
    regex: /google search|search console|seo|serp|brand query|organic/i,
    categories: ["recon", "runtime-detection", "remediation"],
  },
  {
    regex: /growth|revenue|churn|acquisition|retention/i,
    categories: ["remediation", "runtime-detection", "data-security"],
  },
  {
    regex: /\badmin\.|admin portal|backoffice|control panel|tenant console|dashboard\b/i,
    categories: ["iam", "api-security", "appsec", "runtime-detection"],
  },
  {
    regex: /\bwww\.|marketing site|landing page|public site\b/i,
    categories: ["recon", "appsec", "runtime-detection"],
  },
];

const SAAS_BASELINE_CATEGORIES = [
  "recon",
  "appsec",
  "api-security",
  "iam",
  "runtime-detection",
  "remediation",
];

function buildCategoryBoost(goal: string, targets: ExtractedTargets): Record<string, number> {
  const boosts: Record<string, number> = {};
  for (const category of SAAS_BASELINE_CATEGORIES) {
    boosts[category] = (boosts[category] || 0) + 1;
  }

  for (const entry of KEYWORD_MAP) {
    if (entry.regex.test(goal)) {
      for (const category of entry.categories) {
        boosts[category] = (boosts[category] || 0) + 3;
      }
    }
  }

  const domainsLower = targets.domains.map((domain) => domain.toLowerCase());
  if (domainsLower.length > 0) {
    boosts.recon = (boosts.recon || 0) + 2;
  }
  if (domainsLower.length > 1) {
    boosts["runtime-detection"] = (boosts["runtime-detection"] || 0) + 2;
    boosts.remediation = (boosts.remediation || 0) + 1;
  }
  if (domainsLower.some((domain) => domain.startsWith("admin."))) {
    boosts.iam = (boosts.iam || 0) + 4;
    boosts["api-security"] = (boosts["api-security"] || 0) + 3;
    boosts.appsec = (boosts.appsec || 0) + 2;
  }
  if (domainsLower.some((domain) => domain.startsWith("api."))) {
    boosts["api-security"] = (boosts["api-security"] || 0) + 4;
  }

  return boosts;
}

function scoreAgent(
  agent: AgentListItem,
  categoryBoost: Record<string, number>
): { score: number; reason: string } {
  let score = 0;
  score += categoryBoost[agent.category] || 0;
  score += agent.last_eval_pass ? 2 : 0;
  score += typeof agent.last_eval_score === "number" ? agent.last_eval_score / 50 : 0;
  score += agent.risk_level === "critical" ? 1.5 : agent.risk_level === "high" ? 1 : 0.5;

  let reason = "baseline";
  if (categoryBoost[agent.category]) reason = `goal-matched:${agent.category}`;
  if (agent.last_eval_pass) reason += "+evaluated";
  return { score, reason };
}

function selectAutonomousPlan(
  agents: AgentListItem[],
  goal: string,
  maxAgents: number,
  targets: ExtractedTargets
): AutonomousPlanItem[] {
  const categoryBoost = buildCategoryBoost(goal, targets);
  const scored = agents.map((agent) => {
    const { score, reason } = scoreAgent(agent, categoryBoost);
    return { agent, score, reason };
  });

  scored.sort((a, b) => b.score - a.score);
  const selected: AutonomousPlanItem[] = [];
  const usedCategories = new Set<string>();

  for (const row of scored) {
    if (selected.length >= maxAgents) break;
    if (!usedCategories.has(row.agent.category)) {
      selected.push({
        agent_id: row.agent.id,
        agent_name: row.agent.name,
        category: row.agent.category,
        priority: Math.round(row.score * 10) / 10,
        reason: row.reason,
      });
      usedCategories.add(row.agent.category);
    }
  }

  if (selected.length < maxAgents) {
    for (const row of scored) {
      if (selected.length >= maxAgents) break;
      if (selected.some((item) => item.agent_id === row.agent.id)) continue;
      selected.push({
        agent_id: row.agent.id,
        agent_name: row.agent.name,
        category: row.agent.category,
        priority: Math.round(row.score * 10) / 10,
        reason: row.reason,
      });
    }
  }

  selected.sort((a, b) => {
    const ai = CATEGORY_PRIORITY.indexOf(a.category);
    const bi = CATEGORY_PRIORITY.indexOf(b.category);
    if (ai === -1 && bi === -1) return b.priority - a.priority;
    if (ai === -1) return 1;
    if (bi === -1) return -1;
    return ai - bi;
  });

  return selected.slice(0, maxAgents);
}

function formatTargetContext(targets: ExtractedTargets): string {
  if (
    targets.urls.length === 0 &&
    targets.domains.length === 0 &&
    targets.ips.length === 0
  ) {
    return "- No explicit URLs/domains/IPs were parsed from the goal.";
  }

  const lines: string[] = [];
  if (targets.urls.length > 0) lines.push(`- URLs: ${targets.urls.join(", ")}`);
  if (targets.domains.length > 0) lines.push(`- Domains: ${targets.domains.join(", ")}`);
  if (targets.ips.length > 0) lines.push(`- IPs: ${targets.ips.join(", ")}`);
  return lines.join("\n");
}

function buildCategoryDirective(category: string): string {
  switch (category) {
    case "recon":
      return "Map internet-facing assets, trust boundaries, and likely attack paths from external footprint.";
    case "api-security":
      return "Prioritize authn/authz flaws, IDOR, token leakage, excessive data exposure, and rate-limit weaknesses.";
    case "appsec":
      return "Focus on web app attack classes (XSS/CSRF/input validation/session issues) and exploitability.";
    case "iam":
      return "Assess privilege boundaries, role assumptions, admin path hardening, and secret handling exposure.";
    case "cloud-k8s":
      return "Validate cloud/container runtime posture, exposed services, and least-privilege control drift.";
    case "data-security":
      return "Review sensitive data paths, retention/backup controls, encryption posture, and exfiltration risks.";
    case "runtime-detection":
      return "Design practical detection logic with alert thresholds, telemetry requirements, and triage playbooks.";
    case "compliance":
      return "Map findings to concrete control evidence and define remediation proof required for audit acceptance.";
    case "remediation":
      return "Produce fix sequencing with owners, ETA, rollback safety, and retest acceptance criteria.";
    default:
      return "Produce the most actionable risk-reduction workstream for this campaign lane.";
  }
}

function buildAutonomousInput(args: {
  goal: string;
  runOrder: number;
  totalRuns: number;
  campaignId: string;
  campaignCorrelationId: string;
  category: string;
  agentName: string;
  targets: ExtractedTargets;
}): string {
  const {
    goal,
    runOrder,
    totalRuns,
    campaignId,
    campaignCorrelationId,
    category,
    agentName,
    targets,
  } = args;
  return `Autonomous campaign execution (${runOrder}/${totalRuns}):

Campaign context:
- Campaign id: ${campaignId}
- Correlation id: ${campaignCorrelationId}
- Agent lane: ${agentName} (${category})

Scope targets:
${formatTargetContext(targets)}

Goal:
${goal}

Category directive:
${buildCategoryDirective(category)}

Operational requirements:
- Produce actionable security tasks with validation checks.
- Include evidence collection steps for auditability.
- Include severity, business impact, and exploit preconditions for each finding.
- Include "fix now / fix next / monitor" prioritization for SaaS operators.
- Add a retest checklist with explicit pass/fail criteria.
- Do not execute destructive actions.
`;
}

export async function launchAutonomousCampaign(
  userId: string,
  options: LaunchOptions
): Promise<AutonomousLaunchResult> {
  const activeAgents = await listActiveAgents(userId);
  if (activeAgents.length === 0) {
    throw new Error("No active agents available.");
  }

  const campaign = await createCampaign(userId, options.goal);
  const targets = extractTargets(options.goal);
  const plan = selectAutonomousPlan(activeAgents, options.goal, options.maxAgents, targets);
  const campaignCorrelationId = randomUUID();
  await markCampaignStatus(campaign.id, userId, "running");

  const queuedRuns: AutonomousLaunchResult["queued_runs"] = [];
  for (let i = 0; i < plan.length; i++) {
    const item = plan[i];
    const runOrder = i + 1;
    const inputText = buildAutonomousInput({
      goal: options.goal,
      runOrder,
      totalRuns: plan.length,
      campaignId: campaign.id,
      campaignCorrelationId,
      category: item.category,
      agentName: item.agent_name,
      targets,
    });
    const run = await createAgentRun(userId, item.agent_id, inputText);
    await addCampaignRun(campaign.id, item.agent_id, run.id, runOrder);
    enqueueAgentRun({
      runId: run.id,
      userId,
      agentId: item.agent_id,
      inputText,
    });
    queuedRuns.push({ run_id: run.id, agent_id: item.agent_id, run_order: runOrder });
  }

  return {
    campaign,
    plan,
    queued_runs: queuedRuns,
    queue: getQueueState(),
  };
}
