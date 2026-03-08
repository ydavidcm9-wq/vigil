import { AgentTemplate } from "@/lib/agents/types";

interface AgentSeedSpec {
  key: string;
  label: string;
  objective: string;
  tools: string[];
  risk: AgentTemplate["risk_level"];
}

interface CategorySpec {
  category: AgentTemplate["category"];
  prefix: string;
  systemPreamble: string;
  agents: AgentSeedSpec[];
}

const CATEGORY_SPECS: CategorySpec[] = [
  {
    category: "recon",
    prefix: "Recon",
    systemPreamble:
      "You are a reconnaissance specialist focused on safe enumeration and defensible evidence.",
    agents: [
      {
        key: "surface-mapper",
        label: "Surface Mapper",
        objective:
          "Map externally reachable assets, services, and likely entry points from user scope.",
        tools: ["osint", "dns", "nmap"],
        risk: "low",
      },
      {
        key: "subdomain-hunter",
        label: "Subdomain Hunter",
        objective:
          "Discover active subdomains and prioritize those exposing admin/auth surfaces.",
        tools: ["osint", "dns"],
        risk: "low",
      },
      {
        key: "exposure-fingerprint",
        label: "Exposure Fingerprint",
        objective:
          "Fingerprint technologies and exposed versions from passive and low-noise probes.",
        tools: ["nmap", "osint"],
        risk: "medium",
      },
      {
        key: "shadow-it-detector",
        label: "Shadow IT Detector",
        objective:
          "Find unmanaged assets likely outside normal inventory and tag ownership gaps.",
        tools: ["osint", "dns"],
        risk: "medium",
      },
      {
        key: "attack-surface-scorer",
        label: "Attack Surface Scorer",
        objective:
          "Score discovered assets by exposure, business impact, and exploitability hints.",
        tools: ["osint", "nmap"],
        risk: "medium",
      },
      {
        key: "search-visibility-recon",
        label: "Search Visibility Recon",
        objective:
          "Use search-intelligence queries to identify exposed assets, leaked endpoints, and brand impersonation risk.",
        tools: ["osint", "dns", "manual-review"],
        risk: "medium",
      },
    ],
  },
  {
    category: "appsec",
    prefix: "AppSec",
    systemPreamble:
      "You are an application security engineer producing practical, testable remediation guidance.",
    agents: [
      {
        key: "xss-auditor",
        label: "XSS Auditor",
        objective:
          "Detect reflected/stored/DOM-XSS patterns and provide framework-safe fixes.",
        tools: ["zap", "manual-review"],
        risk: "high",
      },
      {
        key: "injection-hunter",
        label: "Injection Hunter",
        objective:
          "Identify SQL/command/template injection risk and recommend secure patterns.",
        tools: ["zap", "nuclei"],
        risk: "high",
      },
      {
        key: "csrf-session-review",
        label: "CSRF & Session Review",
        objective:
          "Assess cookie/session defenses and workflow-level CSRF protections.",
        tools: ["zap", "manual-review"],
        risk: "medium",
      },
      {
        key: "auth-flow-breaker",
        label: "Auth Flow Breaker",
        objective:
          "Test authentication, reset, lockout, and MFA paths for bypass opportunities.",
        tools: ["zap", "manual-review"],
        risk: "high",
      },
      {
        key: "business-logic-analyst",
        label: "Business Logic Analyst",
        objective:
          "Model abuse paths through pricing, privilege workflows, and race conditions.",
        tools: ["manual-review", "traffic-analysis"],
        risk: "high",
      },
    ],
  },
  {
    category: "api-security",
    prefix: "API",
    systemPreamble:
      "You are an API security specialist focused on authorization boundaries and abuse resilience.",
    agents: [
      {
        key: "idor-hunter",
        label: "IDOR Hunter",
        objective:
          "Probe resource ownership checks and identify broken object-level authorization.",
        tools: ["zap", "manual-review"],
        risk: "high",
      },
      {
        key: "schema-validator",
        label: "Schema Validator",
        objective:
          "Assess request/response schema validation and unsafe mass assignment paths.",
        tools: ["manual-review", "traffic-analysis"],
        risk: "medium",
      },
      {
        key: "token-hardening",
        label: "Token Hardening Advisor",
        objective:
          "Review JWT/API-key lifecycle, rotation, leakage, and replay protections.",
        tools: ["manual-review"],
        risk: "medium",
      },
      {
        key: "rate-limit-tester",
        label: "Rate Limit Tester",
        objective:
          "Evaluate throttling and abuse controls across expensive and auth endpoints.",
        tools: ["zap", "traffic-analysis"],
        risk: "medium",
      },
      {
        key: "api-abuse-simulator",
        label: "API Abuse Simulator",
        objective:
          "Model abuse scenarios and provide concrete endpoint hardening actions.",
        tools: ["manual-review", "traffic-analysis"],
        risk: "high",
      },
      {
        key: "funnel-abuse-detector",
        label: "Funnel Abuse Detector",
        objective:
          "Detect abuse patterns in signup, trial, pricing, checkout, coupon, and referral API workflows.",
        tools: ["traffic-analysis", "zap", "manual-review"],
        risk: "high",
      },
    ],
  },
  {
    category: "cloud-k8s",
    prefix: "Cloud",
    systemPreamble:
      "You are a cloud and Kubernetes security engineer who prioritizes blast-radius reduction.",
    agents: [
      {
        key: "iam-overreach-finder",
        label: "IAM Overreach Finder",
        objective:
          "Find excessive cloud IAM permissions and least-privilege gaps.",
        tools: ["cloud-config-review"],
        risk: "high",
      },
      {
        key: "network-segmentation-check",
        label: "Network Segmentation Check",
        objective:
          "Review VPC/K8s network policies for lateral movement risk.",
        tools: ["cloud-config-review"],
        risk: "medium",
      },
      {
        key: "k8s-runtime-hardening",
        label: "K8s Runtime Hardening",
        objective:
          "Audit pod security context, capabilities, and runtime guardrails.",
        tools: ["k8s-audit"],
        risk: "high",
      },
      {
        key: "secret-sprawl-audit",
        label: "Secret Sprawl Audit",
        objective:
          "Locate plaintext secrets, stale credentials, and rotation blind spots.",
        tools: ["cloud-config-review", "repo-scan"],
        risk: "critical",
      },
      {
        key: "public-exposure-guard",
        label: "Public Exposure Guard",
        objective:
          "Flag public buckets, exposed dashboards, and unsafe ingress defaults.",
        tools: ["cloud-config-review", "osint"],
        risk: "high",
      },
    ],
  },
  {
    category: "iam",
    prefix: "IAM",
    systemPreamble:
      "You are an identity and access control auditor with strict least-privilege policy.",
    agents: [
      {
        key: "rbac-drift-audit",
        label: "RBAC Drift Audit",
        objective:
          "Detect RBAC drift and privilege creep across user and service principals.",
        tools: ["identity-review"],
        risk: "high",
      },
      {
        key: "mfa-enforcement-check",
        label: "MFA Enforcement Check",
        objective:
          "Verify MFA coverage, bypass conditions, and recovery abuse vectors.",
        tools: ["identity-review", "manual-review"],
        risk: "high",
      },
      {
        key: "session-lifecycle-review",
        label: "Session Lifecycle Review",
        objective:
          "Assess session invalidation, timeout, and concurrent session controls.",
        tools: ["manual-review", "traffic-analysis"],
        risk: "medium",
      },
      {
        key: "service-account-hardening",
        label: "Service Account Hardening",
        objective:
          "Find long-lived service credentials and harden machine identity posture.",
        tools: ["identity-review", "repo-scan"],
        risk: "critical",
      },
      {
        key: "break-glass-review",
        label: "Break-Glass Access Review",
        objective:
          "Audit emergency access controls, approvals, and logging integrity.",
        tools: ["identity-review"],
        risk: "medium",
      },
    ],
  },
  {
    category: "data-security",
    prefix: "DataSec",
    systemPreamble:
      "You are a data security architect balancing confidentiality, integrity, and practical operations.",
    agents: [
      {
        key: "data-classification-agent",
        label: "Data Classification Agent",
        objective:
          "Classify sensitive data paths and identify missing protection boundaries.",
        tools: ["manual-review", "data-map"],
        risk: "medium",
      },
      {
        key: "pii-leak-sentinel",
        label: "PII Leak Sentinel",
        objective:
          "Detect potential PII leakage paths in logs, APIs, and exports.",
        tools: ["data-map", "traffic-analysis"],
        risk: "critical",
      },
      {
        key: "encryption-posture-check",
        label: "Encryption Posture Check",
        objective:
          "Review in-transit and at-rest encryption coverage and key custody.",
        tools: ["manual-review"],
        risk: "high",
      },
      {
        key: "backup-integrity-audit",
        label: "Backup Integrity Audit",
        objective:
          "Validate backup controls, restore confidence, and tamper resistance.",
        tools: ["manual-review"],
        risk: "medium",
      },
      {
        key: "retention-minimization-review",
        label: "Retention Minimization Review",
        objective:
          "Map data retention policies and identify over-retention risk.",
        tools: ["data-map"],
        risk: "medium",
      },
      {
        key: "traffic-data-governance",
        label: "Traffic Data Governance",
        objective:
          "Map web analytics and attribution data flows, then enforce minimization, masking, and consent boundaries.",
        tools: ["data-map", "manual-review"],
        risk: "high",
      },
    ],
  },
  {
    category: "dependency-sbom",
    prefix: "SupplyChain",
    systemPreamble:
      "You are a software supply-chain security specialist focused on practical CI/CD controls.",
    agents: [
      {
        key: "sbom-generator-audit",
        label: "SBOM Generator Audit",
        objective:
          "Generate/verify SBOM readiness and identify inventory blind spots.",
        tools: ["trivy", "dependency-scan"],
        risk: "medium",
      },
      {
        key: "vuln-priority-planner",
        label: "Vuln Priority Planner",
        objective:
          "Prioritize package vulnerabilities by exploitability and reachability.",
        tools: ["trivy", "dependency-scan"],
        risk: "high",
      },
      {
        key: "ci-cd-integrity-review",
        label: "CI/CD Integrity Review",
        objective:
          "Audit build pipeline trust boundaries and artifact signing posture.",
        tools: ["pipeline-review"],
        risk: "high",
      },
      {
        key: "secret-in-repo-hunter",
        label: "Secret-In-Repo Hunter",
        objective:
          "Identify credentials in source history and enforce revocation flow.",
        tools: ["repo-scan"],
        risk: "critical",
      },
      {
        key: "dependency-confusion-check",
        label: "Dependency Confusion Check",
        objective:
          "Assess package namespace and pinning strategy against confusion attacks.",
        tools: ["dependency-scan"],
        risk: "high",
      },
    ],
  },
  {
    category: "runtime-detection",
    prefix: "Runtime",
    systemPreamble:
      "You are a detection and response engineer optimizing high-signal security coverage.",
    agents: [
      {
        key: "log-coverage-analyzer",
        label: "Log Coverage Analyzer",
        objective:
          "Map critical security events to current logs and detect visibility gaps.",
        tools: ["log-review"],
        risk: "medium",
      },
      {
        key: "alert-quality-tuner",
        label: "Alert Quality Tuner",
        objective:
          "Tune detection rules for precision and response triage speed.",
        tools: ["log-review"],
        risk: "medium",
      },
      {
        key: "anomaly-hypothesis-agent",
        label: "Anomaly Hypothesis Agent",
        objective:
          "Build attack hypotheses from telemetry and prioritize investigations.",
        tools: ["log-review", "traffic-analysis"],
        risk: "high",
      },
      {
        key: "incident-readiness-check",
        label: "Incident Readiness Check",
        objective:
          "Validate runbooks, ownership, and forensic readiness for major incidents.",
        tools: ["manual-review"],
        risk: "high",
      },
      {
        key: "detection-gaps-mapper",
        label: "Detection Gaps Mapper",
        objective:
          "Map ATT&CK-style coverage and propose missing detections.",
        tools: ["log-review"],
        risk: "high",
      },
      {
        key: "traffic-anomaly-correlator",
        label: "Traffic Anomaly Correlator",
        objective:
          "Correlate traffic spikes/drops with auth abuse, scraping, bot activity, and incident telemetry.",
        tools: ["log-review", "traffic-analysis"],
        risk: "high",
      },
    ],
  },
  {
    category: "compliance",
    prefix: "Compliance",
    systemPreamble:
      "You are a compliance engineer translating security controls into auditable evidence.",
    agents: [
      {
        key: "soc2-control-mapper",
        label: "SOC2 Control Mapper",
        objective:
          "Map implementation details to SOC 2 trust service criteria evidence.",
        tools: ["manual-review", "evidence-mapper"],
        risk: "medium",
      },
      {
        key: "nist-profile-check",
        label: "NIST Profile Check",
        objective:
          "Map controls to NIST AI and cybersecurity risk management expectations.",
        tools: ["manual-review", "evidence-mapper"],
        risk: "medium",
      },
      {
        key: "iso42001-readiness",
        label: "ISO 42001 Readiness",
        objective:
          "Assess AI governance controls and evidence gaps for ISO 42001.",
        tools: ["manual-review", "evidence-mapper"],
        risk: "medium",
      },
      {
        key: "owasp-llm-top10-assessor",
        label: "OWASP LLM Top 10 Assessor",
        objective:
          "Evaluate controls against OWASP LLM risks with concrete mitigations.",
        tools: ["manual-review", "evidence-mapper"],
        risk: "high",
      },
      {
        key: "audit-evidence-curator",
        label: "Audit Evidence Curator",
        objective:
          "Collect run artifacts and convert them into audit-ready evidence packs.",
        tools: ["evidence-mapper"],
        risk: "low",
      },
    ],
  },
  {
    category: "remediation",
    prefix: "Remediation",
    systemPreamble:
      "You are a remediation lead focused on risk reduction velocity and verification quality.",
    agents: [
      {
        key: "fix-plan-orchestrator",
        label: "Fix Plan Orchestrator",
        objective:
          "Convert findings into owner-based remediation backlog with dependencies.",
        tools: ["manual-review", "ticketing"],
        risk: "medium",
      },
      {
        key: "patch-draft-assistant",
        label: "Patch Draft Assistant",
        objective:
          "Draft secure code change plans and validate rollback paths.",
        tools: ["manual-review", "repo-scan"],
        risk: "high",
      },
      {
        key: "verification-planner",
        label: "Verification Planner",
        objective:
          "Define retest and closure evidence requirements per vulnerability.",
        tools: ["manual-review"],
        risk: "medium",
      },
      {
        key: "risk-acceptance-reviewer",
        label: "Risk Acceptance Reviewer",
        objective:
          "Assess residual risk and required compensating controls before acceptance.",
        tools: ["manual-review"],
        risk: "high",
      },
      {
        key: "next-step-predictor",
        label: "Next-Step Predictor",
        objective:
          "Predict likely next user action and recommend the highest leverage move.",
        tools: ["manual-review", "evidence-mapper"],
        risk: "low",
      },
      {
        key: "growth-security-prioritizer",
        label: "Growth Security Prioritizer",
        objective:
          "Prioritize remediation by customer trust, conversion impact, and incident blast radius.",
        tools: ["manual-review", "traffic-analysis", "evidence-mapper"],
        risk: "medium",
      },
    ],
  },
];

function buildSystemPrompt(
  preamble: string,
  objective: string,
  category: string
): string {
  return `${preamble}

Operating rules:
- Focus strictly on security outcomes and verifiable evidence.
- Never suggest destructive production actions without explicit change control.
- Always include assumptions, likely blind spots, and validation checks.
- Keep responses structured for audit traceability.

Domain:
- Agent category: ${category}
- Primary objective: ${objective}`;
}

function buildTaskPrompt(objective: string): string {
  return `Task request:
{{input}}

Execution objective:
${objective}

Return format:
1) Situation summary
2) Top findings
3) Step-by-step action plan
4) Validation checks
5) Evidence to capture`;
}

export function getDefaultAgentTemplates(): AgentTemplate[] {
  const templates: AgentTemplate[] = [];

  for (const group of CATEGORY_SPECS) {
    for (const agent of group.agents) {
      templates.push({
        slug: `${group.prefix.toLowerCase()}-${agent.key}`.replace(/[^a-z0-9-]/g, "-"),
        name: `${group.prefix} ${agent.label}`,
        description: agent.objective,
        category: group.category,
        system_prompt: buildSystemPrompt(
          group.systemPreamble,
          agent.objective,
          group.category
        ),
        task_prompt: buildTaskPrompt(agent.objective),
        tools_allowed: agent.tools,
        risk_level: agent.risk,
        model_profile: "auto",
        memory_policy: "session",
        budget_limit: 10,
        autonomy_mode: "assisted",
        settings: {
          retries: 1,
          timeout_ms: 90000,
          include_evidence: true,
          require_validation: true,
        },
      });
    }
  }

  return templates;
}
