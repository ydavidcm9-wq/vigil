export interface StarterFaqEntry {
  category: string;
  question: string;
  answer: string;
  tags: string[];
}

export const STARTER_FAQ_ENTRIES: StarterFaqEntry[] = [
  {
    category: "Getting Started",
    question: "What is Vigil built for?",
    answer:
      "Vigil helps teams run practical security audits for SaaS apps. It combines scans, findings triage, remediation guidance, and AI-assisted workflows in one dashboard.",
    tags: ["overview", "saas", "security-audit"],
  },
  {
    category: "Getting Started",
    question: "What should I do first after onboarding?",
    answer:
      "Start with asset scope, configure scan defaults, run a baseline web scan, and review critical/high findings first. Then use AI Chat to build a remediation plan.",
    tags: ["onboarding", "baseline", "workflow"],
  },
  {
    category: "Getting Started",
    question: "How do I run a complete audit in this platform?",
    answer:
      "Use the AI Chat Step 1-20 playbook. Follow each step in order: scope, auth controls, injection checks, dependency risk, API tests, remediation sprint, and retest.",
    tags: ["playbook", "step-1-20", "audit"],
  },
  {
    category: "Scanning",
    question: "When should I use OWASP ZAP?",
    answer:
      "Use ZAP for web application testing: XSS, injection patterns, auth/session weaknesses, and common web misconfigurations.",
    tags: ["zap", "web", "dast"],
  },
  {
    category: "Scanning",
    question: "When should I use Nuclei?",
    answer:
      "Use Nuclei for fast template-driven checks across known CVEs, exposures, misconfigurations, and technology-specific issues.",
    tags: ["nuclei", "templates", "cve"],
  },
  {
    category: "Scanning",
    question: "When should I use Nmap?",
    answer:
      "Use Nmap to enumerate ports/services, validate exposed attack surface, and identify unexpected network paths.",
    tags: ["nmap", "network", "attack-surface"],
  },
  {
    category: "Scanning",
    question: "When should I use Trivy?",
    answer:
      "Use Trivy for container image and dependency vulnerability scanning. Prioritize fixes by exploitability and runtime exposure.",
    tags: ["trivy", "container", "dependencies"],
  },
  {
    category: "Findings",
    question: "How should we prioritize vulnerabilities?",
    answer:
      "Prioritize by exploitability and business impact, not severity label alone. Handle critical/high internet-facing issues first, then chainable medium risks.",
    tags: ["prioritization", "risk", "triage"],
  },
  {
    category: "Findings",
    question: "What evidence should be attached to a finding?",
    answer:
      "Capture scanner output, affected endpoint/service, reproduction steps, request/response snippets, and verification method after the fix.",
    tags: ["evidence", "validation", "workflow"],
  },
  {
    category: "Findings",
    question: "How do we verify remediation is complete?",
    answer:
      "Retest with the same scanner, run a focused regression check, and record before/after evidence. Mark finding remediated only after verification passes.",
    tags: ["retest", "remediation", "quality-gate"],
  },
  {
    category: "AI Chat",
    question: "How does AI Chat use local data?",
    answer:
      "AI Chat retrieves context from your local knowledge base (notes, FAQ docs, and prior chat knowledge chunks) and uses Ollama locally for responses.",
    tags: ["rag", "ollama", "local-llm"],
  },
  {
    category: "AI Chat",
    question: "Can users resume old conversations?",
    answer:
      "Yes. Conversations and messages are stored in PostgreSQL. Users can reopen history, continue threads, edit notes, and pick up where they left off.",
    tags: ["history", "chat", "persistence"],
  },
  {
    category: "AI Chat",
    question: "What are AI Notes used for?",
    answer:
      "AI Notes store investigation context, decisions, and remediation plans. Notes can be pinned, edited, and linked to specific conversations.",
    tags: ["notes", "knowledge", "documentation"],
  },
  {
    category: "Compliance",
    question: "Does this replace external compliance audits?",
    answer:
      "No. It accelerates preparation by collecting technical evidence and remediation records, but formal certification still requires independent assessor review.",
    tags: ["compliance", "audit", "evidence"],
  },
  {
    category: "Compliance",
    question: "How can we map work to SOC 2 or ISO 27001 controls?",
    answer:
      "Use notes and reports to map findings/remediation to control objectives, then maintain proof artifacts such as logs, test evidence, and approvals.",
    tags: ["soc2", "iso27001", "controls"],
  },
  {
    category: "Operations",
    question: "Where are models and data stored?",
    answer:
      "Ollama model files are stored on local Docker volumes, and application data is stored in PostgreSQL. This keeps core inference and evidence local.",
    tags: ["storage", "docker", "data-residency"],
  },
  {
    category: "Operations",
    question: "How do we update LLM settings safely?",
    answer:
      "Use Settings > LLM to change base URL, default model, embedding model, and retrieval depth. Test with a known prompt before production rollout.",
    tags: ["settings", "llm", "change-management"],
  },
  {
    category: "Operations",
    question: "What should we monitor daily?",
    answer:
      "Monitor service health, failed scans, new critical findings, model availability, and chat/API error rates.",
    tags: ["monitoring", "ops", "health"],
  },
  {
    category: "Security Hardening",
    question: "Should we allow direct SSH auto-remediation from the app?",
    answer:
      "Only with strict controls: just-in-time credentials, command allowlists, approval gates, full command logging, and isolated remediation sandboxes.",
    tags: ["ssh", "automation", "risk"],
  },
  {
    category: "Security Hardening",
    question: "How do we reduce prompt injection risk?",
    answer:
      "Use system guardrails, input sanitation, explicit tool permissioning, and require verification evidence before acting on AI-generated remediation steps.",
    tags: ["prompt-injection", "guardrails", "ai-security"],
  },
  {
    category: "Security Hardening",
    question: "How should we use cookies defensively in SaaS auth?",
    answer:
      "Store session cookies as httpOnly + secure + sameSite, rotate sessions on login, and enforce CSRF/origin checks for state-changing requests. This blocks token theft via script access and reduces cross-site request abuse.",
    tags: ["cookies", "session-security", "csrf"],
  },
  {
    category: "Autonomous Agents",
    question: "How do autonomous agent campaigns help our SaaS business?",
    answer:
      "Autonomous campaigns run parallel security workflows so teams find, prioritize, and fix risks faster. This reduces incident cost, shortens audit prep time, and protects conversion-critical journeys such as signup and checkout.",
    tags: ["autonomous", "business-value", "operations"],
  },
  {
    category: "Autonomous Agents",
    question: "What campaign goal should we run first for agency-grade security?",
    answer:
      "Start with: 'Assess internet-facing surface, auth/session risks, API abuse paths, and top remediation actions with audit evidence.' This triggers broad coverage while staying focused on actionable fixes.",
    tags: ["campaign", "agency", "kickoff"],
  },
  {
    category: "Traffic Intelligence",
    question: "Which traffic data should we use for security decisions?",
    answer:
      "Use web/app telemetry, auth events, API latency/error trends, WAF/CDN logs, and conversion funnel metrics. Correlate these with scan findings to distinguish normal growth from abuse or attack activity.",
    tags: ["traffic", "telemetry", "decisioning"],
  },
  {
    category: "Traffic Intelligence",
    question: "How do we use Google Search data safely?",
    answer:
      "Ingest only approved metadata from Google Search Console (queries, pages, CTR, impressions, average position). Do not ingest PII, and enforce role-based access, retention limits, and redaction before AI analysis.",
    tags: ["google-search", "search-console", "privacy"],
  },
  {
    category: "Traffic Intelligence",
    question: "Can we run Google intelligence without API keys?",
    answer:
      "Yes. Use no-key mode for baseline SERP intelligence, then upgrade to Custom Search API when you need higher reliability and quota guarantees. Keep no-key mode as fallback for resilience.",
    tags: ["google-search", "no-key", "resilience"],
  },
  {
    category: "Traffic Intelligence",
    question: "How can we detect attack-driven traffic anomalies?",
    answer:
      "Track abrupt shifts in bot ratio, failed auths, unusual endpoint patterns, and geo/device spikes. Combine anomaly alerts with recent findings and deploy focused mitigations (rate limits, bot rules, auth hardening).",
    tags: ["anomaly-detection", "bot-defense", "incident-response"],
  },
  {
    category: "Growth + Security",
    question: "How do we connect security findings to revenue impact?",
    answer:
      "Tag each finding to business journeys (signup, trial activation, billing, account recovery). Prioritize remediation by exploitability and customer impact so engineering effort aligns with trust and growth outcomes.",
    tags: ["revenue", "prioritization", "risk"],
  },
  {
    category: "Growth + Security",
    question: "Can generative AI help with SEO/security strategy at the same time?",
    answer:
      "Yes. Use AI to summarize search visibility changes, correlate with platform risk, and propose safe experiments. Keep a human approval gate for production changes and require evidence-backed recommendations.",
    tags: ["genai", "seo", "strategy"],
  },
  {
    category: "Generative AI Ops",
    question: "What data should never be sent to LLM prompts?",
    answer:
      "Never send plaintext credentials, secret keys, session tokens, private customer payloads, or unreleased incident details. Store secrets in protected settings and pass only redacted context to models.",
    tags: ["llm-safety", "secrets", "data-protection"],
  },
  {
    category: "Generative AI Ops",
    question: "How do we keep AI outputs user-friendly for non-security teams?",
    answer:
      "Use structured outputs: situation, business impact, recommended action, owner, ETA, and validation checks. Keep language plain and map each action to an outcome the business team understands.",
    tags: ["ux", "communication", "cross-functional"],
  },
  {
    category: "Generative AI Ops",
    question: "How should we evaluate AI recommendations before execution?",
    answer:
      "Require reproducible evidence, expected side effects, rollback steps, and explicit approval for high-risk actions. Treat AI output as a draft until validated by engineering or security owners.",
    tags: ["validation", "approval", "change-management"],
  },
  {
    category: "Leadership Metrics",
    question: "Which KPIs prove this platform is helping the business?",
    answer:
      "Track MTTD/MTTR, critical finding closure time, regression rate, incident-driven traffic loss, and remediation throughput. Pair technical metrics with business metrics such as signup conversion and churn risk.",
    tags: ["kpi", "leadership", "outcomes"],
  },
  {
    category: "Leadership Metrics",
    question: "How often should we refresh FAQ and playbooks?",
    answer:
      "Review weekly during active remediation and monthly during steady state. Update when major incidents, architecture changes, or compliance requirements change.",
    tags: ["knowledge-management", "governance", "cadence"],
  },
];
