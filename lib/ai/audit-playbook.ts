export interface AuditPlaybookStep {
  step: number;
  title: string;
  objective: string;
  prompt: string;
}

export const AUDIT_PLAYBOOK_STEPS: AuditPlaybookStep[] = [
  {
    step: 1,
    title: "Scope and Asset Inventory",
    objective: "Define what is in scope and list all internet-facing assets.",
    prompt:
      "Step 1 audit kickoff: Help me define scope for my SaaS security audit. Ask me for domains, IPs, cloud providers, APIs, repos, and third-party services. Then produce a clean in-scope asset list and out-of-scope list.",
  },
  {
    step: 2,
    title: "Authentication and Access Control",
    objective: "Verify MFA, password policy, and role permissions.",
    prompt:
      "Step 2 access control review: Create a checklist to test MFA enforcement, password reset flow, session invalidation, and least-privilege roles in my SaaS app.",
  },
  {
    step: 3,
    title: "Session and Token Security",
    objective: "Harden cookies, JWT/session lifetime, and logout behavior.",
    prompt:
      "Step 3 session review: Audit my session and token security. Include cookie flags, token expiration, rotation, replay risks, CSRF controls, and logout invalidation tests.",
  },
  {
    step: 4,
    title: "Input Validation and XSS/Injection",
    objective: "Check all user inputs for XSS, SQLi, command injection, and SSRF.",
    prompt:
      "Step 4 injection testing: Build a practical test plan for XSS, SQL injection, command injection, template injection, and SSRF across my web forms and API endpoints.",
  },
  {
    step: 5,
    title: "Dependency and Supply Chain Risk",
    objective: "Identify vulnerable dependencies and risky build artifacts.",
    prompt:
      "Step 5 supply chain audit: Review my dependency risk strategy. Provide commands and workflow for vulnerability scanning, lockfile hygiene, SBOM generation, and patch prioritization.",
  },
  {
    step: 6,
    title: "Secrets and Key Management",
    objective: "Ensure no secrets are leaked and keys are rotated safely.",
    prompt:
      "Step 6 secrets audit: Create a secrets-management checklist for my SaaS. Cover repo leaks, env var handling, key rotation cadence, and emergency key revocation.",
  },
  {
    step: 7,
    title: "Transport and Encryption",
    objective: "Validate TLS configuration and data encryption practices.",
    prompt:
      "Step 7 encryption review: Audit TLS settings, HSTS, certificate lifecycle, and at-rest encryption for user data, backups, and logs. Explain risks and fixes in plain English.",
  },
  {
    step: 8,
    title: "Cloud IAM and Network Segmentation",
    objective: "Tighten cloud identity roles and reduce lateral movement.",
    prompt:
      "Step 8 cloud hardening: Give me a cloud IAM and network segmentation audit playbook for AWS/GCP/Azure style environments with least privilege and deny-by-default principles.",
  },
  {
    step: 9,
    title: "Logging, Monitoring, and Alerting",
    objective: "Confirm high-value security events are logged and monitored.",
    prompt:
      "Step 9 detection coverage: List what security events I must log for a SaaS app and map each to alerts. Include login abuse, privilege changes, key actions, and suspicious API usage.",
  },
  {
    step: 10,
    title: "Backup and Disaster Recovery",
    objective: "Prove recoverability and validate restore procedures.",
    prompt:
      "Step 10 resilience check: Build a backup and disaster recovery test plan for my SaaS, including RPO/RTO targets, restore drills, and ransomware recovery steps.",
  },
  {
    step: 11,
    title: "Automated Vulnerability Scanning",
    objective: "Run baseline web, network, and container vulnerability scans.",
    prompt:
      "Step 11 scanning baseline: Recommend the exact sequence of scans (web, network, container) I should run first on my SaaS, with expected findings and false-positive handling.",
  },
  {
    step: 12,
    title: "Container and Runtime Hardening",
    objective: "Minimize attack surface in images and runtime configuration.",
    prompt:
      "Step 12 container hardening: Audit my container security posture for base image hygiene, rootless runtime, dropped capabilities, seccomp/apparmor, and read-only filesystem settings.",
  },
  {
    step: 13,
    title: "API Security Controls",
    objective: "Validate authz, rate limits, schema validation, and abuse resistance.",
    prompt:
      "Step 13 API audit: Create an API security test matrix for authz bypass, mass assignment, IDOR, schema validation, and sensitive data exposure.",
  },
  {
    step: 14,
    title: "Abuse Prevention and Rate Limiting",
    objective: "Reduce brute force, scraping, and automation abuse risk.",
    prompt:
      "Step 14 abuse resistance: Design anti-abuse controls for login, signup, password reset, and high-cost endpoints. Include rate limits, bot detection, and lockout strategy.",
  },
  {
    step: 15,
    title: "Business Logic and Fraud Testing",
    objective: "Find logic flaws that bypass expected workflows.",
    prompt:
      "Step 15 business logic review: Help me test for workflow abuse, pricing manipulation, privilege escalation through logic flaws, and race condition exploits.",
  },
  {
    step: 16,
    title: "Incident Response Readiness",
    objective: "Prepare for detection, containment, and communication.",
    prompt:
      "Step 16 incident readiness: Create an incident response runbook for my SaaS with severity levels, triage owners, containment steps, forensics checklist, and customer comms templates.",
  },
  {
    step: 17,
    title: "Compliance Control Mapping",
    objective: "Map technical controls to common compliance frameworks.",
    prompt:
      "Step 17 compliance mapping: Map my security controls to SOC 2 and ISO 27001 style requirements. Show what evidence I should collect for each control.",
  },
  {
    step: 18,
    title: "Remediation Sprint Plan",
    objective: "Prioritize fixes by risk reduction and implementation effort.",
    prompt:
      "Step 18 remediation planning: Turn my findings into a 30-day remediation sprint grouped by critical/high/medium risk with owner, ETA, and validation steps.",
  },
  {
    step: 19,
    title: "Retest and Verification",
    objective: "Verify fixes and confirm vulnerabilities are closed.",
    prompt:
      "Step 19 retest: Give me a retesting checklist to verify each fixed vulnerability, including what evidence proves closure and what triggers reopening.",
  },
  {
    step: 20,
    title: "Executive Security Report",
    objective: "Summarize posture, residual risk, and continuous monitoring plan.",
    prompt:
      "Step 20 executive summary: Generate a concise executive security report from all audit work: top risks, what was fixed, residual risks, and next-quarter security roadmap.",
  },
];
