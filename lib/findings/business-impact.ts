export interface FindingForImpact {
  id: string;
  severity: string;
  category?: string | null;
  title?: string | null;
  description?: string | null;
  target?: string | null;
  scanner?: string | null;
  status?: string | null;
}

export interface BusinessImpact {
  score: number;
  priority: "p0" | "p1" | "p2" | "p3";
  estimated_impact: "revenue_trust" | "customer_trust" | "operational";
  journeys: string[];
  rationale: string[];
}

const SEVERITY_BASE: Record<string, number> = {
  critical: 88,
  high: 72,
  medium: 52,
  low: 30,
  info: 10,
};

const CATEGORY_WEIGHT: Record<string, number> = {
  auth: 10,
  sqli: 12,
  xss: 8,
  csrf: 7,
  ssrf: 10,
  idor: 11,
  injection: 11,
  open_port: 3,
  web_misconfig: 6,
  directory: 2,
  vulnerability: 8,
};

const SCANNER_WEIGHT: Record<string, number> = {
  sqlmap: 10,
  zap: 7,
  nuclei: 7,
  nmap: 2,
  trivy: 5,
  osint: 3,
};

function clampScore(value: number): number {
  if (value < 0) return 0;
  if (value > 100) return 100;
  return Math.round(value);
}

function normalize(input: string | null | undefined): string {
  return (input || "").toLowerCase();
}

function inferJourneys(finding: FindingForImpact): string[] {
  const text = `${normalize(finding.title)} ${normalize(finding.description)} ${normalize(
    finding.category
  )} ${normalize(finding.target)}`;
  const journeys = new Set<string>();

  if (/login|auth|session|mfa|password|oauth|token/.test(text)) journeys.add("authentication");
  if (/signup|register|onboarding|trial/.test(text)) journeys.add("signup");
  if (/checkout|payment|billing|invoice|subscription|stripe/.test(text)) journeys.add("billing");
  if (/api|graphql|rest|endpoint|idor/.test(text)) journeys.add("api");
  if (/pii|privacy|data|export|leak|breach/.test(text)) journeys.add("data");
  if (/admin|dashboard|backoffice/.test(text)) journeys.add("admin");

  if (journeys.size === 0) journeys.add("platform");
  return Array.from(journeys);
}

function inferEstimatedImpact(journeys: string[]): BusinessImpact["estimated_impact"] {
  if (journeys.includes("billing") || journeys.includes("signup")) return "revenue_trust";
  if (journeys.includes("authentication") || journeys.includes("data")) return "customer_trust";
  return "operational";
}

function inferPriority(score: number): BusinessImpact["priority"] {
  if (score >= 90) return "p0";
  if (score >= 75) return "p1";
  if (score >= 55) return "p2";
  return "p3";
}

export function scoreBusinessImpact(finding: FindingForImpact): BusinessImpact {
  const severity = normalize(finding.severity);
  const category = normalize(finding.category);
  const scanner = normalize(finding.scanner);
  const status = normalize(finding.status);

  let score = SEVERITY_BASE[severity] ?? 20;
  score += CATEGORY_WEIGHT[category] ?? 0;
  score += SCANNER_WEIGHT[scanner] ?? 0;

  const journeys = inferJourneys(finding);
  if (journeys.includes("billing")) score += 8;
  if (journeys.includes("signup")) score += 6;
  if (journeys.includes("authentication")) score += 6;
  if (journeys.includes("data")) score += 6;
  if (journeys.includes("admin")) score += 5;

  if (status === "confirmed") score += 4;
  if (status === "ticket_created") score += 2;
  if (status === "accepted_risk" || status === "remediated" || status === "false_positive") {
    score -= 15;
  }

  const finalScore = clampScore(score);
  const rationale: string[] = [
    `Base severity weight: ${SEVERITY_BASE[severity] ?? 20}`,
    `Category/scanner adjustment: ${(CATEGORY_WEIGHT[category] ?? 0) + (SCANNER_WEIGHT[scanner] ?? 0)}`,
    `Business journey exposure: ${journeys.join(", ")}`,
  ];

  return {
    score: finalScore,
    priority: inferPriority(finalScore),
    estimated_impact: inferEstimatedImpact(journeys),
    journeys,
    rationale,
  };
}
