const TRIVY_URL = process.env.TRIVY_URL || "http://localhost:8081";
const TRIVY_TOKEN = process.env.TRIVY_TOKEN || "changeme";

export interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Severity: string;
  Title?: string;
  Description?: string;
  References?: string[];
  CVSS?: Record<string, { V3Score?: number }>;
}

export interface TrivyResult {
  Target: string;
  Class: string;
  Type: string;
  Vulnerabilities?: TrivyVulnerability[];
}

export interface TrivyScanOutput {
  SchemaVersion: number;
  ArtifactName: string;
  ArtifactType: string;
  Results: TrivyResult[];
}

export async function isTrivyAvailable(): Promise<boolean> {
  try {
    const res = await fetch(`${TRIVY_URL}/healthz`, {
      signal: AbortSignal.timeout(5000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

// Trivy server uses gRPC internally - we shell out to trivy CLI client
// which connects to the server. This function builds the command.
export function buildTrivyCommand(
  scanType: "image" | "fs" | "repo",
  target: string
): string[] {
  return [
    "trivy",
    scanType,
    "--server",
    TRIVY_URL,
    "--token",
    TRIVY_TOKEN,
    "--format",
    "json",
    "--severity",
    "CRITICAL,HIGH,MEDIUM,LOW",
    target,
  ];
}

export function mapTrivySeverity(
  severity: string
): "critical" | "high" | "medium" | "low" | "info" {
  switch (severity.toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "info";
  }
}

export function parseTrivyOutput(output: TrivyScanOutput): {
  findings: Array<{
    severity: string;
    title: string;
    description: string;
    cve_id: string;
    cvss_score: number | null;
    package_name: string;
    installed_version: string;
    fixed_version: string | null;
    references: string[];
  }>;
  summary: Record<string, number>;
} {
  const findings: Array<{
    severity: string;
    title: string;
    description: string;
    cve_id: string;
    cvss_score: number | null;
    package_name: string;
    installed_version: string;
    fixed_version: string | null;
    references: string[];
  }> = [];

  const summary: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const result of output.Results || []) {
    for (const vuln of result.Vulnerabilities || []) {
      const severity = mapTrivySeverity(vuln.Severity);
      summary[severity]++;

      let cvssScore: number | null = null;
      if (vuln.CVSS) {
        const scores = Object.values(vuln.CVSS);
        if (scores.length > 0 && scores[0].V3Score) {
          cvssScore = scores[0].V3Score;
        }
      }

      findings.push({
        severity,
        title: vuln.Title || `${vuln.VulnerabilityID} in ${vuln.PkgName}`,
        description: vuln.Description || "",
        cve_id: vuln.VulnerabilityID,
        cvss_score: cvssScore,
        package_name: vuln.PkgName,
        installed_version: vuln.InstalledVersion,
        fixed_version: vuln.FixedVersion || null,
        references: vuln.References || [],
      });
    }
  }

  return { findings, summary };
}
