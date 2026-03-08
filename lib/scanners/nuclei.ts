import { bridgeRequest, BridgeResponse } from "./bridge-client";

export interface NucleiFinding {
  template_id: string;
  template_name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  type: string;
  host: string;
  matched_at: string;
  description?: string;
  tags?: string[];
  cve_id?: string;
  cvss_score?: number;
  reference?: string[];
  curl_command?: string;
  matcher_name?: string;
  extracted_results?: string[];
}

export interface NucleiResult {
  findings: NucleiFinding[];
  stats: {
    templates_loaded: number;
    hosts_scanned: number;
    findings_count: number;
  };
}

export async function nucleiScan(
  target: string,
  options: {
    templates?: string[];
    severity?: string[];
    tags?: string[];
    timeout?: number;
  } = {}
): Promise<BridgeResponse<NucleiResult>> {
  return bridgeRequest<NucleiResult>(
    "/nuclei/scan",
    {
      target,
      templates: options.templates,
      severity: options.severity || ["critical", "high", "medium"],
      tags: options.tags,
    },
    options.timeout || 600000
  );
}
