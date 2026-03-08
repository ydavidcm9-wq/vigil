import { bridgeRequest, BridgeResponse } from "./bridge-client";

export interface ShannonConfig {
  targetUrl: string;
  repoPath?: string;
  authentication?: {
    loginUrl: string;
    username: string;
    password: string;
    totpSecret?: string;
  };
  maxConcurrentPipelines?: number;
  focusPaths?: string[];
  avoidPaths?: string[];
}

export interface ShannonProgress {
  phase: "pre-recon" | "recon" | "vuln-analysis" | "exploitation" | "reporting";
  agents_active: number;
  agents_completed: number;
  agents_total: number;
  findings_so_far: number;
  elapsed_seconds: number;
  status: "running" | "completed" | "failed";
}

export interface ShannonReport {
  title: string;
  executive_summary: string;
  findings: Array<{
    title: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    category: string;
    description: string;
    poc: string;
    remediation: string;
    url: string;
  }>;
  scan_metadata: {
    target: string;
    duration_seconds: number;
    agents_used: string[];
    total_requests: number;
  };
}

export async function startPentest(
  config: ShannonConfig
): Promise<BridgeResponse<{ sessionId: string }>> {
  return bridgeRequest<{ sessionId: string }>(
    "/shannon/start",
    {
      target_url: config.targetUrl,
      repo_path: config.repoPath,
      authentication: config.authentication,
      max_concurrent: config.maxConcurrentPipelines || 2,
      focus_paths: config.focusPaths,
      avoid_paths: config.avoidPaths,
    },
    10000 // Just starts the process, doesn't wait for completion
  );
}

export async function getPentestProgress(
  sessionId: string
): Promise<BridgeResponse<ShannonProgress>> {
  return bridgeRequest<ShannonProgress>(`/shannon/progress/${sessionId}`);
}

export async function getPentestReport(
  sessionId: string
): Promise<BridgeResponse<ShannonReport>> {
  return bridgeRequest<ShannonReport>(`/shannon/report/${sessionId}`);
}

export async function cancelPentest(
  sessionId: string
): Promise<BridgeResponse<void>> {
  return bridgeRequest<void>(`/shannon/cancel/${sessionId}`, {});
}
