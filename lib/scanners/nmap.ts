import { bridgeRequest, BridgeResponse } from "./bridge-client";

export interface NmapHost {
  ip: string;
  hostname?: string;
  state: string;
  os?: string;
  ports: NmapPort[];
}

export interface NmapPort {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version?: string;
  scripts?: Record<string, string>;
}

export interface NmapResult {
  hosts: NmapHost[];
  scan_info: {
    type: string;
    num_services: number;
    protocol: string;
  };
  run_stats: {
    hosts_up: number;
    hosts_down: number;
    elapsed: string;
  };
}

export type ScanType = "quick" | "full" | "service" | "vuln" | "os";

export async function nmapScan(
  target: string,
  options: {
    scanType?: ScanType;
    ports?: string;
    scripts?: string[];
    timeout?: number;
  } = {}
): Promise<BridgeResponse<NmapResult>> {
  return bridgeRequest<NmapResult>(
    "/nmap/scan",
    {
      target,
      scanType: options.scanType || "service",
      ports: options.ports,
      scripts: options.scripts,
    },
    options.timeout || 600000
  );
}
