const ZAP_URL = process.env.ZAP_URL || "http://localhost:8080";
const ZAP_API_KEY = process.env.ZAP_API_KEY || "changeme";

async function zapApi<T = unknown>(
  path: string,
  params: Record<string, string> = {}
): Promise<T> {
  const url = new URL(`${ZAP_URL}/JSON/${path}`);
  url.searchParams.set("apikey", ZAP_API_KEY);
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v);
  }
  const res = await fetch(url.toString(), {
    signal: AbortSignal.timeout(30000),
  });
  if (!res.ok) throw new Error(`ZAP API error: ${res.status}`);
  return res.json() as T;
}

export interface ZapAlert {
  pluginId: string;
  alert: string;
  name: string;
  risk: string;
  confidence: string;
  url: string;
  param?: string;
  attack?: string;
  evidence?: string;
  description: string;
  solution: string;
  reference: string;
  cweid: string;
  wascid: string;
}

export async function startSpider(targetUrl: string): Promise<string> {
  const result = await zapApi<{ scan: string }>("spider/action/scan", {
    url: targetUrl,
  });
  return result.scan;
}

export async function getSpiderStatus(scanId: string): Promise<number> {
  const result = await zapApi<{ status: string }>("spider/view/status", {
    scanId,
  });
  return parseInt(result.status);
}

export async function startActiveScan(targetUrl: string): Promise<string> {
  const result = await zapApi<{ scan: string }>("ascan/action/scan", {
    url: targetUrl,
  });
  return result.scan;
}

export async function getActiveScanStatus(scanId: string): Promise<number> {
  const result = await zapApi<{ status: string }>("ascan/view/status", {
    scanId,
  });
  return parseInt(result.status);
}

export async function getAlerts(
  targetUrl?: string
): Promise<ZapAlert[]> {
  const params: Record<string, string> = {};
  if (targetUrl) params.baseurl = targetUrl;
  const result = await zapApi<{ alerts: ZapAlert[] }>(
    "core/view/alerts",
    params
  );
  return result.alerts;
}

export async function getAlertsSummary(): Promise<
  Record<string, number>
> {
  const result = await zapApi<{
    alertsSummary: Record<string, number>;
  }>("alert/view/alertsSummary");
  return result.alertsSummary;
}

export async function getVersion(): Promise<string> {
  const result = await zapApi<{ version: string }>("core/view/version");
  return result.version;
}

export async function isZapAvailable(): Promise<boolean> {
  try {
    await getVersion();
    return true;
  } catch {
    return false;
  }
}

export function mapZapRiskToSeverity(
  risk: string
): "critical" | "high" | "medium" | "low" | "info" {
  switch (risk.toLowerCase()) {
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    case "informational":
      return "info";
    default:
      return "info";
  }
}
