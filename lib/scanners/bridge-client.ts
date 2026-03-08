const BRIDGE_URL = process.env.BRIDGE_URL || "http://localhost:9877";
const DEFAULT_TIMEOUT = 300000; // 5 minutes
const BRIDGE_SHARED_TOKEN = process.env.BRIDGE_SHARED_TOKEN?.trim() || "";

export interface BridgeResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  duration_ms?: number;
}

function buildHeaders(hasBody: boolean): HeadersInit | undefined {
  const headers: Record<string, string> = {};
  if (hasBody) {
    headers["Content-Type"] = "application/json";
  }
  if (BRIDGE_SHARED_TOKEN) {
    headers.Authorization = `Bearer ${BRIDGE_SHARED_TOKEN}`;
  }
  return Object.keys(headers).length > 0 ? headers : undefined;
}

export async function bridgeRequest<T = unknown>(
  endpoint: string,
  body?: Record<string, unknown>,
  timeoutMs = DEFAULT_TIMEOUT
): Promise<BridgeResponse<T>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`${BRIDGE_URL}${endpoint}`, {
      method: body ? "POST" : "GET",
      headers: buildHeaders(Boolean(body)),
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    const json = await res.json();
    if (!res.ok) {
      return { success: false, error: json.error || `HTTP ${res.status}` };
    }
    // Bridge returns { success, result } — normalize to { success, data }
    if (json.result && !json.data) {
      json.data = json.result;
    }
    return json as BridgeResponse<T>;
  } catch (err) {
    if ((err as Error).name === "AbortError") {
      return { success: false, error: "Scan timed out" };
    }
    return {
      success: false,
      error: `Bridge connection failed: ${(err as Error).message}`,
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function isBridgeHealthy(): Promise<boolean> {
  try {
    const res = await fetch(`${BRIDGE_URL}/health`, {
      headers: buildHeaders(false),
      signal: AbortSignal.timeout(5000),
    });
    return res.ok;
  } catch {
    return false;
  }
}
