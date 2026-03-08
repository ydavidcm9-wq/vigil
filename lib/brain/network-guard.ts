import { isIP } from "node:net";
import { lookup } from "node:dns/promises";

const LOOKUP_TIMEOUT_MS = 3000;

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return true;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a >= 224) return true;
  return false;
}

function isPrivateIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  return (
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80") ||
    normalized.startsWith("::ffff:127.")
  );
}

function isDisallowedHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return (
    host === "localhost" ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".home")
  );
}

function isPrivateIp(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) return isPrivateIPv4(ip);
  if (version === 6) return isPrivateIPv6(ip);
  return true;
}

async function resolveHost(hostname: string): Promise<string[]> {
  const resolver = lookup(hostname, { all: true, verbatim: true }).then((rows) =>
    rows.map((row) => row.address)
  );
  const timeout = new Promise<string[]>((_, reject) => {
    setTimeout(() => reject(new Error("DNS resolution timeout")), LOOKUP_TIMEOUT_MS);
  });
  return Promise.race([resolver, timeout]);
}

export async function assertSafeExternalUrl(rawUrl: string): Promise<URL> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error("Invalid URL");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only http/https URLs are allowed");
  }
  if (parsed.username || parsed.password) {
    throw new Error("Credentials in URL are not allowed");
  }
  if (isDisallowedHost(parsed.hostname)) {
    throw new Error("Disallowed host");
  }

  const hostIpVersion = isIP(parsed.hostname);
  if (hostIpVersion > 0 && isPrivateIp(parsed.hostname)) {
    throw new Error("Private or loopback addresses are not allowed");
  }

  const resolvedIps = await resolveHost(parsed.hostname);
  if (resolvedIps.length === 0) {
    throw new Error("Could not resolve host");
  }

  for (const ip of resolvedIps) {
    if (isPrivateIp(ip)) {
      throw new Error("Target resolves to private or loopback addresses");
    }
  }

  return parsed;
}
