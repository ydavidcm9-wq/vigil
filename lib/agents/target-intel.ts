import crypto from "crypto";
import { promises as dnsPromises } from "dns";
import { XMLParser } from "fast-xml-parser";
import { getCloudDnsSettings } from "@/lib/settings/cloud-dns";

interface TargetSet {
  domains: string[];
  ips: string[];
  urls: string[];
}

interface DnsRecord {
  type: string;
  value: string;
}

interface CloudDnsCheck {
  provider: "cloudflare" | "google";
  ok: boolean;
  answers: DnsRecord[];
  error?: string;
}

interface CloudProviderZoneMatch {
  provider:
    | "cloudflare-account"
    | "gcp-cloud-dns"
    | "aws-route53"
    | "azure-dns";
  ok: boolean;
  matched_domain: string;
  zone_name: string;
  zone_dns_name: string;
  visibility?: string;
  detail?: string;
  error?: string;
}

export interface TargetIntelResult {
  targets: TargetSet;
  dns: Array<{
    domain: string;
    local: DnsRecord[];
    cloud_checks: CloudDnsCheck[];
    provider_zone_matches: CloudProviderZoneMatch[];
  }>;
  provider_account_checks: Array<{
    provider:
      | "cloudflare-account"
      | "gcp-cloud-dns"
      | "aws-route53"
      | "azure-dns";
    ok: boolean;
    detail: string;
  }>;
  generated_at: string;
}

interface CloudflareZone {
  name: string;
  status: string;
  name_servers: string[];
}

interface GcpManagedZone {
  name: string;
  dnsName: string;
  visibility?: string;
}

interface AwsHostedZone {
  id: string;
  name: string;
  privateZone: boolean;
}

interface AzureDnsZone {
  id: string;
  name: string;
  zoneType?: string;
}

function redactIdentifier(value: string): string {
  if (!value) return value;
  if (value.length <= 6) return "[redacted]";
  return `${value.slice(0, 2)}***${value.slice(-2)}`;
}

function unique(items: string[]): string[] {
  return Array.from(new Set(items));
}

function isValidDomain(host: string): boolean {
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(
    host
  );
}

function isValidIpv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    const n = Number(part);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
}

export function extractTargets(input: string): TargetSet {
  const urlMatches = input.match(/https?:\/\/[^\s)]+/gi) || [];
  const domainsFromUrls = urlMatches
    .map((url) => {
      try {
        return new URL(url).hostname;
      } catch {
        return null;
      }
    })
    .filter((v): v is string => Boolean(v));

  const domainMatches = input.match(
    /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi
  ) || [];
  const ipMatches = input.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];

  const domains = unique([...domainsFromUrls, ...domainMatches]).filter(isValidDomain);
  const ips = unique(ipMatches).filter(isValidIpv4);
  const urls = unique(urlMatches);

  return { domains, ips, urls };
}

async function queryDoHCloudflare(domain: string): Promise<CloudDnsCheck> {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
      {
        headers: { accept: "application/dns-json" },
        signal: AbortSignal.timeout(5000),
      }
    );
    if (!res.ok) {
      return { provider: "cloudflare", ok: false, answers: [], error: `HTTP ${res.status}` };
    }
    const data = (await res.json()) as {
      Answer?: Array<{ type?: number; data?: string }>;
    };
    const answers =
      data.Answer?.map((a) => ({
        type: a.type === 1 ? "A" : "OTHER",
        value: String(a.data || ""),
      })).filter((a) => a.value) || [];
    return { provider: "cloudflare", ok: true, answers };
  } catch (err) {
    return {
      provider: "cloudflare",
      ok: false,
      answers: [],
      error: (err as Error).message,
    };
  }
}

async function queryDoHGoogle(domain: string): Promise<CloudDnsCheck> {
  try {
    const res = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`,
      { signal: AbortSignal.timeout(5000) }
    );
    if (!res.ok) {
      return { provider: "google", ok: false, answers: [], error: `HTTP ${res.status}` };
    }
    const data = (await res.json()) as {
      Answer?: Array<{ type?: number; data?: string }>;
    };
    const answers =
      data.Answer?.map((a) => ({
        type: a.type === 1 ? "A" : "OTHER",
        value: String(a.data || ""),
      })).filter((a) => a.value) || [];
    return { provider: "google", ok: true, answers };
  } catch (err) {
    return {
      provider: "google",
      ok: false,
      answers: [],
      error: (err as Error).message,
    };
  }
}

function zoneCandidates(domain: string): string[] {
  const parts = domain.split(".");
  const output: string[] = [];
  for (let i = 0; i < parts.length - 1; i++) {
    const candidate = parts.slice(i).join(".");
    if (isValidDomain(candidate)) output.push(candidate);
  }
  return unique(output);
}

function normalizeDomain(input: string): string {
  return input.replace(/\.$/, "").toLowerCase();
}

function isDomainInAllowlist(domain: string, allowlist: string[]): boolean {
  if (!allowlist.length) return true;
  const normalizedDomain = normalizeDomain(domain);
  return allowlist.some((allow) => {
    const normalizedAllow = normalizeDomain(allow);
    return (
      normalizedDomain === normalizedAllow ||
      normalizedDomain.endsWith(`.${normalizedAllow}`)
    );
  });
}

async function fetchCloudflareZoneMatch(
  domain: string,
  apiToken: string
): Promise<CloudProviderZoneMatch[]> {
  const matches: CloudProviderZoneMatch[] = [];
  for (const candidate of zoneCandidates(domain).slice(0, 4)) {
    try {
      const res = await fetch(
        `https://api.cloudflare.com/client/v4/zones?name=${encodeURIComponent(candidate)}&status=active&page=1&per_page=3`,
        {
          headers: {
            Authorization: `Bearer ${apiToken}`,
            "Content-Type": "application/json",
          },
          signal: AbortSignal.timeout(5000),
        }
      );

      if (!res.ok) {
        matches.push({
          provider: "cloudflare-account",
          ok: false,
          matched_domain: candidate,
          zone_name: candidate,
          zone_dns_name: candidate,
          error: `HTTP ${res.status}`,
        });
        continue;
      }

      const body = (await res.json()) as {
        success?: boolean;
        result?: Array<{
          name?: string;
          status?: string;
          name_servers?: string[];
        }>;
      };

      const zones: CloudflareZone[] =
        body.result?.map((zone) => ({
          name: String(zone.name || candidate),
          status: String(zone.status || "unknown"),
          name_servers: Array.isArray(zone.name_servers)
            ? zone.name_servers.map(String)
            : [],
        })) || [];

      if (zones.length === 0) continue;

      for (const zone of zones) {
        matches.push({
          provider: "cloudflare-account",
          ok: true,
          matched_domain: domain,
          zone_name: zone.name,
          zone_dns_name: zone.name,
          detail: `status=${zone.status}; ns=${zone.name_servers.join(",") || "none"}`,
        });
      }
      return matches;
    } catch (err) {
      matches.push({
        provider: "cloudflare-account",
        ok: false,
        matched_domain: candidate,
        zone_name: candidate,
        zone_dns_name: candidate,
        error: (err as Error).message,
      });
    }
  }
  return matches;
}

function base64url(input: Buffer | string): string {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function fetchGoogleAccessToken(serviceAccountJson: string): Promise<string> {
  const svc = JSON.parse(serviceAccountJson) as {
    client_email?: string;
    private_key?: string;
    token_uri?: string;
  };

  if (!svc.client_email || !svc.private_key) {
    throw new Error("GCP service account is missing client_email/private_key.");
  }

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: svc.client_email,
    scope: "https://www.googleapis.com/auth/ndev.clouddns.readonly",
    aud: svc.token_uri || "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };

  const unsigned = `${base64url(JSON.stringify(header))}.${base64url(
    JSON.stringify(payload)
  )}`;
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(unsigned);
  signer.end();
  const signature = signer.sign(svc.private_key);
  const assertion = `${unsigned}.${base64url(signature)}`;

  const res = await fetch(svc.token_uri || "https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion,
    }),
    signal: AbortSignal.timeout(7000),
  });

  if (!res.ok) {
    throw new Error(`Token endpoint HTTP ${res.status}`);
  }
  const json = (await res.json()) as { access_token?: string };
  if (!json.access_token) throw new Error("No access_token returned by GCP.");
  return json.access_token;
}

async function fetchGoogleZoneMatch(
  domain: string,
  serviceAccountJson: string,
  projectIdOverride?: string
): Promise<CloudProviderZoneMatch[]> {
  const serviceAccount = JSON.parse(serviceAccountJson) as { project_id?: string };
  const projectId = projectIdOverride || serviceAccount.project_id;
  if (!projectId) {
    return [
      {
        provider: "gcp-cloud-dns",
        ok: false,
        matched_domain: domain,
        zone_name: domain,
        zone_dns_name: domain,
        error: "GCP project_id missing.",
      },
    ];
  }

  try {
    const accessToken = await fetchGoogleAccessToken(serviceAccountJson);
    const res = await fetch(
      `https://dns.googleapis.com/dns/v1/projects/${encodeURIComponent(projectId)}/managedZones`,
      {
        headers: { Authorization: `Bearer ${accessToken}` },
        signal: AbortSignal.timeout(7000),
      }
    );
    if (!res.ok) {
      return [
        {
          provider: "gcp-cloud-dns",
          ok: false,
          matched_domain: domain,
          zone_name: domain,
          zone_dns_name: domain,
          error: `HTTP ${res.status}`,
        },
      ];
    }

    const body = (await res.json()) as { managedZones?: unknown[] };
    const zones: GcpManagedZone[] = Array.isArray(body.managedZones)
      ? body.managedZones.map((zone) => {
          const record = zone as Record<string, unknown>;
          return {
            name: String(record.name || ""),
            dnsName: String(record.dnsName || ""),
            visibility: String(record.visibility || ""),
          };
        })
      : [];

    const matches: CloudProviderZoneMatch[] = [];
    for (const zone of zones) {
      const zoneDns = zone.dnsName.replace(/\.$/, "").toLowerCase();
      if (!zoneDns) continue;
      if (domain.toLowerCase() === zoneDns || domain.toLowerCase().endsWith(`.${zoneDns}`)) {
        matches.push({
          provider: "gcp-cloud-dns",
          ok: true,
          matched_domain: domain,
          zone_name: zone.name,
          zone_dns_name: zone.dnsName,
          visibility: zone.visibility || undefined,
        });
      }
    }

    return matches;
  } catch (err) {
    return [
      {
        provider: "gcp-cloud-dns",
        ok: false,
        matched_domain: domain,
        zone_name: domain,
        zone_dns_name: domain,
        error: (err as Error).message,
      },
    ];
  }
}

function sha256Hex(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function hmac(key: Buffer | string, value: string): Buffer {
  return crypto.createHmac("sha256", key).update(value).digest();
}

function awsDateStamps(date: Date): { amzDate: string; dateStamp: string } {
  const iso = date.toISOString().replace(/[:-]|\.\d{3}/g, "");
  return {
    amzDate: iso,
    dateStamp: iso.slice(0, 8),
  };
}

async function listAwsHostedZones(
  accessKeyId: string,
  secretAccessKey: string,
  sessionToken?: string
): Promise<AwsHostedZone[]> {
  const host = "route53.amazonaws.com";
  const region = "us-east-1";
  const service = "route53";
  const method = "GET";
  const canonicalUri = "/2013-04-01/hostedzone";
  const canonicalQuery = "";
  const payloadHash = sha256Hex("");
  const now = new Date();
  const { amzDate, dateStamp } = awsDateStamps(now);

  const headers: Record<string, string> = {
    host,
    "x-amz-date": amzDate,
  };
  if (sessionToken) headers["x-amz-security-token"] = sessionToken;

  const signedHeaderKeys = Object.keys(headers).sort();
  const canonicalHeaders = signedHeaderKeys
    .map((key) => `${key}:${headers[key].trim()}\n`)
    .join("");
  const signedHeaders = signedHeaderKeys.join(";");

  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join("\n");

  const kDate = hmac(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  const kSigning = hmac(kService, "aws4_request");
  const signature = crypto
    .createHmac("sha256", kSigning)
    .update(stringToSign)
    .digest("hex");

  const authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const response = await fetch(`https://${host}${canonicalUri}`, {
    method,
    headers: {
      "x-amz-date": amzDate,
      ...(sessionToken ? { "x-amz-security-token": sessionToken } : {}),
      Authorization: authorization,
    },
    signal: AbortSignal.timeout(7000),
  });

  if (!response.ok) {
    throw new Error(`AWS Route53 HTTP ${response.status}`);
  }
  const xml = await response.text();
  const parser = new XMLParser({ ignoreAttributes: false });
  const parsed = parser.parse(xml) as {
    ListHostedZonesResponse?: {
      HostedZones?: { HostedZone?: Array<Record<string, unknown>> | Record<string, unknown> };
    };
  };
  const hosted = parsed.ListHostedZonesResponse?.HostedZones?.HostedZone;
  const zones = Array.isArray(hosted) ? hosted : hosted ? [hosted] : [];
  return zones.map((zone) => ({
    id: String(zone.Id || ""),
    name: String(zone.Name || ""),
    privateZone: String((zone.Config as Record<string, unknown>)?.PrivateZone || "")
      .toLowerCase()
      .includes("true"),
  }));
}

async function fetchAwsZoneMatch(
  domain: string,
  accessKeyId: string,
  secretAccessKey: string,
  sessionToken?: string
): Promise<CloudProviderZoneMatch[]> {
  try {
    const zones = await listAwsHostedZones(accessKeyId, secretAccessKey, sessionToken);
    const matches: CloudProviderZoneMatch[] = [];
    for (const zone of zones) {
      const zoneDns = normalizeDomain(zone.name);
      if (
        normalizeDomain(domain) === zoneDns ||
        normalizeDomain(domain).endsWith(`.${zoneDns}`)
      ) {
        matches.push({
          provider: "aws-route53",
          ok: true,
          matched_domain: domain,
          zone_name: zone.id || zone.name,
          zone_dns_name: zone.name,
          visibility: zone.privateZone ? "private" : "public",
        });
      }
    }
    return matches;
  } catch (err) {
    return [
      {
        provider: "aws-route53",
        ok: false,
        matched_domain: domain,
        zone_name: domain,
        zone_dns_name: domain,
        error: (err as Error).message,
      },
    ];
  }
}

async function fetchAzureAccessToken(
  tenantId: string,
  clientId: string,
  clientSecret: string
): Promise<string> {
  const tokenUrl = `https://login.microsoftonline.com/${encodeURIComponent(
    tenantId
  )}/oauth2/v2.0/token`;
  const res = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: clientId,
      client_secret: clientSecret,
      scope: "https://management.azure.com/.default",
    }),
    signal: AbortSignal.timeout(7000),
  });
  if (!res.ok) throw new Error(`Azure token HTTP ${res.status}`);
  const body = (await res.json()) as { access_token?: string };
  if (!body.access_token) throw new Error("Azure access_token missing.");
  return body.access_token;
}

async function fetchAzureDnsZones(
  subscriptionId: string,
  accessToken: string
): Promise<AzureDnsZone[]> {
  const url = `https://management.azure.com/subscriptions/${encodeURIComponent(
    subscriptionId
  )}/providers/Microsoft.Network/dnszones?api-version=2018-05-01`;

  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(9000),
  });
  if (!res.ok) throw new Error(`Azure DNS HTTP ${res.status}`);
  const body = (await res.json()) as { value?: Array<Record<string, unknown>> };
  return (body.value || []).map((zone) => ({
    id: String(zone.id || ""),
    name: String(zone.name || ""),
    zoneType: String(
      ((zone.properties as Record<string, unknown> | undefined)?.zoneType as
        | string
        | undefined) || ""
    ),
  }));
}

async function fetchAzureZoneMatch(
  domain: string,
  tenantId: string,
  clientId: string,
  clientSecret: string,
  subscriptionId: string
): Promise<CloudProviderZoneMatch[]> {
  try {
    const token = await fetchAzureAccessToken(tenantId, clientId, clientSecret);
    const zones = await fetchAzureDnsZones(subscriptionId, token);
    const matches: CloudProviderZoneMatch[] = [];
    for (const zone of zones) {
      const zoneDns = normalizeDomain(zone.name);
      if (
        normalizeDomain(domain) === zoneDns ||
        normalizeDomain(domain).endsWith(`.${zoneDns}`)
      ) {
        matches.push({
          provider: "azure-dns",
          ok: true,
          matched_domain: domain,
          zone_name: zone.id || zone.name,
          zone_dns_name: zone.name,
          visibility: zone.zoneType || undefined,
        });
      }
    }
    return matches;
  } catch (err) {
    return [
      {
        provider: "azure-dns",
        ok: false,
        matched_domain: domain,
        zone_name: domain,
        zone_dns_name: domain,
        error: (err as Error).message,
      },
    ];
  }
}

async function resolveLocalDns(domain: string): Promise<DnsRecord[]> {
  const resolver = new dnsPromises.Resolver();
  resolver.setServers(["1.1.1.1", "8.8.8.8"]);

  const output: DnsRecord[] = [];

  try {
    const addrs = await resolver.resolve4(domain, { ttl: true });
    for (const addr of addrs) {
      output.push({ type: "A", value: `${addr.address} (ttl:${addr.ttl})` });
    }
  } catch {
    // ignored
  }

  try {
    const ns = await resolver.resolveNs(domain);
    for (const item of ns) output.push({ type: "NS", value: item });
  } catch {
    // ignored
  }

  return output;
}

export async function gatherTargetIntel(input: string): Promise<TargetIntelResult> {
  const targets = extractTargets(input);
  const domains = targets.domains.slice(0, 5);
  const cloudDnsSettings = await getCloudDnsSettings();

  const providerChecks: TargetIntelResult["provider_account_checks"] = [];
  if (cloudDnsSettings.cloudflare.enabled) {
    providerChecks.push({
      provider: "cloudflare-account",
      ok: Boolean(cloudDnsSettings.cloudflare.api_token),
      detail: cloudDnsSettings.cloudflare.api_token
        ? "Cloudflare connector enabled."
        : "Cloudflare enabled but token missing.",
    });
  }
  if (cloudDnsSettings.gcp.enabled) {
    providerChecks.push({
      provider: "gcp-cloud-dns",
      ok: Boolean(cloudDnsSettings.gcp.service_account_json),
      detail: cloudDnsSettings.gcp.service_account_json
        ? `GCP connector enabled for project ${cloudDnsSettings.gcp.project_id || "service-account-default"}.`
        : "GCP enabled but service account JSON missing.",
    });
  }
  if (cloudDnsSettings.aws.enabled) {
    providerChecks.push({
      provider: "aws-route53",
      ok: Boolean(
        cloudDnsSettings.aws.access_key_id && cloudDnsSettings.aws.secret_access_key
      ),
      detail:
        cloudDnsSettings.aws.access_key_id && cloudDnsSettings.aws.secret_access_key
          ? `AWS Route53 connector enabled (${cloudDnsSettings.aws.region || "us-east-1"}).`
          : "AWS enabled but credentials missing.",
    });
  }
  if (cloudDnsSettings.azure.enabled) {
    providerChecks.push({
      provider: "azure-dns",
      ok: Boolean(
        cloudDnsSettings.azure.tenant_id &&
          cloudDnsSettings.azure.client_id &&
          cloudDnsSettings.azure.client_secret &&
          cloudDnsSettings.azure.subscription_id
      ),
      detail:
        cloudDnsSettings.azure.tenant_id &&
        cloudDnsSettings.azure.client_id &&
        cloudDnsSettings.azure.client_secret &&
        cloudDnsSettings.azure.subscription_id
          ? "Azure DNS connector enabled."
          : "Azure enabled but tenant/client/subscription credentials missing.",
    });
  }

  const dns = [];
  for (const domain of domains) {
    const providerZoneMatches: CloudProviderZoneMatch[] = [];
    const cfAllowed =
      cloudDnsSettings.cloudflare.enabled &&
      isDomainInAllowlist(domain, cloudDnsSettings.cloudflare.zone_allowlist) &&
      Boolean(cloudDnsSettings.cloudflare.api_token);

    if (cfAllowed) {
      providerZoneMatches.push(
        ...(await fetchCloudflareZoneMatch(
          domain,
          cloudDnsSettings.cloudflare.api_token as string
        ))
      );
    }

    const gcpAllowed =
      cloudDnsSettings.gcp.enabled &&
      isDomainInAllowlist(domain, cloudDnsSettings.gcp.zone_allowlist) &&
      Boolean(cloudDnsSettings.gcp.service_account_json);

    if (gcpAllowed) {
      providerZoneMatches.push(
        ...(await fetchGoogleZoneMatch(
          domain,
          cloudDnsSettings.gcp.service_account_json as string,
          cloudDnsSettings.gcp.project_id
        ))
      );
    }

    const awsAllowed =
      cloudDnsSettings.aws.enabled &&
      isDomainInAllowlist(domain, cloudDnsSettings.aws.zone_allowlist) &&
      Boolean(
        cloudDnsSettings.aws.access_key_id && cloudDnsSettings.aws.secret_access_key
      );

    if (awsAllowed) {
      providerZoneMatches.push(
        ...(await fetchAwsZoneMatch(
          domain,
          cloudDnsSettings.aws.access_key_id as string,
          cloudDnsSettings.aws.secret_access_key as string,
          cloudDnsSettings.aws.session_token
        ))
      );
    }

    const azureAllowed =
      cloudDnsSettings.azure.enabled &&
      isDomainInAllowlist(domain, cloudDnsSettings.azure.zone_allowlist) &&
      Boolean(
        cloudDnsSettings.azure.tenant_id &&
          cloudDnsSettings.azure.client_id &&
          cloudDnsSettings.azure.client_secret &&
          cloudDnsSettings.azure.subscription_id
      );

    if (azureAllowed) {
      providerZoneMatches.push(
        ...(await fetchAzureZoneMatch(
          domain,
          cloudDnsSettings.azure.tenant_id as string,
          cloudDnsSettings.azure.client_id as string,
          cloudDnsSettings.azure.client_secret as string,
          cloudDnsSettings.azure.subscription_id as string
        ))
      );
    }

    const [local, cf, google] = await Promise.all([
      resolveLocalDns(domain),
      queryDoHCloudflare(domain),
      queryDoHGoogle(domain),
    ]);

    const normalizedZoneMatches = cloudDnsSettings.safety.redact_provider_identifiers
      ? providerZoneMatches.map((match) => ({
          ...match,
          zone_name: redactIdentifier(match.zone_name),
          zone_dns_name: redactIdentifier(match.zone_dns_name),
        }))
      : providerZoneMatches;
    dns.push({
      domain,
      local,
      cloud_checks: [cf, google],
      provider_zone_matches: normalizedZoneMatches,
    });
  }

  return {
    targets,
    dns,
    provider_account_checks: providerChecks,
    generated_at: new Date().toISOString(),
  };
}
