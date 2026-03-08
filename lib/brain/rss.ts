import { XMLParser } from "fast-xml-parser";

export interface ParsedFeedItem {
  guid: string;
  url: string | null;
  title: string;
  summary: string;
  content: string;
  source: string | null;
  published_at: string | null;
  importance_score: number;
  tags: string[];
}

interface ParsedFeed {
  title: string;
  items: ParsedFeedItem[];
}

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  parseTagValue: true,
  trimValues: true,
});

const RSS_TIMEOUT_MS = 15000;
const MAX_XML_SIZE = 2_000_000;
const MAX_ITEMS = 30;

function toArray<T>(value: T | T[] | null | undefined): T[] {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function asText(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value.trim();
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    if (typeof obj["#text"] === "string") return obj["#text"].trim();
    if (typeof obj["@_href"] === "string") return obj["@_href"].trim();
    if (typeof obj["href"] === "string") return obj["href"].trim();
  }
  return "";
}

function normalizeDate(value: unknown): string | null {
  const raw = asText(value);
  if (!raw) return null;
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

function scoreImportance(title: string, body: string): number {
  const text = `${title} ${body}`.toLowerCase();
  let score = 20;

  const critical = ["zero day", "0day", "rce", "actively exploited", "critical vulnerability", "breach", "data leak", "cve-"];
  const high = ["privilege escalation", "authentication bypass", "ssrf", "supply chain", "ransomware", "patch now"];
  const medium = ["xss", "csrf", "sql injection", "misconfiguration", "phishing", "botnet"];

  for (const token of critical) {
    if (text.includes(token)) score += 22;
  }
  for (const token of high) {
    if (text.includes(token)) score += 12;
  }
  for (const token of medium) {
    if (text.includes(token)) score += 5;
  }

  return Math.max(0, Math.min(100, score));
}

function inferTags(title: string, summary: string): string[] {
  const text = `${title} ${summary}`.toLowerCase();
  const tags: string[] = [];

  const map: Array<[string, string[]]> = [
    ["vulnerability", ["cve-", "vulnerability", "exploit", "rce"]],
    ["cloud", ["aws", "azure", "gcp", "kubernetes", "container"]],
    ["identity", ["oauth", "sso", "credential", "mfa", "auth"]],
    ["malware", ["ransomware", "trojan", "malware", "botnet"]],
    ["compliance", ["nist", "soc2", "iso 27001", "compliance", "audit"]],
    ["supply-chain", ["dependency", "sbom", "package", "ci/cd", "pipeline"]],
    ["ai-security", ["llm", "ai model", "prompt injection", "genai", "agent"]],
  ];

  for (const [tag, tokens] of map) {
    if (tokens.some((token) => text.includes(token))) {
      tags.push(tag);
    }
  }

  if (tags.length === 0) tags.push("general");
  return tags.slice(0, 6);
}

async function fetchXml(url: string): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), RSS_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "VigilRSS/1.0",
        Accept: "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.5",
      },
    });

    if (!res.ok) {
      throw new Error(`Feed request failed (${res.status})`);
    }

    const xml = await res.text();
    if (!xml || xml.length > MAX_XML_SIZE) {
      throw new Error("Feed payload is empty or too large");
    }
    return xml;
  } catch (err) {
    if ((err as Error).name === "AbortError") {
      throw new Error("Feed request timed out");
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

function normalizeRssItems(root: Record<string, unknown>): ParsedFeedItem[] {
  const channel = root.rss && typeof root.rss === "object" ? (root.rss as Record<string, unknown>).channel : null;
  const normalizedChannel = Array.isArray(channel) ? channel[0] : channel;
  if (!normalizedChannel || typeof normalizedChannel !== "object") return [];

  const items = toArray((normalizedChannel as Record<string, unknown>).item);
  return items.map((entry) => {
    const row = entry as Record<string, unknown>;
    const title = asText(row.title) || "Untitled";
    const link = asText(row.link) || null;
    const guid = asText(row.guid) || link || title;
    const summary = asText(row.description) || asText(row["content:encoded"]);
    const content = asText(row["content:encoded"]) || summary;
    const source = asText(row["dc:creator"]) || asText(row.author) || null;
    const published_at = normalizeDate(row.pubDate) || normalizeDate(row["dc:date"]);
    const importance = scoreImportance(title, summary || content);

    return {
      guid,
      url: link,
      title,
      summary: summary || content,
      content: content || summary,
      source,
      published_at,
      importance_score: importance,
      tags: inferTags(title, summary || content),
    };
  });
}

function normalizeAtomItems(root: Record<string, unknown>): ParsedFeedItem[] {
  const feed = root.feed;
  if (!feed || typeof feed !== "object") return [];

  const entries = toArray((feed as Record<string, unknown>).entry);
  return entries.map((entry) => {
    const row = entry as Record<string, unknown>;
    const title = asText(row.title) || "Untitled";

    const links = toArray(row.link as unknown);
    const primaryLink = links.find((linkObj) => {
      if (typeof linkObj !== "object" || !linkObj) return false;
      const rel = asText((linkObj as Record<string, unknown>)["@_rel"]);
      return !rel || rel === "alternate";
    }) as Record<string, unknown> | undefined;

    const link = asText(primaryLink?.["@_href"] ?? row.link) || null;
    const guid = asText(row.id) || link || title;
    const summary = asText(row.summary) || asText(row.content);
    const content = asText(row.content) || summary;

    let source: string | null = null;
    if (row.author && typeof row.author === "object") {
      const authorObj = row.author as Record<string, unknown>;
      source = asText(authorObj.name) || asText(authorObj.email) || null;
    }

    const published_at = normalizeDate(row.published) || normalizeDate(row.updated);
    const importance = scoreImportance(title, summary || content);

    return {
      guid,
      url: link,
      title,
      summary: summary || content,
      content: content || summary,
      source,
      published_at,
      importance_score: importance,
      tags: inferTags(title, summary || content),
    };
  });
}

export async function fetchAndParseFeed(url: string): Promise<ParsedFeed> {
  const xml = await fetchXml(url);
  const parsed = parser.parse(xml);
  if (!parsed || typeof parsed !== "object") {
    throw new Error("Could not parse feed XML");
  }

  const root = parsed as Record<string, unknown>;
  const rssItems = normalizeRssItems(root);
  const atomItems = normalizeAtomItems(root);
  const items = (rssItems.length > 0 ? rssItems : atomItems)
    .filter((item) => item.guid && item.title)
    .slice(0, MAX_ITEMS);

  if (items.length === 0) {
    throw new Error("Feed has no parseable items");
  }

  const rssRoot = root.rss && typeof root.rss === "object" ? (root.rss as Record<string, unknown>) : null;
  const channelRaw = rssRoot?.channel;
  const channelObj = Array.isArray(channelRaw) ? channelRaw[0] : channelRaw;
  const rssTitle =
    channelObj && typeof channelObj === "object"
      ? asText((channelObj as Record<string, unknown>).title)
      : "";
  const atomTitle = asText((root.feed as Record<string, unknown> | undefined)?.title);
  const title = rssTitle || atomTitle || "Security Feed";

  return { title, items };
}
