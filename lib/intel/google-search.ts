import { getGoogleIntelSettings } from "@/lib/settings/google-intel";

export interface GoogleSearchResult {
  title: string;
  url: string;
  snippet: string;
  display_url: string;
}

export interface GoogleSearchResponse {
  mode: "custom_search_api" | "no_key";
  query: string;
  results: GoogleSearchResult[];
  total: number;
  warnings: string[];
}

const GOOGLE_SEARCH_TIMEOUT_MS = 12000;

function decodeEntities(input: string): string {
  return input
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&#x2F;/g, "/")
    .replace(/&#47;/g, "/")
    .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(Number(code)));
}

function stripTags(input: string): string {
  return decodeEntities(input.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim());
}

function normalizeUrl(raw: string): string | null {
  try {
    const decoded = decodeURIComponent(raw);
    const parsed = new URL(decoded);
    if (!["http:", "https:"].includes(parsed.protocol)) return null;
    const host = parsed.hostname.toLowerCase();
    if (host.endsWith("google.com") || host.endsWith("googleusercontent.com")) return null;
    return parsed.toString();
  } catch {
    return null;
  }
}

async function runCustomSearchApi(
  query: string,
  num: number,
  country: string,
  language: string,
  apiKey: string,
  cx: string
): Promise<GoogleSearchResponse> {
  const url = new URL("https://www.googleapis.com/customsearch/v1");
  url.searchParams.set("key", apiKey);
  url.searchParams.set("cx", cx);
  url.searchParams.set("q", query);
  url.searchParams.set("num", String(num));
  url.searchParams.set("gl", country);
  url.searchParams.set("hl", language);
  url.searchParams.set("safe", "active");

  const res = await fetch(url.toString(), {
    signal: AbortSignal.timeout(GOOGLE_SEARCH_TIMEOUT_MS),
  });
  if (!res.ok) {
    throw new Error(`Google Custom Search request failed (${res.status})`);
  }

  const json = (await res.json()) as {
    items?: Array<{ title?: string; link?: string; snippet?: string; displayLink?: string }>;
  };
  const results = (json.items || [])
    .map((item) => ({
      title: item.title?.trim() || "Untitled result",
      url: item.link?.trim() || "",
      snippet: item.snippet?.trim() || "",
      display_url: item.displayLink?.trim() || "",
    }))
    .filter((row) => row.url);

  return {
    mode: "custom_search_api",
    query,
    results,
    total: results.length,
    warnings: [],
  };
}

function parseSerpHtml(html: string): GoogleSearchResult[] {
  const results: GoogleSearchResult[] = [];
  const seen = new Set<string>();
  const linkRegex = /<a href="\/url\?q=([^"&]+)[^"]*"[^>]*>([\s\S]*?)<\/a>/g;

  let match: RegExpExecArray | null = null;
  while ((match = linkRegex.exec(html)) !== null) {
    const rawTarget = match[1];
    const anchorHtml = match[2];
    const normalizedUrl = normalizeUrl(rawTarget);
    if (!normalizedUrl || seen.has(normalizedUrl)) continue;

    const titleMatch = anchorHtml.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i);
    const title = stripTags(titleMatch?.[1] || "");
    if (!title) continue;

    const tail = html.slice(match.index, Math.min(match.index + 1800, html.length));
    const snippetMatch = tail.match(/<div class="(?:VwiC3b|s3v9rd|yXK7lf)[^"]*"[^>]*>([\s\S]*?)<\/div>/i);
    const snippet = stripTags(snippetMatch?.[1] || "");

    seen.add(normalizedUrl);
    results.push({
      title,
      url: normalizedUrl,
      snippet,
      display_url: new URL(normalizedUrl).hostname,
    });

    if (results.length >= 20) break;
  }

  return results;
}

async function runNoKeySearch(
  query: string,
  num: number,
  country: string,
  language: string
): Promise<GoogleSearchResponse> {
  const url = new URL("https://www.google.com/search");
  url.searchParams.set("q", query);
  url.searchParams.set("num", String(num));
  url.searchParams.set("hl", language);
  url.searchParams.set("gl", country);
  url.searchParams.set("pws", "0");
  url.searchParams.set("safe", "active");

  const res = await fetch(url.toString(), {
    headers: {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    },
    signal: AbortSignal.timeout(GOOGLE_SEARCH_TIMEOUT_MS),
  });

  if (!res.ok) {
    throw new Error(`Google SERP request failed (${res.status})`);
  }

  const html = await res.text();
  const parsed = parseSerpHtml(html).slice(0, num);
  const warnings: string[] = [];
  if (parsed.length === 0) {
    warnings.push(
      "No parsable results returned from live SERP. Try a more specific query or configure Custom Search API mode."
    );
  }

  return {
    mode: "no_key",
    query,
    results: parsed,
    total: parsed.length,
    warnings,
  };
}

export async function googleSearch(
  query: string,
  options?: {
    num?: number;
    country?: string;
    language?: string;
  }
): Promise<GoogleSearchResponse> {
  const settings = await getGoogleIntelSettings();
  const num = Math.min(Math.max(options?.num ?? settings.max_results, 1), 20);
  const country = (options?.country || settings.country || "us").toLowerCase();
  const language = (options?.language || settings.language || "en").toLowerCase();

  if (!settings.enabled) {
    return {
      mode: "no_key",
      query,
      results: [],
      total: 0,
      warnings: ["Google intelligence is disabled in settings."],
    };
  }

  if (!settings.allow_live_google_fetch) {
    return {
      mode: settings.mode,
      query,
      results: [],
      total: 0,
      warnings: ["Live Google fetching is disabled by policy."],
    };
  }

  if (
    settings.mode === "custom_search_api" &&
    settings.api_key &&
    settings.cse_cx
  ) {
    try {
      return await runCustomSearchApi(
        query,
        num,
        country,
        language,
        settings.api_key,
        settings.cse_cx
      );
    } catch (err) {
      const fallback = await runNoKeySearch(query, num, country, language);
      fallback.warnings.unshift(
        `Custom Search API mode failed and automatically fell back to no-key mode: ${(err as Error).message}`
      );
      return fallback;
    }
  }

  return runNoKeySearch(query, num, country, language);
}
