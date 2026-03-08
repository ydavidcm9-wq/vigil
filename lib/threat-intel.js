// Vigil — Threat intelligence feed aggregation
const https = require('https');
const http = require('http');
const neuralCache = require('./neural-cache');

const CACHE_TTL = 15 * 60 * 1000; // 15 minutes
const FETCH_TIMEOUT = 10000;

// Security RSS/Atom feeds
const RSS_FEEDS = [
  {
    name: 'NIST NVD',
    url: 'https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml',
    category: 'vulnerabilities'
  },
  {
    name: 'US-CERT Alerts',
    url: 'https://www.cisa.gov/uscert/ncas/alerts.xml',
    category: 'alerts'
  },
  {
    name: 'CISA Known Exploited',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    category: 'exploits',
    isJSON: true
  },
  {
    name: 'Krebs on Security',
    url: 'https://krebsonsecurity.com/feed/',
    category: 'news'
  },
  {
    name: 'The Hacker News',
    url: 'https://feeds.feedburner.com/TheHackersNews',
    category: 'news'
  },
  {
    name: 'Threatpost',
    url: 'https://threatpost.com/feed/',
    category: 'news'
  },
  {
    name: 'Schneier on Security',
    url: 'https://www.schneier.com/feed/',
    category: 'analysis'
  }
];

/**
 * Fetch a URL and return its body
 * @param {string} url
 * @returns {Promise<string>}
 */
function fetchURL(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    const req = client.get(url, {
      timeout: FETCH_TIMEOUT,
      headers: {
        'User-Agent': 'Vigil/1.0 Security Intelligence Agent'
      }
    }, (res) => {
      // Follow redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchURL(res.headers.location).then(resolve).catch(reject);
      }

      if (res.statusCode !== 200) {
        return reject(new Error('HTTP ' + res.statusCode));
      }

      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Timeout'));
    });
  });
}

/**
 * Parse RSS/Atom XML into items
 * Very basic XML parser — handles common RSS and Atom formats
 * @param {string} xml
 * @returns {Array}
 */
function parseRSS(xml) {
  const items = [];

  // Try RSS <item> elements
  const itemRegex = /<item>([\s\S]*?)<\/item>/gi;
  let match;

  while ((match = itemRegex.exec(xml)) !== null) {
    const block = match[1];
    const title = extractTag(block, 'title');
    const link = extractTag(block, 'link');
    const description = extractTag(block, 'description');
    const pubDate = extractTag(block, 'pubDate');

    if (title) {
      items.push({
        title: decodeEntities(title),
        link: decodeEntities(link || ''),
        description: decodeEntities((description || '').substring(0, 500)),
        date: pubDate ? new Date(pubDate).toISOString() : null
      });
    }
  }

  // Try Atom <entry> elements if no RSS items found
  if (items.length === 0) {
    const entryRegex = /<entry>([\s\S]*?)<\/entry>/gi;
    while ((match = entryRegex.exec(xml)) !== null) {
      const block = match[1];
      const title = extractTag(block, 'title');
      const linkMatch = block.match(/<link[^>]*href=["']([^"']*)["']/);
      const summary = extractTag(block, 'summary') || extractTag(block, 'content');
      const updated = extractTag(block, 'updated') || extractTag(block, 'published');

      if (title) {
        items.push({
          title: decodeEntities(title),
          link: linkMatch ? decodeEntities(linkMatch[1]) : '',
          description: decodeEntities((summary || '').substring(0, 500)),
          date: updated ? new Date(updated).toISOString() : null
        });
      }
    }
  }

  return items;
}

function extractTag(xml, tag) {
  // Handle CDATA
  const cdataRegex = new RegExp('<' + tag + '[^>]*>\\s*<!\\[CDATA\\[([\\s\\S]*?)\\]\\]>\\s*</' + tag + '>', 'i');
  const cdataMatch = xml.match(cdataRegex);
  if (cdataMatch) return cdataMatch[1].trim();

  const regex = new RegExp('<' + tag + '[^>]*>([\\s\\S]*?)</' + tag + '>', 'i');
  const match = xml.match(regex);
  return match ? match[1].trim() : null;
}

function decodeEntities(str) {
  if (!str) return '';
  return str
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/<[^>]*>/g, ''); // Strip HTML tags
}

/**
 * Fetch all security feeds
 * @returns {Promise<Array>} - Array of { source, category, items[] }
 */
async function fetchFeeds() {
  const cacheKey = 'threat-intel:feeds';
  const cached = neuralCache.get(cacheKey);
  if (cached) return cached;

  const results = [];

  const feedPromises = RSS_FEEDS.map(async (feed) => {
    try {
      const body = await fetchURL(feed.url);

      if (feed.isJSON) {
        const data = JSON.parse(body);
        const items = (data.vulnerabilities || []).slice(0, 20).map(v => ({
          title: v.cveID || v.vulnerabilityName || 'Unknown',
          link: v.notes || '',
          description: v.shortDescription || v.vulnerabilityName || '',
          date: v.dateAdded || null,
          cve: v.cveID || null
        }));
        results.push({ source: feed.name, category: feed.category, items, fetched: new Date().toISOString() });
      } else {
        const items = parseRSS(body).slice(0, 20);
        results.push({ source: feed.name, category: feed.category, items, fetched: new Date().toISOString() });
      }
    } catch (err) {
      results.push({
        source: feed.name,
        category: feed.category,
        items: [],
        error: err.message,
        fetched: new Date().toISOString()
      });
    }
  });

  await Promise.allSettled(feedPromises);

  neuralCache.set(cacheKey, results, CACHE_TTL);
  return results;
}

/**
 * Correlate local findings against known CVEs
 * @param {Array} findings - Array of { cve, title, description }
 * @returns {Promise<Array>} - Enriched findings with threat intel
 */
async function correlateThreats(findings) {
  if (!findings || findings.length === 0) return [];

  const feeds = await fetchFeeds();
  const allFeedItems = [];
  feeds.forEach(f => {
    if (f.items) allFeedItems.push(...f.items);
  });

  return findings.map(finding => {
    const matches = [];

    // Match by CVE
    if (finding.cve) {
      const cveMatches = allFeedItems.filter(item =>
        item.title && item.title.includes(finding.cve) ||
        item.description && item.description.includes(finding.cve) ||
        item.cve === finding.cve
      );
      matches.push(...cveMatches);
    }

    // Keyword matching
    if (finding.title) {
      const keywords = finding.title.toLowerCase().split(/\s+/).filter(w => w.length > 4);
      const kwMatches = allFeedItems.filter(item => {
        const text = ((item.title || '') + ' ' + (item.description || '')).toLowerCase();
        return keywords.some(kw => text.includes(kw));
      });
      matches.push(...kwMatches.slice(0, 3));
    }

    return {
      ...finding,
      intelMatches: matches.slice(0, 5),
      intelCount: matches.length,
      intelEnriched: matches.length > 0
    };
  });
}

/**
 * Get overall threat level based on feeds + local analysis
 * @returns {Promise<object>} - { level, score, summary, feedStatus }
 */
async function getThreatLevel() {
  const cacheKey = 'threat-intel:level';
  const cached = neuralCache.get(cacheKey);
  if (cached) return cached;

  const feeds = await fetchFeeds();
  let totalItems = 0;
  let criticalItems = 0;
  let recentItems = 0;
  const oneDayAgo = new Date(Date.now() - 86400000).toISOString();

  feeds.forEach(feed => {
    if (!feed.items) return;
    totalItems += feed.items.length;

    feed.items.forEach(item => {
      const text = ((item.title || '') + ' ' + (item.description || '')).toLowerCase();
      if (text.includes('critical') || text.includes('emergency') || text.includes('0-day') || text.includes('zero-day')) {
        criticalItems++;
      }
      if (item.date && item.date > oneDayAgo) {
        recentItems++;
      }
    });
  });

  let level, score;
  if (criticalItems > 5) {
    level = 'critical';
    score = 90;
  } else if (criticalItems > 2) {
    level = 'high';
    score = 70;
  } else if (recentItems > 10) {
    level = 'elevated';
    score = 50;
  } else if (totalItems > 0) {
    level = 'guarded';
    score = 30;
  } else {
    level = 'low';
    score = 10;
  }

  const result = {
    level,
    score,
    summary: `${totalItems} items from ${feeds.length} feeds, ${criticalItems} critical, ${recentItems} in last 24h`,
    feedStatus: feeds.map(f => ({
      name: f.source,
      category: f.category,
      itemCount: f.items ? f.items.length : 0,
      error: f.error || null
    })),
    ts: new Date().toISOString()
  };

  neuralCache.set(cacheKey, result, CACHE_TTL);
  return result;
}

module.exports = {
  RSS_FEEDS,
  fetchFeeds,
  correlateThreats,
  getThreatLevel
};
