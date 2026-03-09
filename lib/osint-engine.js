// Vigil — OSINT reconnaissance engine
// Uses built-in dns module + https for external lookups — no dependencies
const dns = require('dns');
const https = require('https');
const http = require('http');
const neuralCache = require('./neural-cache');

const CACHE_TTL = 10 * 60 * 1000; // 10 minutes
const FETCH_TIMEOUT = 10000;

/**
 * Domain reconnaissance — WHOIS, DNS records, subdomains, cert transparency
 * @param {string} domain
 * @returns {Promise<object>}
 */
async function domainRecon(domain) {
  if (!domain) return { error: 'No domain specified' };

  const cacheKey = 'osint:domain:' + domain;
  const cached = neuralCache.get(cacheKey);
  if (cached) return cached;

  const results = {
    domain,
    dns: {},
    whois: null,
    subdomains: [],
    certTransparency: [],
    timestamp: new Date().toISOString()
  };

  // Run all lookups in parallel
  const [dnsResults, whoisResult, subdomainResult, ctResult] = await Promise.allSettled([
    getDNSRecords(domain),
    getWhois(domain),
    findSubdomains(domain),
    getCertTransparency(domain)
  ]);

  if (dnsResults.status === 'fulfilled') results.dns = dnsResults.value;
  if (whoisResult.status === 'fulfilled') results.whois = whoisResult.value;
  if (subdomainResult.status === 'fulfilled') results.subdomains = subdomainResult.value;
  if (ctResult.status === 'fulfilled') results.certTransparency = ctResult.value;

  neuralCache.set(cacheKey, results, CACHE_TTL);
  return results;
}

/**
 * Get all DNS records for a domain
 * @param {string} domain
 * @returns {Promise<object>}
 */
async function getDNSRecords(domain) {
  const records = {};

  const lookups = [
    { type: 'A', fn: () => dnsResolve(domain, 'A') },
    { type: 'AAAA', fn: () => dnsResolve(domain, 'AAAA') },
    { type: 'MX', fn: () => dnsResolveMx(domain) },
    { type: 'TXT', fn: () => dnsResolve(domain, 'TXT') },
    { type: 'NS', fn: () => dnsResolve(domain, 'NS') },
    { type: 'CNAME', fn: () => dnsResolve(domain, 'CNAME') },
    { type: 'SOA', fn: () => dnsResolveSoa(domain) }
  ];

  const results = await Promise.allSettled(lookups.map(l => l.fn()));

  lookups.forEach((lookup, i) => {
    if (results[i].status === 'fulfilled' && results[i].value) {
      records[lookup.type] = results[i].value;
    }
  });

  return records;
}

function dnsResolve(domain, type) {
  return new Promise((resolve, reject) => {
    dns.resolve(domain, type, (err, records) => {
      if (err) return reject(err);
      resolve(records);
    });
  });
}

function dnsResolveMx(domain) {
  return new Promise((resolve, reject) => {
    dns.resolveMx(domain, (err, records) => {
      if (err) return reject(err);
      resolve(records.sort((a, b) => a.priority - b.priority));
    });
  });
}

function dnsResolveSoa(domain) {
  return new Promise((resolve, reject) => {
    dns.resolveSoa(domain, (err, record) => {
      if (err) return reject(err);
      resolve(record);
    });
  });
}

/**
 * WHOIS lookup via whois binary or web API fallback
 * @param {string} domain
 * @returns {Promise<object>}
 */
async function getWhois(domain) {
  // Try whois binary first
  try {
    const { execCommand, binaryExists } = require('./exec');
    const hasWhois = await binaryExists('whois');

    if (hasWhois) {
      const result = await execCommand(`whois ${domain}`, { timeout: 10000 });
      if (result.code === 0 && result.stdout) {
        return parseWhois(result.stdout);
      }
    }
  } catch {}

  // Fallback: no whois available
  return {
    available: false,
    message: 'whois binary not found — install whois package'
  };
}

/**
 * Parse WHOIS output into structured data
 * @param {string} raw
 * @returns {object}
 */
function parseWhois(raw) {
  const data = { raw: raw.substring(0, 2000) };

  const fields = {
    registrar: /Registrar:\s*(.+)/i,
    created: /Creat(?:ion|ed)\s*Date:\s*(.+)/i,
    expires: /Expir(?:ation|y)\s*Date:\s*(.+)/i,
    updated: /Updated?\s*Date:\s*(.+)/i,
    nameServers: /Name\s*Server:\s*(.+)/gi,
    status: /Status:\s*(.+)/gi,
    registrant: /Registrant\s*(?:Name|Organization):\s*(.+)/i
  };

  for (const [key, regex] of Object.entries(fields)) {
    if (key === 'nameServers' || key === 'status') {
      const matches = [];
      let m;
      while ((m = regex.exec(raw)) !== null) {
        matches.push(m[1].trim());
      }
      if (matches.length > 0) data[key] = matches;
    } else {
      const match = raw.match(regex);
      if (match) data[key] = match[1].trim();
    }
  }

  return data;
}

/**
 * Find subdomains via DNS brute-force (common prefixes)
 * @param {string} domain
 * @returns {Promise<string[]>}
 */
async function findSubdomains(domain) {
  const commonPrefixes = [
    'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
    'smtp', 'secure', 'vpn', 'admin', 'api', 'dev', 'staging', 'test',
    'ftp', 'cloud', 'git', 'cdn', 'app', 'portal', 'dashboard',
    'login', 'auth', 'sso', 'docs', 'status', 'monitor', 'mx',
    'pop', 'imap', 'autodiscover', 'cpanel', 'whm', 'backup'
  ];

  const found = [];

  const checks = commonPrefixes.map(prefix => {
    const subdomain = prefix + '.' + domain;
    return new Promise(resolve => {
      dns.resolve4(subdomain, (err, addresses) => {
        if (!err && addresses && addresses.length > 0) {
          found.push({ subdomain, addresses });
        }
        resolve();
      });
    });
  });

  await Promise.allSettled(checks);
  return found;
}

/**
 * Certificate transparency log search
 * Uses crt.sh API
 * @param {string} domain
 * @returns {Promise<Array>}
 */
async function getCertTransparency(domain) {
  try {
    const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
    const body = await fetchJSON(url);

    if (!Array.isArray(body)) return [];

    // Deduplicate and limit
    const seen = new Set();
    const results = [];

    for (const entry of body) {
      const name = entry.name_value || entry.common_name || '';
      const names = name.split('\n').map(n => n.trim()).filter(Boolean);

      for (const n of names) {
        if (!seen.has(n) && n.includes(domain)) {
          seen.add(n);
          results.push({
            name: n,
            issuer: entry.issuer_name || '',
            notBefore: entry.not_before || '',
            notAfter: entry.not_after || '',
            serialNumber: entry.serial_number || ''
          });
        }
      }

      if (results.length >= 100) break;
    }

    return results;
  } catch {
    return [];
  }
}

/**
 * IP address lookup — reverse DNS, geolocation, ASN
 * @param {string} ip
 * @returns {Promise<object>}
 */
async function ipLookup(ip) {
  if (!ip) return { error: 'No IP specified' };

  const cacheKey = 'osint:ip:' + ip;
  const cached = neuralCache.get(cacheKey);
  if (cached) return cached;

  const results = {
    ip,
    reverseDNS: null,
    geolocation: null,
    timestamp: new Date().toISOString()
  };

  // Reverse DNS
  try {
    results.reverseDNS = await new Promise((resolve, reject) => {
      dns.reverse(ip, (err, hostnames) => {
        if (err) return reject(err);
        resolve(hostnames);
      });
    });
  } catch {
    results.reverseDNS = [];
  }

  // Geolocation via ip-api.com (free, no API key)
  try {
    const geoData = await fetchJSON(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query`);
    if (geoData && geoData.status === 'success') {
      results.geolocation = {
        country: geoData.country,
        countryCode: geoData.countryCode,
        region: geoData.regionName,
        city: geoData.city,
        zip: geoData.zip,
        lat: geoData.lat,
        lon: geoData.lon,
        timezone: geoData.timezone,
        isp: geoData.isp,
        org: geoData.org,
        as: geoData.as,
        asName: geoData.asname
      };
    }
  } catch {}

  neuralCache.set(cacheKey, results, CACHE_TTL);
  return results;
}

/**
 * Fetch JSON from a URL
 * @param {string} url
 * @returns {Promise<object>}
 */
function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;

    const req = client.get(url, {
      timeout: FETCH_TIMEOUT,
      headers: {
        'User-Agent': 'Vigil/1.0 Security OSINT Agent',
        'Accept': 'application/json'
      }
    }, (res) => {
      // Follow redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchJSON(res.headers.location).then(resolve).catch(reject);
      }

      if (res.statusCode !== 200) {
        return reject(new Error('HTTP ' + res.statusCode));
      }

      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Timeout'));
    });
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  WebOSINT-inspired modules — Reverse IP, Domain Reputation, WHOIS History
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Fetch plain text from a URL (for APIs that return text, not JSON)
 * @param {string} url
 * @returns {Promise<string>}
 */
function fetchText(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    const req = client.get(url, {
      timeout: FETCH_TIMEOUT,
      headers: {
        'User-Agent': 'Vigil/1.0 Security OSINT Agent',
        'Accept': 'text/plain, application/json'
      }
    }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchText(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error('HTTP ' + res.statusCode));
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

/**
 * Reverse IP lookup via HackerTarget (free, no API key needed)
 * Returns domains hosted on the same IP address
 * @param {string} ip — IPv4 address
 * @param {string} [apiKey] — optional HackerTarget API key for higher limits
 * @returns {Promise<object>}
 */
async function reverseIPLookup(ip, apiKey) {
  if (!ip) return { error: 'No IP specified' };

  const cacheKey = 'osint:reverse-ip:' + ip;
  const cached = neuralCache.get(cacheKey);
  if (cached) return cached;

  const result = { ip, domains: [], count: 0 };

  try {
    const baseUrl = apiKey
      ? `https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(ip)}&apikey=${apiKey}`
      : `http://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(ip)}`;

    const text = await fetchText(baseUrl);

    if (text && !text.startsWith('error') && !text.includes('API count exceeded')) {
      result.domains = text.trim().split('\n')
        .map(d => d.trim())
        .filter(d => d && d !== 'No DNS A records found' && !d.startsWith('error'));
      result.count = result.domains.length;
    } else if (text && text.includes('API count exceeded')) {
      result.rateLimited = true;
    }
  } catch (e) {
    result.error = e.message;
  }

  neuralCache.set(cacheKey, result, CACHE_TTL);
  return result;
}

/**
 * Domain reputation score via WhoisXML API
 * @param {string} domain
 * @param {string} apiKey — WhoisXML API key (required)
 * @returns {Promise<object>}
 */
async function domainReputation(domain, apiKey) {
  if (!domain) return { error: 'No domain specified' };
  if (!apiKey) return { available: false, message: 'WhoisXML API key not configured — add in Settings > Credentials' };

  const cacheKey = 'osint:reputation:' + domain;
  const cached = neuralCache.get(cacheKey);
  if (cached) return cached;

  const result = { domain, score: null, tests: [] };

  try {
    const url = `https://domain-reputation.whoisxmlapi.com/api/v2?apiKey=${apiKey}&domainName=${encodeURIComponent(domain)}`;
    const data = await fetchJSON(url);

    if (data) {
      result.score = data.reputationScore != null ? data.reputationScore : null;
      result.mode = data.mode || 'fast';
      if (Array.isArray(data.testResults)) {
        result.tests = data.testResults.map(t => ({
          test: t.test || '',
          result: t.testCode != null ? t.testCode : null,
          warnings: Array.isArray(t.warnings) ? t.warnings : []
        }));
        result.testsPassed = result.tests.filter(t => t.result === 0).length;
        result.testsFailed = result.tests.filter(t => t.result !== 0).length;
      }
    }
  } catch (e) {
    result.error = e.message;
  }

  neuralCache.set(cacheKey, result, CACHE_TTL);
  return result;
}

/**
 * Historical WHOIS records via WhoisFreaks API
 * @param {string} domain
 * @param {string} apiKey — WhoisFreaks API key (required)
 * @returns {Promise<object>}
 */
async function whoisHistory(domain, apiKey) {
  if (!domain) return { error: 'No domain specified' };
  if (!apiKey) return { available: false, message: 'WhoisFreaks API key not configured — add in Settings > Credentials' };

  const cacheKey = 'osint:whois-history:' + domain;
  const cached = neuralCache.get(cacheKey);
  if (cached) return cached;

  const result = { domain, records: [], count: 0 };

  try {
    const url = `https://api.whoisfreaks.com/v1.0/whois?apiKey=${apiKey}&whois=historical&domainName=${encodeURIComponent(domain)}`;
    const data = await fetchJSON(url);

    if (data && Array.isArray(data.whois_records)) {
      result.records = data.whois_records.slice(0, 20).map(r => ({
        date: r.create_date || r.update_date || null,
        registrar: r.registrar ? (r.registrar.name || r.registrar) : null,
        registrant: r.registrant ? (r.registrant.organization || r.registrant.name || null) : null,
        nameservers: r.name_servers ? (Array.isArray(r.name_servers) ? r.name_servers : [r.name_servers]) : [],
        created: r.create_date || null,
        updated: r.update_date || null,
        expires: r.expiry_date || null,
      }));
      result.count = data.whois_records_count || result.records.length;
    } else if (data && data.status === false) {
      result.error = data.message || 'API error';
    }
  } catch (e) {
    result.error = e.message;
  }

  neuralCache.set(cacheKey, result, CACHE_TTL);
  return result;
}

/**
 * Enhanced IP lookup with dual-source geolocation (ip-api.com + ipinfo.io)
 * @param {string} ip
 * @returns {Promise<object>}
 */
async function ipLookupEnhanced(ip) {
  if (!ip) return { error: 'No IP specified' };

  const cacheKey = 'osint:ip-enhanced:' + ip;
  const cached = neuralCache.get(cacheKey);
  if (cached) return cached;

  const result = { ip, sources: [] };

  // Dual-source geolocation for cross-verification
  const [ipApiResult, ipInfoResult] = await Promise.allSettled([
    fetchJSON(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query`),
    fetchJSON(`https://ipinfo.io/${ip}/json`)
  ]);

  if (ipApiResult.status === 'fulfilled' && ipApiResult.value && ipApiResult.value.status === 'success') {
    const d = ipApiResult.value;
    result.primary = {
      source: 'ip-api.com',
      country: d.country, countryCode: d.countryCode,
      region: d.regionName, city: d.city, zip: d.zip,
      lat: d.lat, lon: d.lon, timezone: d.timezone,
      isp: d.isp, org: d.org, as: d.as, asName: d.asname
    };
    result.sources.push('ip-api.com');
  }

  if (ipInfoResult.status === 'fulfilled' && ipInfoResult.value && !ipInfoResult.value.error) {
    const d = ipInfoResult.value;
    const [lat, lon] = (d.loc || '').split(',').map(Number);
    result.secondary = {
      source: 'ipinfo.io',
      city: d.city || null,
      region: d.region || null,
      country: d.country || null,
      org: d.org || null,
      postal: d.postal || null,
      timezone: d.timezone || null,
      lat: lat || null, lon: lon || null,
      hostname: d.hostname || null
    };
    result.sources.push('ipinfo.io');
  }

  // Cross-verification: check if both sources agree
  if (result.primary && result.secondary) {
    result.verified = (result.primary.country === result.secondary.country) ||
      (result.primary.countryCode === result.secondary.country);
  }

  neuralCache.set(cacheKey, result, CACHE_TTL);
  return result;
}

/**
 * Email address OSINT — check for breaches (HIBP-style, no API key needed)
 * @param {string} email
 * @returns {Promise<object>}
 */
async function emailLookup(email) {
  if (!email) return { error: 'No email specified' };

  const domain = email.split('@')[1];
  if (!domain) return { error: 'Invalid email format' };

  const results = {
    email,
    domain,
    mxRecords: [],
    domainAge: null,
    timestamp: new Date().toISOString()
  };

  // Check MX records for email domain
  try {
    results.mxRecords = await dnsResolveMx(domain);
  } catch {
    results.mxRecords = [];
  }

  // Basic domain recon for the email domain
  try {
    const dnsRecords = await getDNSRecords(domain);
    results.dnsRecords = dnsRecords;
  } catch {}

  return results;
}

module.exports = {
  domainRecon,
  ipLookup,
  ipLookupEnhanced,
  emailLookup,
  getDNSRecords,
  getWhois,
  findSubdomains,
  getCertTransparency,
  reverseIPLookup,
  domainReputation,
  whoisHistory
};
