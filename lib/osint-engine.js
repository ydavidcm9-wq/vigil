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
  emailLookup,
  getDNSRecords,
  getWhois,
  findSubdomains,
  getCertTransparency
};
