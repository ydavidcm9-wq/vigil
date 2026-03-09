/**
 * Vigil — Web Reconnaissance Engine (Scrapy-inspired)
 *
 * Lightweight Node.js web crawler for security reconnaissance.
 * Architecture: Spider → Middleware → Pipeline (Scrapy pattern)
 *
 * Spider types:
 *   surface     — Crawl domain, extract links/emails/tech/headers
 *   exposed     — Check common sensitive paths (.env, .git, backups)
 *   fingerprint — Deep tech stack detection from headers + HTML patterns
 */
const https = require('https');
const http = require('http');
const { URL } = require('url');
const EventEmitter = require('events');

// ── Exposed/Sensitive paths to check ──
const SENSITIVE_PATHS = [
  '/.env', '/.git/config', '/.git/HEAD', '/.gitignore',
  '/.htaccess', '/.htpasswd', '/web.config', '/wp-config.php',
  '/wp-config.php.bak', '/wp-login.php', '/administrator/',
  '/backup.zip', '/backup.tar.gz', '/backup.sql', '/db.sql',
  '/dump.sql', '/database.sql', '/config.php', '/config.yml',
  '/config.json', '/package.json', '/composer.json',
  '/Dockerfile', '/docker-compose.yml', '/.dockerignore',
  '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
  '/.well-known/security.txt', '/server-status', '/server-info',
  '/phpinfo.php', '/info.php', '/test.php', '/debug/',
  '/api/', '/api/v1/', '/api/swagger.json', '/swagger-ui/',
  '/graphql', '/.DS_Store', '/Thumbs.db',
  '/error_log', '/access.log', '/debug.log',
  '/.ssh/authorized_keys', '/id_rsa', '/id_rsa.pub',
  '/credentials.json', '/secrets.yml', '/token.json',
];

// ── Tech fingerprint patterns ──
const TECH_PATTERNS = {
  // Headers
  headers: {
    'x-powered-by': { regex: /(.+)/, field: 'poweredBy' },
    'server': { regex: /(.+)/, field: 'server' },
    'x-aspnet-version': { regex: /(.+)/, field: 'aspnet' },
    'x-drupal-cache': { regex: /.+/, value: 'Drupal' },
    'x-generator': { regex: /(.+)/, field: 'generator' },
    'x-varnish': { regex: /.+/, value: 'Varnish' },
    'x-cache': { regex: /HIT|MISS/, value: 'CDN Cache' },
    'cf-ray': { regex: /.+/, value: 'Cloudflare' },
    'x-amz-cf-id': { regex: /.+/, value: 'AWS CloudFront' },
    'x-vercel-id': { regex: /.+/, value: 'Vercel' },
    'x-netlify-request-id': { regex: /.+/, value: 'Netlify' },
  },
  // HTML body patterns
  body: [
    { regex: /<meta\s+name=["']generator["']\s+content=["']([^"']+)/i, field: 'generator' },
    { regex: /wp-content|wp-includes/i, value: 'WordPress' },
    { regex: /\/sites\/default\/files/i, value: 'Drupal' },
    { regex: /Joomla!/i, value: 'Joomla' },
    { regex: /shopify\.com/i, value: 'Shopify' },
    { regex: /react/i, value: 'React (possible)' },
    { regex: /ng-app|angular/i, value: 'Angular (possible)' },
    { regex: /vue\.js|__vue__/i, value: 'Vue.js (possible)' },
    { regex: /jquery[./\-](\d[\d.]+)/i, field: 'jQuery' },
    { regex: /bootstrap[./\-](\d[\d.]+)/i, field: 'Bootstrap' },
    { regex: /next\.js|__NEXT_DATA__/i, value: 'Next.js' },
    { regex: /nuxt/i, value: 'Nuxt.js' },
    { regex: /laravel/i, value: 'Laravel' },
    { regex: /django/i, value: 'Django' },
    { regex: /express/i, value: 'Express.js (possible)' },
    { regex: /phpmyadmin/i, value: 'phpMyAdmin' },
    { regex: /grafana/i, value: 'Grafana' },
    { regex: /kibana/i, value: 'Kibana' },
    { regex: /gitlab/i, value: 'GitLab' },
    { regex: /jenkins/i, value: 'Jenkins' },
  ],
};

// ── Security headers to check ──
const SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'x-xss-protection',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
];

/** Fetch a URL with timeout, redirect following, and response metadata */
function fetchURL(url, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.request(parsed, {
      method: 'GET',
      timeout,
      headers: {
        'User-Agent': 'Vigil-SecurityScanner/1.0 (+https://vigil.agency)',
        'Accept': 'text/html,application/xhtml+xml,*/*',
      },
      rejectUnauthorized: false,
    }, (res) => {
      // Follow redirects (up to 3)
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        try {
          const redirectUrl = new URL(res.headers.location, url).href;
          res.resume();
          return fetchURL(redirectUrl, timeout).then(resolve).catch(reject);
        } catch { /* fall through */ }
      }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { if (body.length < 500000) body += chunk; }); // 500KB limit
      res.on('end', () => {
        resolve({
          url,
          statusCode: res.statusCode,
          headers: res.headers,
          body,
          contentType: res.headers['content-type'] || '',
        });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.end();
  });
}

/** Parse robots.txt and return disallowed paths */
function parseRobotsTxt(body) {
  const disallowed = [];
  let inWildcard = false;
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (/^user-agent:\s*\*/i.test(trimmed)) inWildcard = true;
    else if (/^user-agent:/i.test(trimmed)) inWildcard = false;
    else if (inWildcard && /^disallow:\s*(.+)/i.test(trimmed)) {
      disallowed.push(RegExp.$1.trim());
    }
  }
  return disallowed;
}

/** Extract links from HTML */
function extractLinks(html, baseUrl) {
  const links = new Set();
  const regex = /(?:href|src|action)=["']([^"'#]+)/gi;
  let match;
  while ((match = regex.exec(html)) !== null) {
    try {
      const resolved = new URL(match[1], baseUrl).href;
      if (resolved.startsWith('http')) links.add(resolved);
    } catch { /* skip invalid URLs */ }
  }
  return [...links];
}

/** Extract emails from HTML */
function extractEmails(html) {
  const emails = new Set();
  const regex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  let match;
  while ((match = regex.exec(html)) !== null) {
    const email = match[0].toLowerCase();
    if (!email.endsWith('.png') && !email.endsWith('.jpg') && !email.endsWith('.gif')) {
      emails.add(email);
    }
  }
  return [...emails];
}

/** Extract forms from HTML */
function extractForms(html, baseUrl) {
  const forms = [];
  const formRegex = /<form[^>]*>([\s\S]*?)<\/form>/gi;
  let match;
  while ((match = formRegex.exec(html)) !== null) {
    const tag = match[0];
    const actionMatch = tag.match(/action=["']([^"']*)/i);
    const methodMatch = tag.match(/method=["']([^"']*)/i);
    const hasPassword = /type=["']password/i.test(match[1]);
    const hasFile = /type=["']file/i.test(match[1]);
    const inputCount = (match[1].match(/<input/gi) || []).length;
    forms.push({
      action: actionMatch ? actionMatch[1] : '',
      method: (methodMatch ? methodMatch[1] : 'GET').toUpperCase(),
      hasPassword,
      hasFile,
      inputCount,
    });
  }
  return forms;
}

/** Detect technologies from headers and body */
function detectTech(headers, body) {
  const techs = new Set();
  const details = {};

  // Header-based detection
  for (const [header, pattern] of Object.entries(TECH_PATTERNS.headers)) {
    const val = headers[header];
    if (val) {
      if (pattern.value) techs.add(pattern.value);
      if (pattern.field) { details[pattern.field] = val; techs.add(val); }
    }
  }

  // Body-based detection
  for (const pattern of TECH_PATTERNS.body) {
    const match = body.match(pattern.regex);
    if (match) {
      if (pattern.value) techs.add(pattern.value);
      if (pattern.field) { details[pattern.field] = match[1] || 'detected'; techs.add(`${pattern.field} ${match[1] || ''}`); }
    }
  }

  return { technologies: [...techs], details };
}

/** Analyze security headers */
function analyzeSecurityHeaders(headers) {
  const present = [];
  const missing = [];
  for (const h of SECURITY_HEADERS) {
    if (headers[h]) present.push({ header: h, value: headers[h] });
    else missing.push(h);
  }
  const score = Math.round((present.length / SECURITY_HEADERS.length) * 100);
  return { present, missing, score, total: SECURITY_HEADERS.length };
}


// ═══════════════════════════════════════════════════════════════════════
//  WebRecon — Main crawler engine
// ═══════════════════════════════════════════════════════════════════════

class WebRecon extends EventEmitter {
  constructor(options = {}) {
    super();
    this.maxDepth = options.depth || 2;
    this.maxPages = options.maxPages || 30;
    this.delay = options.delay || 500; // ms between requests
    this.respectRobots = options.respectRobots !== false;
    this.timeout = options.timeout || 10000;

    // Scheduler state
    this._visited = new Set();
    this._queue = [];
    this._results = { pages: [], emails: new Set(), technologies: new Set(), forms: [], exposedPaths: [], securityHeaders: null };
    this._pageCount = 0;
    this._running = false;
    this._disallowed = [];
    this._targetDomain = null;
  }

  /** Run a surface scan — crawl and extract everything */
  async surface(targetUrl) {
    const start = Date.now();
    const parsed = new URL(targetUrl);
    this._targetDomain = parsed.hostname;

    // Check robots.txt
    if (this.respectRobots) {
      try {
        const robotsUrl = `${parsed.protocol}//${parsed.host}/robots.txt`;
        const r = await fetchURL(robotsUrl, 5000);
        if (r.statusCode === 200) this._disallowed = parseRobotsTxt(r.body);
      } catch { /* no robots.txt */ }
    }

    // Seed the queue
    this._queue.push({ url: targetUrl, depth: 0 });

    // Crawl loop
    while (this._queue.length > 0 && this._pageCount < this.maxPages) {
      const { url, depth } = this._queue.shift();
      if (this._visited.has(url)) continue;
      if (depth > this.maxDepth) continue;
      if (this._isDisallowed(url)) continue;

      this._visited.add(url);
      this.emit('progress', { phase: 'crawling', url, pageCount: this._pageCount, queueSize: this._queue.length });

      try {
        const response = await fetchURL(url, this.timeout);
        this._pageCount++;

        const isHTML = response.contentType.includes('text/html');
        const page = {
          url: response.url,
          statusCode: response.statusCode,
          contentType: response.contentType,
          size: response.body.length,
        };

        if (isHTML) {
          // Extract links
          const links = extractLinks(response.body, url);
          const internal = links.filter(l => this._isInternal(l));
          const external = links.filter(l => !this._isInternal(l));
          page.internalLinks = internal.length;
          page.externalLinks = external.length;

          // Queue internal links for crawling
          for (const link of internal) {
            if (!this._visited.has(link)) {
              this._queue.push({ url: link, depth: depth + 1 });
            }
          }

          // Extract emails
          const emails = extractEmails(response.body);
          emails.forEach(e => this._results.emails.add(e));

          // Extract forms
          const forms = extractForms(response.body, url);
          if (forms.length) {
            this._results.forms.push(...forms.map(f => ({ ...f, page: url })));
          }

          // Tech detection
          const tech = detectTech(response.headers, response.body);
          tech.technologies.forEach(t => this._results.technologies.add(t));
        }

        // Security headers (first page only)
        if (!this._results.securityHeaders) {
          this._results.securityHeaders = analyzeSecurityHeaders(response.headers);
        }

        this._results.pages.push(page);

        // Rate limiting
        if (this.delay > 0) await this._sleep(this.delay);
      } catch (e) {
        this._results.pages.push({ url, statusCode: 0, error: e.message });
      }
    }

    return this._buildResult('surface', targetUrl, Date.now() - start);
  }

  /** Run exposed files check — probe sensitive paths */
  async exposed(targetUrl) {
    const start = Date.now();
    const parsed = new URL(targetUrl);
    const baseUrl = `${parsed.protocol}//${parsed.host}`;
    this._targetDomain = parsed.hostname;

    this.emit('progress', { phase: 'scanning', message: `Checking ${SENSITIVE_PATHS.length} paths...` });

    const results = [];
    for (const p of SENSITIVE_PATHS) {
      const url = baseUrl + p;
      try {
        const response = await fetchURL(url, this.timeout);
        const isExposed = response.statusCode === 200 && response.body.length > 0;
        const isForbidden = response.statusCode === 403;
        if (isExposed || isForbidden) {
          const risk = isExposed ? this._assessPathRisk(p) : 'info';
          results.push({
            path: p,
            url,
            statusCode: response.statusCode,
            size: response.body.length,
            contentType: response.contentType,
            risk,
            exposed: isExposed,
          });
          this.emit('progress', { phase: 'found', path: p, status: response.statusCode, risk });
        }
      } catch { /* timeout/error = not reachable */ }

      if (this.delay > 0) await this._sleep(Math.max(this.delay, 200)); // min 200ms for path scanning
    }

    this._results.exposedPaths = results;
    return this._buildResult('exposed', targetUrl, Date.now() - start);
  }

  /** Run tech fingerprinting — deep analysis of target */
  async fingerprint(targetUrl) {
    const start = Date.now();
    const parsed = new URL(targetUrl);
    this._targetDomain = parsed.hostname;

    this.emit('progress', { phase: 'fingerprinting', url: targetUrl });

    // Fetch main page
    try {
      const response = await fetchURL(targetUrl, this.timeout);
      const tech = detectTech(response.headers, response.body);
      tech.technologies.forEach(t => this._results.technologies.add(t));

      this._results.securityHeaders = analyzeSecurityHeaders(response.headers);
      this._results.pages.push({
        url: response.url,
        statusCode: response.statusCode,
        size: response.body.length,
      });

      // Extract forms
      const forms = extractForms(response.body, targetUrl);
      this._results.forms = forms.map(f => ({ ...f, page: targetUrl }));

      // Check a few key paths for more tech clues
      const techPaths = ['/robots.txt', '/sitemap.xml', '/favicon.ico', '/wp-login.php', '/administrator/', '/api/', '/.well-known/security.txt'];
      for (const p of techPaths) {
        try {
          const r = await fetchURL(`${parsed.protocol}//${parsed.host}${p}`, 5000);
          if (r.statusCode === 200) {
            if (p === '/wp-login.php') this._results.technologies.add('WordPress');
            if (p === '/administrator/') this._results.technologies.add('Joomla');
            if (p === '/.well-known/security.txt') this._results.technologies.add('security.txt present');
            if (p === '/robots.txt') {
              // Extract sitemaps and notable disallows
              const sitemaps = r.body.match(/Sitemap:\s*(.+)/gi) || [];
              if (sitemaps.length) this._results.technologies.add(`${sitemaps.length} sitemap(s)`);
            }
          }
        } catch { /* skip */ }
        await this._sleep(200);
      }
    } catch (e) {
      this._results.pages.push({ url: targetUrl, statusCode: 0, error: e.message });
    }

    return this._buildResult('fingerprint', targetUrl, Date.now() - start);
  }

  _isInternal(url) {
    try {
      return new URL(url).hostname === this._targetDomain;
    } catch { return false; }
  }

  _isDisallowed(url) {
    if (!this._disallowed.length) return false;
    try {
      const p = new URL(url).pathname;
      return this._disallowed.some(d => p.startsWith(d));
    } catch { return false; }
  }

  _assessPathRisk(path) {
    if (/\.env|credentials|secret|token|id_rsa|\.ssh/i.test(path)) return 'critical';
    if (/\.git|\.htpasswd|wp-config|config\.(php|yml|json)|\.sql|dump/i.test(path)) return 'high';
    if (/backup|phpinfo|debug|server-(status|info)/i.test(path)) return 'medium';
    return 'low';
  }

  _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

  _buildResult(spiderType, target, duration) {
    return {
      spiderType,
      target,
      domain: this._targetDomain,
      duration,
      pagesScanned: this._results.pages.length,
      pages: this._results.pages,
      emails: [...this._results.emails],
      technologies: [...this._results.technologies],
      forms: this._results.forms,
      exposedPaths: this._results.exposedPaths,
      securityHeaders: this._results.securityHeaders,
      summary: {
        pagesScanned: this._results.pages.length,
        emailsFound: this._results.emails.size,
        technologiesDetected: this._results.technologies.size,
        formsFound: this._results.forms.length,
        exposedPathsFound: this._results.exposedPaths.filter(p => p.exposed).length,
        forbiddenPaths: this._results.exposedPaths.filter(p => p.statusCode === 403).length,
        securityHeaderScore: this._results.securityHeaders ? this._results.securityHeaders.score : null,
        loginForms: this._results.forms.filter(f => f.hasPassword).length,
        fileUploads: this._results.forms.filter(f => f.hasFile).length,
      },
    };
  }
}

module.exports = { WebRecon, fetchURL, SENSITIVE_PATHS, SECURITY_HEADERS };
