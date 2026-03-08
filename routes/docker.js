/**
 * Docker Routes — Container security monitoring
 * Supports: local Docker images + user-added image watchlist
 * Scanning: Trivy (if installed) or native AI-powered analysis
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA = path.join(__dirname, '..', 'data');
const IMAGES_PATH = path.join(DATA, 'container-images.json');

function readJSON(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return fallback; }
}
function writeJSON(p, data) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + '.tmp.' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, p);
}

function dockerRequest(method, apiPath, body) {
  return new Promise((resolve, reject) => {
    const isWin = process.platform === 'win32';
    const opts = {
      method,
      path: apiPath,
      headers: { 'Content-Type': 'application/json' },
      timeout: 10000,
    };
    if (isWin) opts.socketPath = '//./pipe/docker_engine';
    else opts.socketPath = '/var/run/docker.sock';

    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, data }); }
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('timeout')); });
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// Fetch Docker Hub image tags/metadata
function fetchDockerHubInfo(imageName) {
  return new Promise((resolve) => {
    // Parse image name — handle library images and namespaced images
    let namespace = 'library';
    let repo = imageName;
    if (imageName.includes('/')) {
      const parts = imageName.split('/');
      namespace = parts[0];
      repo = parts.slice(1).join('/');
    }
    const url = `https://hub.docker.com/v2/repositories/${namespace}/${repo}/`;

    https.get(url, { timeout: 8000 }, (res) => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve(JSON.parse(d)); } catch { resolve(null); }
      });
    }).on('error', () => resolve(null));
  });
}

// Known EOL / vulnerable base image patterns
const EOL_IMAGES = {
  'node:14': { eol: '2023-04-30', severity: 'critical', reason: 'Node.js 14 is End of Life — no security patches' },
  'node:16': { eol: '2023-09-11', severity: 'critical', reason: 'Node.js 16 is End of Life — no security patches' },
  'node:18': { eol: '2025-04-30', severity: 'medium', reason: 'Node.js 18 enters maintenance — consider upgrading to 22 LTS' },
  'python:3.7': { eol: '2023-06-27', severity: 'critical', reason: 'Python 3.7 is End of Life' },
  'python:3.8': { eol: '2024-10-07', severity: 'critical', reason: 'Python 3.8 is End of Life' },
  'python:3.9': { eol: '2025-10-05', severity: 'medium', reason: 'Python 3.9 approaching EOL' },
  'ubuntu:18.04': { eol: '2023-05-31', severity: 'critical', reason: 'Ubuntu 18.04 is End of Life — no security updates' },
  'ubuntu:20.04': { eol: '2025-04-02', severity: 'medium', reason: 'Ubuntu 20.04 approaching EOL' },
  'alpine:3.16': { eol: '2024-05-23', severity: 'high', reason: 'Alpine 3.16 is End of Life' },
  'alpine:3.17': { eol: '2024-11-22', severity: 'high', reason: 'Alpine 3.17 is End of Life' },
  'debian:10': { eol: '2024-06-30', severity: 'critical', reason: 'Debian 10 (Buster) is End of Life' },
  'debian:11': { eol: '2026-06-30', severity: 'low', reason: 'Debian 11 (Bullseye) — still maintained but consider upgrading' },
  'postgres:12': { eol: '2024-11-14', severity: 'critical', reason: 'PostgreSQL 12 is End of Life' },
  'postgres:13': { eol: '2025-11-13', severity: 'medium', reason: 'PostgreSQL 13 approaching EOL' },
  'mysql:5.7': { eol: '2023-10-21', severity: 'critical', reason: 'MySQL 5.7 is End of Life' },
  'redis:6': { eol: '2025-04-01', severity: 'medium', reason: 'Redis 6 approaching EOL' },
  'nginx:1.22': { eol: '2024-05-01', severity: 'high', reason: 'Nginx 1.22 is no longer maintained' },
  'mongo:4': { eol: '2024-02-01', severity: 'critical', reason: 'MongoDB 4.x is End of Life' },
};

// Common image security checks (no Trivy needed)
function nativeImageAnalysis(imageName, tag) {
  const findings = [];
  const fullName = imageName + ':' + tag;

  // Check EOL status
  for (const [pattern, info] of Object.entries(EOL_IMAGES)) {
    const [pName, pTag] = pattern.split(':');
    if (imageName.endsWith(pName) && tag.startsWith(pTag)) {
      findings.push({
        severity: info.severity,
        cve_id: 'EOL-' + pName.toUpperCase() + '-' + pTag,
        vulnerability_id: 'EOL-' + pName + '-' + pTag,
        pkg_name: pName,
        package: pName,
        installed_version: tag,
        fixed_version: 'Upgrade to latest LTS',
        title: info.reason,
        description: info.reason + '. EOL date: ' + info.eol,
      });
    }
  }

  // Check for :latest tag (no version pinning)
  if (tag === 'latest') {
    findings.push({
      severity: 'medium',
      cve_id: 'BEST-PRACTICE-001',
      vulnerability_id: 'BP-001',
      pkg_name: imageName,
      package: imageName,
      installed_version: 'latest',
      fixed_version: 'Pin to specific version',
      title: 'Image uses :latest tag — no version pinning',
      description: 'Using :latest means builds are not reproducible and may pull vulnerable versions unexpectedly. Pin to a specific version tag.',
    });
  }

  // Check for non-slim/non-alpine images (larger attack surface)
  if (!tag.includes('slim') && !tag.includes('alpine') && !tag.includes('minimal') && !tag.includes('distroless')) {
    const knownFullImages = ['node', 'python', 'ruby', 'golang', 'rust', 'php', 'java', 'openjdk'];
    if (knownFullImages.some(n => imageName.endsWith(n))) {
      findings.push({
        severity: 'low',
        cve_id: 'BEST-PRACTICE-002',
        vulnerability_id: 'BP-002',
        pkg_name: imageName,
        package: imageName,
        installed_version: tag,
        fixed_version: tag + '-slim or ' + tag + '-alpine',
        title: 'Full image used — consider slim/alpine variant for smaller attack surface',
        description: 'Full base images contain many packages not needed at runtime, increasing the attack surface. Use -slim or -alpine variants.',
      });
    }
  }

  // Check for root user (common default)
  findings.push({
    severity: 'medium',
    cve_id: 'CIS-4.1',
    vulnerability_id: 'CIS-4.1',
    pkg_name: 'container-config',
    package: 'container-config',
    installed_version: 'default (root)',
    fixed_version: 'USER nonroot in Dockerfile',
    title: 'Container likely runs as root (default)',
    description: 'Most Docker images run as root by default. Add a USER directive in your Dockerfile to run as a non-root user. CIS Docker Benchmark 4.1.',
  });

  return findings;
}

module.exports = function (app, ctx) {
  const { requireAuth, requireAdmin, requireRole, execCommand, askAI } = ctx;

  // GET /api/docker/status
  app.get('/api/docker/status', requireAuth, async (req, res) => {
    try {
      const result = await dockerRequest('GET', '/_ping');
      const version = await dockerRequest('GET', '/version');
      res.json({
        available: result.status === 200,
        version: version.data?.Version || 'unknown',
        apiVersion: version.data?.ApiVersion || 'unknown',
        os: (version.data?.Os || '') + '/' + (version.data?.Arch || ''),
        platform: process.platform,
      });
    } catch (e) {
      res.json({ available: false, error: e.message, platform: process.platform });
    }
  });

  // GET /api/docker/containers
  app.get('/api/docker/containers', requireAuth, async (req, res) => {
    try {
      const all = req.query.all !== 'false';
      const result = await dockerRequest('GET', `/containers/json?all=${all}`);
      const containers = Array.isArray(result.data) ? result.data.map(c => ({
        id: (c.Id || '').substring(0, 12),
        name: (c.Names || ['/unknown'])[0].replace(/^\//, ''),
        image: c.Image,
        state: c.State,
        status: c.Status,
        created: c.Created,
        ports: (c.Ports || []).map(p => ({
          private: p.PrivatePort,
          public: p.PublicPort,
          type: p.Type,
        })),
      })) : [];
      res.json({ containers });
    } catch (e) {
      res.json({ containers: [], error: e.message });
    }
  });

  // GET /api/docker/containers/:id/inspect
  app.get('/api/docker/containers/:id/inspect', requireAuth, async (req, res) => {
    try {
      const result = await dockerRequest('GET', `/containers/${req.params.id}/json`);
      if (result.status === 404) return res.status(404).json({ error: 'Container not found' });
      res.json(result.data);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ════════════════════════════════════════════════════════════════════════
  // IMAGE WATCHLIST — user-managed list of images to monitor
  // ════════════════════════════════════════════════════════════════════════

  // GET /api/docker/images — merge local Docker + watchlist
  app.get('/api/docker/images', requireAuth, async (req, res) => {
    const images = [];

    // 1. Try local Docker images
    try {
      const result = await dockerRequest('GET', '/images/json');
      if (Array.isArray(result.data)) {
        for (const i of result.data) {
          const tags = i.RepoTags || [];
          for (const tag of tags) {
            if (tag === '<none>:<none>') continue;
            const parts = tag.split(':');
            images.push({
              id: (i.Id || '').replace('sha256:', '').substring(0, 12),
              name: parts[0],
              tag: parts[1] || 'latest',
              source: 'docker',
              sizeMB: Math.round((i.Size || 0) / 1048576),
              created: i.Created,
            });
          }
        }
      }
    } catch {}

    // 2. Add watchlist images (user-added)
    const watchlist = readJSON(IMAGES_PATH, []);
    for (const w of watchlist) {
      // Don't duplicate if already from Docker
      const exists = images.some(i => i.name === w.name && i.tag === w.tag);
      if (!exists) {
        images.push({
          id: w.id,
          name: w.name,
          tag: w.tag,
          source: 'manual',
          addedAt: w.addedAt,
          lastScanAt: w.lastScanAt || null,
          findingsCount: w.findingsCount != null ? w.findingsCount : null,
        });
      }
    }

    res.json({ images });
  });

  // POST /api/docker/images — add image to watchlist
  app.post('/api/docker/images', requireRole('analyst'), (req, res) => {
    try {
      const { image } = req.body;
      if (!image) return res.status(400).json({ error: 'image required' });

      // Parse image:tag
      const parts = image.split(':');
      const name = parts[0].trim();
      const tag = (parts[1] || 'latest').trim();

      if (!name) return res.status(400).json({ error: 'Invalid image name' });

      const watchlist = readJSON(IMAGES_PATH, []);
      const exists = watchlist.some(w => w.name === name && w.tag === tag);
      if (exists) return res.status(409).json({ error: 'Image already in watchlist' });

      const entry = {
        id: crypto.randomUUID(),
        name,
        tag,
        addedAt: new Date().toISOString(),
        addedBy: req.user ? req.user.username : 'unknown',
        lastScanAt: null,
        findingsCount: null,
      };
      watchlist.push(entry);
      writeJSON(IMAGES_PATH, watchlist);

      res.json(entry);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // DELETE /api/docker/images/:image — remove from watchlist
  app.delete('/api/docker/images/:image', requireRole('analyst'), (req, res) => {
    try {
      const imageParam = decodeURIComponent(req.params.image);
      const parts = imageParam.split(':');
      const name = parts[0];
      const tag = parts[1] || 'latest';

      let watchlist = readJSON(IMAGES_PATH, []);
      const before = watchlist.length;
      watchlist = watchlist.filter(w => !(w.name === name && w.tag === tag));
      if (watchlist.length === before) return res.status(404).json({ error: 'Image not in watchlist' });

      writeJSON(IMAGES_PATH, watchlist);
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ════════════════════════════════════════════════════════════════════════
  // CONTAINER SCAN — enhanced with native fallback + AI analysis
  // Called from scan-api.js POST /api/scan/container, also usable directly
  // ════════════════════════════════════════════════════════════════════════

  // Expose native scan for scan-api.js
  ctx.nativeContainerScan = async function(imageName) {
    const parts = imageName.split(':');
    const name = parts[0];
    const tag = parts[1] || 'latest';

    // Native analysis (EOL checks, best practices, CIS benchmarks)
    const findings = nativeImageAnalysis(name, tag);

    // Fetch Docker Hub metadata
    const hubInfo = await fetchDockerHubInfo(name);
    let metadata = null;
    if (hubInfo && hubInfo.name) {
      metadata = {
        description: hubInfo.description || '',
        starCount: hubInfo.star_count || 0,
        pullCount: hubInfo.pull_count || 0,
        lastUpdated: hubInfo.last_updated || null,
        isOfficial: hubInfo.is_official || false,
      };

      // Check if image is very old (not updated in 6+ months)
      if (hubInfo.last_updated) {
        const lastUpdate = new Date(hubInfo.last_updated);
        const monthsAgo = (Date.now() - lastUpdate.getTime()) / (30 * 24 * 3600 * 1000);
        if (monthsAgo > 6) {
          findings.push({
            severity: 'medium',
            cve_id: 'STALE-IMAGE',
            vulnerability_id: 'STALE-IMAGE',
            pkg_name: name,
            package: name,
            installed_version: tag,
            fixed_version: 'Update to latest version',
            title: `Image not updated in ${Math.round(monthsAgo)} months — may contain unpatched vulnerabilities`,
            description: `Last Docker Hub update: ${hubInfo.last_updated}. Stale images accumulate CVEs over time.`,
          });
        }
      }
    }

    // AI-powered analysis
    let analysis = null;
    try {
      const findingSummary = findings.map(f => `[${f.severity}] ${f.title}`).join('\n');
      const prompt = `You are a container security expert. Analyze this Docker image and its findings.

Image: ${imageName}
${metadata ? `Docker Hub: ${metadata.pullCount} pulls, ${metadata.starCount} stars, official: ${metadata.isOfficial}, last updated: ${metadata.lastUpdated}` : ''}

Findings:
${findingSummary || 'No specific findings from static analysis.'}

Provide a brief security assessment (3-5 sentences): overall risk level, key concerns, and specific recommendations for hardening this container. Be concise and actionable.`;
      analysis = await askAI(prompt, { timeout: 20000 });
    } catch {}

    // Update watchlist with scan results
    const watchlist = readJSON(IMAGES_PATH, []);
    const entry = watchlist.find(w => w.name === name && w.tag === tag);
    if (entry) {
      entry.lastScanAt = new Date().toISOString();
      entry.findingsCount = findings.length;
      writeJSON(IMAGES_PATH, watchlist);
    }

    return { findings, metadata, analysis };
  };

  // POST /api/docker/scan/:id — scan container by Docker ID
  app.post('/api/docker/scan/:id', requireRole('analyst'), async (req, res) => {
    try {
      const inspect = await dockerRequest('GET', `/containers/${req.params.id}/json`);
      if (inspect.status === 404) return res.status(404).json({ error: 'Container not found' });

      const imageName = inspect.data?.Config?.Image || inspect.data?.Image;
      if (!imageName) return res.status(400).json({ error: 'Could not determine image name' });

      // Try trivy first
      try {
        const result = await execCommand(
          `trivy image --format json --severity CRITICAL,HIGH,MEDIUM ${imageName} 2>&1`,
          { timeout: 300000 }
        );
        let findings = [];
        try {
          const report = JSON.parse(result.stdout);
          for (const r of (report.Results || [])) {
            for (const vuln of (r.Vulnerabilities || [])) {
              findings.push({
                cveId: vuln.VulnerabilityID,
                severity: (vuln.Severity || 'MEDIUM').toLowerCase(),
                package: vuln.PkgName,
                installedVersion: vuln.InstalledVersion,
                fixedVersion: vuln.FixedVersion || null,
                title: vuln.Title || vuln.VulnerabilityID,
              });
            }
          }
        } catch {}
        return res.json({ image: imageName, findings, total: findings.length, scanner: 'trivy' });
      } catch {}

      // Fallback to native
      const native = await ctx.nativeContainerScan(imageName);
      res.json({ image: imageName, vulnerabilities: native.findings, total: native.findings.length, scanner: 'native', analysis: native.analysis });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
};
