/**
 * Threats Routes — Threat intelligence, local detection, AI triage
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA = path.join(__dirname, '..', 'data');
const THREATS_PATH = path.join(DATA, 'threats.json');

function escapeHtml(s) { return String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }

function readJSON(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return fallback; }
}
function writeJSON(p, data) {
  // Atomic write: temp file + rename
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + '.tmp.' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, p);
}

module.exports = function (app, ctx) {
  const { requireAuth, requireAdmin, execCommand, askAI, askAIJSON } = ctx;

  // Detect local threats (auth.log brute force, suspicious processes)
  async function detectLocalThreats() {
    const detected = [];
    const now = new Date().toISOString();

    // Check auth.log for failed logins
    if (process.platform !== 'win32') {
      try {
        const result = await execCommand(
          "grep -c 'Failed password' /var/log/auth.log 2>/dev/null || journalctl -u sshd --since '24 hours ago' 2>/dev/null | grep -c 'Failed password' || echo 0",
          { timeout: 5000 }
        );
        const count = parseInt(result.stdout.trim()) || 0;
        if (count > 10) {
          detected.push({
            id: crypto.randomUUID(),
            type: 'brute_force',
            title: `SSH brute force detected: ${count} failed login attempts in 24h`,
            severity: count > 100 ? 'critical' : count > 50 ? 'high' : 'medium',
            source: 'auth.log',
            details: `${count} failed SSH password attempts detected`,
            detectedAt: now,
            status: 'active',
          });
        }
      } catch {}

      // Check for suspicious processes (crypto miners, reverse shells)
      try {
        const suspicious = ['xmrig', 'minerd', 'cpuminer', 'cryptonight', 'stratum', 'ncat', 'socat'];
        const result = await execCommand("ps aux 2>/dev/null", { timeout: 5000 });
        const lines = result.stdout.toLowerCase();
        for (const name of suspicious) {
          if (lines.includes(name)) {
            detected.push({
              id: crypto.randomUUID(),
              type: 'malware',
              title: `Suspicious process detected: ${name}`,
              severity: 'critical',
              source: 'process_scan',
              details: `Process matching '${name}' found in running processes`,
              detectedAt: now,
              status: 'active',
            });
          }
        }
      } catch {}

      // Check for unauthorized cron jobs
      try {
        const result = await execCommand("crontab -l 2>/dev/null | grep -v '^#' | grep -c '.' || echo 0", { timeout: 3000 });
        const count = parseInt(result.stdout.trim()) || 0;
        if (count > 0) {
          const cronList = await execCommand("crontab -l 2>/dev/null | grep -v '^#' | head -5", { timeout: 3000 });
          // Look for suspicious cron entries
          const cronText = cronList.stdout.toLowerCase();
          if (cronText.includes('curl') || cronText.includes('wget') || cronText.includes('/tmp/')) {
            detected.push({
              id: crypto.randomUUID(),
              type: 'persistence',
              title: 'Suspicious cron job detected',
              severity: 'high',
              source: 'cron_scan',
              details: `Cron job with network download or /tmp execution detected`,
              detectedAt: now,
              status: 'active',
            });
          }
        }
      } catch {}

      // Check for world-writable files in sensitive directories
      try {
        const result = await execCommand("find /etc /usr/local/bin -perm -002 -type f 2>/dev/null | head -5 | wc -l", { timeout: 5000 });
        const count = parseInt(result.stdout.trim()) || 0;
        if (count > 0) {
          detected.push({
            id: crypto.randomUUID(),
            type: 'misconfiguration',
            title: `${count} world-writable files in sensitive directories`,
            severity: 'medium',
            source: 'file_scan',
            details: `World-writable files found in /etc or /usr/local/bin`,
            detectedAt: now,
            status: 'active',
          });
        }
      } catch {}
    }

    return detected;
  }

  function getRecentThreats() {
    return readJSON(THREATS_PATH, []);
  }

  // Expose for other routes
  ctx.getRecentThreats = getRecentThreats;

  // GET /api/threats
  app.get('/api/threats', requireAuth, async (req, res) => {
    try {
      let threats = readJSON(THREATS_PATH, []);

      // Merge local detections
      const localThreats = await detectLocalThreats();
      if (localThreats.length > 0) {
        const existingIds = new Set(threats.map(t => t.title));
        for (const lt of localThreats) {
          if (!existingIds.has(lt.title)) {
            threats.push(lt);
          }
        }
        // Cap stored threats
        if (threats.length > 500) threats = threats.slice(-500);
        writeJSON(THREATS_PATH, threats);
      }

      // Apply filters
      const severity = req.query.severity;
      const status = req.query.status;
      let filtered = threats;
      if (severity) filtered = filtered.filter(t => t.severity === severity);
      if (status) filtered = filtered.filter(t => t.status === status);

      // Calculate threat level
      const active = threats.filter(t => t.status === 'active');
      const criticalCount = active.filter(t => t.severity === 'critical').length;
      const highCount = active.filter(t => t.severity === 'high').length;
      let level = 'LOW';
      if (criticalCount > 0) level = 'CRITICAL';
      else if (highCount > 2) level = 'HIGH';
      else if (highCount > 0 || active.length > 5) level = 'MEDIUM';

      res.json({ threats: filtered.slice(-100).reverse(), level });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/threats/feed — RSS security feeds
  app.get('/api/threats/feed', requireAuth, async (req, res) => {
    try {
      // Return known CVE sources and threat feeds
      const feeds = [
        { name: 'CISA Known Exploited', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', type: 'government' },
        { name: 'NVD Recent CVEs', url: 'https://nvd.nist.gov/vuln/search', type: 'cve_database' },
        { name: 'Exploit-DB', url: 'https://www.exploit-db.com/', type: 'exploit' },
        { name: 'GitHub Security Advisories', url: 'https://github.com/advisories', type: 'advisory' },
        { name: 'US-CERT Alerts', url: 'https://www.cisa.gov/uscert/ncas/alerts', type: 'government' },
      ];

      // Try to fetch CISA KEV catalog
      let kevEntries = [];
      try {
        const https = require('https');
        const kevData = await new Promise((resolve, reject) => {
          const r = https.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { timeout: 10000 }, (resp) => {
            let d = '';
            resp.on('data', c => d += c);
            resp.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
          });
          r.on('error', reject);
          r.setTimeout(10000, () => { r.destroy(); reject(new Error('timeout')); });
        });
        if (kevData && kevData.vulnerabilities) {
          kevEntries = kevData.vulnerabilities.slice(-20).reverse().map(v => ({
            cveId: v.cveID,
            name: v.vulnerabilityName,
            vendor: v.vendorProject,
            product: v.product,
            dateAdded: v.dateAdded,
            dueDate: v.dueDate,
            description: v.shortDescription,
          }));
        }
      } catch {}

      res.json({ feeds, recentKEV: kevEntries });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/threats/:id/triage — AI triage
  app.post('/api/threats/:id/triage', requireAuth, async (req, res) => {
    try {
      const threats = readJSON(THREATS_PATH, []);
      const threat = threats.find(t => t.id === req.params.id);
      if (!threat) return res.status(404).json({ error: 'Threat not found' });

      const prompt = `You are a senior SOC analyst. Triage this security threat and return a JSON object.

Threat:
- Type: ${threat.type}
- Title: ${threat.title}
- Severity: ${threat.severity}
- Source: ${threat.source}
- Details: ${threat.details || 'No additional details'}

Return ONLY a JSON object with these fields:
{
  "verdict": "true_positive" or "false_positive" or "needs_investigation",
  "confidence": <number 0-100>,
  "reasoning": "<2-3 sentences explaining your analysis>",
  "mitre_technique": "<MITRE ATT&CK technique ID if applicable, e.g. T1110.001, or null>",
  "recommended_action": "<specific action to take>"
}`;

      let triage;
      try {
        triage = await askAIJSON(prompt);
      } catch {
        try {
          const raw = await askAI(prompt, { timeout: 20000 });
          const match = raw.match(/\{[\s\S]*\}/);
          triage = match ? JSON.parse(match[0]) : null;
        } catch {
          triage = null;
        }
      }

      if (!triage) {
        return res.json({
          verdict: 'needs_investigation',
          confidence: 0,
          reasoning: 'AI analysis unavailable. Manual review recommended.',
          mitre_technique: null,
          recommended_action: 'Escalate to security team for manual investigation.',
        });
      }

      // Save triage result on the threat
      threat.triage = triage;
      threat.triagedAt = new Date().toISOString();
      writeJSON(THREATS_PATH, threats);

      res.json(triage);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/threats/level
  app.get('/api/threats/level', requireAuth, (req, res) => {
    const threats = readJSON(THREATS_PATH, []);
    const active = threats.filter(t => t.status === 'active');
    const criticalCount = active.filter(t => t.severity === 'critical').length;
    const highCount = active.filter(t => t.severity === 'high').length;

    let level = 'low';
    if (criticalCount > 0) level = 'critical';
    else if (highCount > 2) level = 'high';
    else if (highCount > 0 || active.length > 5) level = 'medium';

    res.json({
      level,
      active: active.length,
      critical: criticalCount,
      high: highCount,
      medium: active.filter(t => t.severity === 'medium').length,
      low: active.filter(t => t.severity === 'low').length,
    });
  });
};
