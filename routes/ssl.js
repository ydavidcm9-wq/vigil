/**
 * SSL Routes — SSL/TLS certificate monitoring and analysis
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA = path.join(__dirname, '..', 'data');
const MONITORS_PATH = path.join(DATA, 'ssl-monitors.json');

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
  const { requireAuth, requireRole, requireAdmin, execCommand, askAI } = ctx;

  // POST /api/ssl/check — check domain SSL (uses Node.js TLS with openssl fallback)
  app.post('/api/ssl/check', requireAuth, async (req, res) => {
    try {
      const { domain } = req.body;
      if (!domain) return res.status(400).json({ error: 'domain required' });
      if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
        return res.status(400).json({ error: 'Invalid domain format' });
      }

      // Use Node.js TLS (works everywhere — no openssl CLI needed)
      const tls = require('tls');
      const result = await new Promise((resolve) => {
        const r = { domain, checked: true };
        const socket = tls.connect({ host: domain, port: 443, servername: domain, rejectUnauthorized: false }, () => {
          const cert = socket.getPeerCertificate(true);
          socket.end();
          if (!cert || !cert.subject) {
            r.error = 'No certificate returned';
            r.grade = 'F';
            return resolve(r);
          }
          const now = new Date();
          const validFrom = new Date(cert.valid_from);
          const validTo = new Date(cert.valid_to);
          const daysLeft = Math.ceil((validTo - now) / 86400000);

          r.validFrom = validFrom.toISOString();
          r.expiry = validTo.toISOString();
          r.daysLeft = daysLeft;
          r.days_until_expiry = daysLeft;
          r.expired = daysLeft < 0;
          r.subject = cert.subject.CN || Object.values(cert.subject).join(', ');
          r.issuer = cert.issuer ? (cert.issuer.O || cert.issuer.CN || Object.values(cert.issuer).join(', ')) : 'unknown';
          r.san = cert.subjectaltname
            ? cert.subjectaltname.split(',').map(s => s.trim().replace('DNS:', '')).filter(Boolean) : [];
          r.serialNumber = cert.serialNumber || null;
          r.fingerprint = cert.fingerprint256 || cert.fingerprint || null;

          const proto = socket.getProtocol ? socket.getProtocol() : null;
          const cipher = socket.getCipher ? socket.getCipher() : null;
          r.protocol = proto || null;
          r.cipher = cipher ? cipher.name : null;

          let grade = 'A';
          if (r.expired) grade = 'F';
          else if (daysLeft < 7) grade = 'D';
          else if (daysLeft < 30) grade = 'C';
          else if (daysLeft < 90) grade = 'B';
          r.grade = grade;
          resolve(r);
        });
        socket.setTimeout(10000);
        socket.on('timeout', () => { socket.destroy(); resolve({ ...r, error: 'Connection timed out', grade: 'F' }); });
        socket.on('error', (e) => { resolve({ ...r, error: e.message, grade: 'F' }); });
      });

      // Save to ssl-domains list for the monitor view
      const SSL_DOMAINS_PATH = path.join(DATA, 'ssl-domains.json');
      const domains = readJSON(SSL_DOMAINS_PATH, []);
      const existing = domains.findIndex(d => d.domain === domain);
      if (existing >= 0) {
        domains[existing] = { ...domains[existing], ...result, lastCheck: new Date().toISOString() };
      } else {
        domains.push({ ...result, lastCheck: new Date().toISOString() });
      }
      writeJSON(SSL_DOMAINS_PATH, domains);

      // AI analysis
      try {
        const prompt = `Analyze this SSL/TLS certificate check for ${domain} in 3-4 sentences. No markdown.

Grade: ${result.grade}
Expiry: ${result.expiry || 'unknown'} (${result.daysLeft !== undefined ? result.daysLeft + ' days left' : 'unknown'})
Issuer: ${result.issuer || 'unknown'}
Protocol: ${result.protocol || 'unknown'}
Cipher: ${result.cipher || 'unknown'}
SANs: ${result.san ? result.san.join(', ') : 'none'}

Assess the SSL configuration, highlight any issues, and recommend improvements.`;

        result.analysis = await askAI(prompt, { timeout: 15000 }) || null;
      } catch {}

      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/ssl/monitors — monitored domains (reads from ssl-domains.json where check results are saved)
  app.get('/api/ssl/monitors', requireAuth, (req, res) => {
    const SSL_DOMAINS_PATH = path.join(DATA, 'ssl-domains.json');
    const domains = readJSON(SSL_DOMAINS_PATH, []);
    res.json({ domains });
  });

  // POST /api/ssl/monitors — add domain to monitor
  app.post('/api/ssl/monitors', requireRole('analyst'), (req, res) => {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'domain required' });
    if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
      return res.status(400).json({ error: 'Invalid domain format' });
    }

    const monitors = readJSON(MONITORS_PATH, []);
    if (monitors.find(m => m.domain === domain)) {
      return res.status(409).json({ error: 'Domain already monitored' });
    }

    monitors.push({
      domain: escapeHtml(domain),
      addedAt: new Date().toISOString(),
      addedBy: req.user ? req.user.user : 'unknown',
      lastCheck: null,
      lastGrade: null,
      lastDaysLeft: null,
    });
    writeJSON(MONITORS_PATH, monitors);
    res.json({ success: true });
  });

  // DELETE /api/ssl/monitors/:domain
  app.delete('/api/ssl/monitors/:domain', requireRole('analyst'), (req, res) => {
    let monitors = readJSON(MONITORS_PATH, []);
    const before = monitors.length;
    monitors = monitors.filter(m => m.domain !== req.params.domain);
    if (monitors.length === before) return res.status(404).json({ error: 'Monitor not found' });
    writeJSON(MONITORS_PATH, monitors);
    res.json({ success: true });
  });
};
