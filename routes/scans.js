/**
 * Scans Routes — Vulnerability scanning (nmap, nuclei, trivy, ssl)
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA = path.join(__dirname, '..', 'data');
const SCANS_PATH = path.join(DATA, 'scans.json');

function readJSON(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return fallback; }
}
function writeJSON(p, data) {
  // Atomic write: write to temp, then rename (prevents corruption on concurrent access)
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + '.tmp.' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, p);
}

function escapeHtml(s) { return String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }

module.exports = function (app, ctx) {
  const { requireAuth, requireAdmin, requireRole, execCommand } = ctx;

  // ── Input Validators ─────────────────────────────────────────────────

  // Strict target validation — IP, CIDR, or hostname only
  function isValidTarget(target) {
    if (!target || typeof target !== 'string' || target.length > 253) return false;
    // IPv4: 1.2.3.4
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(target)) {
      return target.split('.').every(p => { const n = parseInt(p); return n >= 0 && n <= 255; });
    }
    // IPv4 CIDR: 1.2.3.4/24
    if (/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(target)) {
      const [ip, mask] = target.split('/');
      return ip.split('.').every(p => { const n = parseInt(p); return n >= 0 && n <= 255; })
        && parseInt(mask) >= 0 && parseInt(mask) <= 32;
    }
    // IPv6 (basic)
    if (/^[a-fA-F0-9:]+$/.test(target) && target.includes(':')) return true;
    // Hostname: letters, digits, hyphens, dots — no consecutive dots, no leading/trailing hyphen
    if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(target)) return true;
    return false;
  }

  // Validate port range: "80", "1-1024", "22,80,443"
  function isValidPorts(ports) {
    if (!ports || typeof ports !== 'string') return false;
    return /^[\d,\-]+$/.test(ports) && ports.length <= 100;
  }

  // Whitelist of allowed nmap flags
  const ALLOWED_NMAP_FLAGS = new Set(['-sV', '-sC', '-sS', '-sT', '-sU', '-O', '-A', '-Pn', '-n', '--open', '-T0', '-T1', '-T2', '-T3', '-T4', '-T5']);

  function sanitizeNmapFlags(flags) {
    if (!flags || typeof flags !== 'string') return '-sV';
    return flags.split(/\s+/).filter(f => ALLOWED_NMAP_FLAGS.has(f)).join(' ') || '-sV';
  }

  // Validate nuclei severity
  const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

  function isValidSeverity(sev) {
    if (!sev || typeof sev !== 'string') return false;
    return sev.split(',').every(s => VALID_SEVERITIES.has(s.trim().toLowerCase()));
  }

  // Run scan based on type
  async function executeScan(scan) {
    const { type, target, options } = scan;
    scan.status = 'running';
    scan.startedAt = new Date().toISOString();

    try {
      let findings = [];
      let rawOutput = '';

      switch (type) {
        case 'nmap': {
          const ports = isValidPorts(options && options.ports) ? options.ports : '1-1000';
          const flags = sanitizeNmapFlags(options && options.flags);
          const result = await ctx.execFileSafe('nmap', [...flags.split(/\s+/).filter(Boolean), '-p', ports, '--open', '-oX', '-', target], { timeout: 120000 });
          rawOutput = result.stdout || result.stderr || '';

          // Parse nmap XML-ish output for open ports
          const portMatches = rawOutput.matchAll(/(\d+)\/(\w+)\s+open\s+(\S+)\s*(.*)/g);
          for (const m of portMatches) {
            findings.push({
              id: crypto.randomUUID(),
              scanId: scan.id,
              type: 'open_port',
              title: `Open port ${m[1]}/${m[2]} — ${m[3]}`,
              severity: parseInt(m[1]) < 1024 ? 'medium' : 'low',
              details: m[4] ? m[4].trim() : '',
              port: parseInt(m[1]),
              protocol: m[2],
              service: m[3],
              status: 'open',
            });
          }

          // Fallback: parse "Nmap done" style text
          if (findings.length === 0 && rawOutput.includes('PORT')) {
            const lines = rawOutput.split('\n');
            for (const line of lines) {
              const match = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)/);
              if (match) {
                findings.push({
                  id: crypto.randomUUID(),
                  scanId: scan.id,
                  type: 'open_port',
                  title: `Open port ${match[1]}/${match[2]} — ${match[3]}`,
                  severity: 'low',
                  details: line.trim(),
                  port: parseInt(match[1]),
                  protocol: match[2],
                  service: match[3],
                  status: 'open',
                });
              }
            }
          }
          break;
        }

        case 'nuclei': {
          const severity = isValidSeverity(options && options.severity) ? options.severity : 'critical,high,medium';
          const args = ['-u', target, '-severity', severity, '-json', '-silent'];
          // Templates: only allow alphanumeric, hyphens, slashes (no shell chars)
          if (options && options.templates && /^[a-zA-Z0-9\/_-]+$/.test(options.templates)) {
            args.push('-t', options.templates);
          }
          const result = await ctx.execFileSafe('nuclei', args, { timeout: 300000 });
          rawOutput = result.stdout || '';

          // Parse JSON lines
          for (const line of rawOutput.split('\n').filter(Boolean)) {
            try {
              const entry = JSON.parse(line);
              findings.push({
                id: crypto.randomUUID(),
                scanId: scan.id,
                type: 'vulnerability',
                title: entry['template-id'] || entry.info?.name || 'Unknown',
                severity: (entry.info?.severity || 'medium').toLowerCase(),
                details: entry.info?.description || '',
                url: entry.matched || entry.host || target,
                reference: entry.info?.reference ? (Array.isArray(entry.info.reference) ? entry.info.reference.join(', ') : entry.info.reference) : '',
                tags: entry.info?.tags || [],
                status: 'open',
              });
            } catch {}
          }
          break;
        }

        case 'trivy': {
          const result = await ctx.execFileSafe('trivy', ['fs', '--format', 'json', '--severity', 'CRITICAL,HIGH,MEDIUM', target], { timeout: 180000 });
          rawOutput = result.stdout || '';

          try {
            const report = JSON.parse(rawOutput);
            const results = report.Results || [];
            for (const r of results) {
              for (const vuln of (r.Vulnerabilities || [])) {
                findings.push({
                  id: crypto.randomUUID(),
                  scanId: scan.id,
                  type: 'cve',
                  title: `${vuln.VulnerabilityID}: ${vuln.PkgName} ${vuln.InstalledVersion}`,
                  severity: (vuln.Severity || 'medium').toLowerCase(),
                  details: vuln.Description || '',
                  cveId: vuln.VulnerabilityID,
                  package: vuln.PkgName,
                  installedVersion: vuln.InstalledVersion,
                  fixedVersion: vuln.FixedVersion || null,
                  reference: vuln.PrimaryURL || '',
                  status: 'open',
                });
              }
            }
          } catch {}
          break;
        }

        case 'ssl': {
          // SSL check requires pipe — target already strictly validated by isValidTarget
          const safeTarget = target.replace(/[^a-zA-Z0-9.\-:]/g, '');
          const cmd = `echo | openssl s_client -servername ${safeTarget} -connect ${safeTarget}:443 2>/dev/null | openssl x509 -noout -text -dates -issuer -subject 2>&1`;
          const result = await execCommand(cmd, { timeout: 30000 });
          rawOutput = result.stdout || result.stderr || '';

          // Parse certificate details
          const notAfter = rawOutput.match(/notAfter=(.+)/);
          const issuer = rawOutput.match(/issuer=(.+)/);
          const subject = rawOutput.match(/subject=(.+)/);

          if (notAfter) {
            const expiry = new Date(notAfter[1].trim());
            const daysLeft = Math.ceil((expiry - Date.now()) / 86400000);

            findings.push({
              id: crypto.randomUUID(),
              scanId: scan.id,
              type: 'ssl_cert',
              title: `SSL certificate for ${target}`,
              severity: daysLeft < 7 ? 'critical' : daysLeft < 30 ? 'high' : daysLeft < 90 ? 'medium' : 'low',
              details: `Expires: ${expiry.toISOString().split('T')[0]} (${daysLeft} days). Issuer: ${issuer ? issuer[1].trim() : 'unknown'}`,
              expiry: expiry.toISOString(),
              daysLeft,
              issuer: issuer ? issuer[1].trim() : '',
              subject: subject ? subject[1].trim() : '',
              status: 'open',
            });
          } else {
            findings.push({
              id: crypto.randomUUID(),
              scanId: scan.id,
              type: 'ssl_error',
              title: `SSL check failed for ${target}`,
              severity: 'high',
              details: 'Could not retrieve SSL certificate. The host may not support HTTPS.',
              status: 'open',
            });
          }
          break;
        }

        default:
          throw new Error('Unknown scan type: ' + type);
      }

      scan.findings = findings;
      scan.findingsCount = findings.length;
      scan.status = 'completed';
      scan.completedAt = new Date().toISOString();
      scan.duration = Date.now() - new Date(scan.startedAt).getTime();
      scan.rawOutputLength = rawOutput.length;

    } catch (e) {
      scan.status = 'failed';
      scan.error = e.message;
      scan.completedAt = new Date().toISOString();
    }

    return scan;
  }

  // GET /api/scans
  app.get('/api/scans', requireAuth, (req, res) => {
    const scans = readJSON(SCANS_PATH, []);
    // Return without raw output to keep payload small
    const list = scans.map(s => ({
      id: s.id, type: s.type, target: s.target, status: s.status,
      findingsCount: s.findingsCount || 0,
      createdAt: s.createdAt, completedAt: s.completedAt,
      duration: s.duration || null, error: s.error || null,
    }));
    res.json({ scans: list.reverse() });
  });

  // POST /api/scans — create and run scan
  app.post('/api/scans', requireRole('analyst'), async (req, res) => {
    const { type, target, options } = req.body;
    if (!type || !target) return res.status(400).json({ error: 'type and target required' });
    if (!['nmap', 'nuclei', 'trivy', 'ssl'].includes(type)) return res.status(400).json({ error: 'Invalid scan type. Use: nmap, nuclei, trivy, ssl' });
    if (!isValidTarget(target)) return res.status(400).json({ error: 'Invalid target format' });

    const scan = {
      id: crypto.randomUUID(),
      type,
      target: escapeHtml(target),
      options: options || {},
      status: 'pending',
      findings: [],
      findingsCount: 0,
      createdAt: new Date().toISOString(),
      createdBy: req.user ? req.user.user : 'unknown',
    };

    const scans = readJSON(SCANS_PATH, []);
    scans.push(scan);
    writeJSON(SCANS_PATH, scans);

    // Run scan in background
    executeScan(scan).then(completed => {
      const allScans = readJSON(SCANS_PATH, []);
      const idx = allScans.findIndex(s => s.id === completed.id);
      if (idx >= 0) allScans[idx] = completed;
      writeJSON(SCANS_PATH, allScans);

      // Notify via socket
      if (ctx.io) ctx.io.emit('scan_complete', { id: completed.id, status: completed.status, findingsCount: completed.findingsCount });
    });

    res.json({ scan: { id: scan.id, type: scan.type, target: scan.target, status: scan.status } });
  });

  // GET /api/scans/:id
  app.get('/api/scans/:id', requireAuth, (req, res) => {
    const scans = readJSON(SCANS_PATH, []);
    const scan = scans.find(s => s.id === req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    res.json(scan);
  });

  // POST /api/scans/:id/rerun
  app.post('/api/scans/:id/rerun', requireRole('analyst'), async (req, res) => {
    const scans = readJSON(SCANS_PATH, []);
    const original = scans.find(s => s.id === req.params.id);
    if (!original) return res.status(404).json({ error: 'Scan not found' });

    const newScan = {
      id: crypto.randomUUID(),
      type: original.type,
      target: original.target,
      options: original.options || {},
      status: 'pending',
      findings: [],
      findingsCount: 0,
      createdAt: new Date().toISOString(),
      createdBy: req.user ? req.user.user : 'unknown',
      rerunOf: original.id,
    };

    scans.push(newScan);
    writeJSON(SCANS_PATH, scans);

    executeScan(newScan).then(completed => {
      const allScans = readJSON(SCANS_PATH, []);
      const idx = allScans.findIndex(s => s.id === completed.id);
      if (idx >= 0) allScans[idx] = completed;
      writeJSON(SCANS_PATH, allScans);
      if (ctx.io) ctx.io.emit('scan_complete', { id: completed.id, status: completed.status, findingsCount: completed.findingsCount });
    });

    res.json({ scan: { id: newScan.id, type: newScan.type, target: newScan.target, status: newScan.status } });
  });

  // DELETE /api/scans/:id
  app.delete('/api/scans/:id', requireAdmin, (req, res) => {
    let scans = readJSON(SCANS_PATH, []);
    const idx = scans.findIndex(s => s.id === req.params.id);
    if (idx < 0) return res.status(404).json({ error: 'Scan not found' });
    scans.splice(idx, 1);
    writeJSON(SCANS_PATH, scans);
    res.json({ success: true });
  });
};
