/**
 * Findings Routes — Vulnerability findings across scans
 */
const fs = require('fs');
const path = require('path');

const DATA = path.join(__dirname, '..', 'data');
const SCANS_PATH = path.join(DATA, 'scans.json');

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
  const { requireAuth, requireRole, askAI } = ctx;

  // Collect all findings from all scans
  function getAllFindings() {
    const scans = readJSON(SCANS_PATH, []);
    const findings = [];
    for (const scan of scans) {
      if (scan.findings && Array.isArray(scan.findings)) {
        for (const f of scan.findings) {
          findings.push({
            ...f,
            scanType: scan.type,
            scanTarget: scan.target,
            scanDate: scan.completedAt || scan.createdAt,
          });
        }
      }
    }
    return findings;
  }

  // GET /api/findings
  app.get('/api/findings', requireAuth, (req, res) => {
    try {
      let findings = getAllFindings();

      // Filter by severity
      if (req.query.severity) {
        findings = findings.filter(f => f.severity === req.query.severity);
      }
      // Filter by status
      if (req.query.status) {
        findings = findings.filter(f => f.status === req.query.status);
      }
      // Filter by type
      if (req.query.type) {
        findings = findings.filter(f => f.type === req.query.type);
      }

      // Sort: critical first, then high, medium, low
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      findings.sort((a, b) => (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5));

      res.json({ findings, total: findings.length });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/findings/stats — MUST be before :id route
  app.get('/api/findings/stats', requireAuth, (req, res) => {
    try {
      const findings = getAllFindings();
      const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      const byStatus = { open: 0, investigating: 0, resolved: 0, false_positive: 0 };
      const byType = {};
      for (const f of findings) {
        bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
        byStatus[f.status] = (byStatus[f.status] || 0) + 1;
        byType[f.type] = (byType[f.type] || 0) + 1;
      }
      res.json({ total: findings.length, bySeverity, byStatus, byType });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/findings/:id
  app.get('/api/findings/:id', requireAuth, (req, res) => {
    const findings = getAllFindings();
    const finding = findings.find(f => f.id === req.params.id);
    if (!finding) return res.status(404).json({ error: 'Finding not found' });
    res.json(finding);
  });

  // POST /api/findings/:id/analyze — AI analysis
  app.post('/api/findings/:id/analyze', requireAuth, async (req, res) => {
    try {
      const findings = getAllFindings();
      const finding = findings.find(f => f.id === req.params.id);
      if (!finding) return res.status(404).json({ error: 'Finding not found' });

      const prompt = `You are a senior security engineer. Analyze this vulnerability finding and provide actionable guidance.

Finding:
- Type: ${finding.type}
- Title: ${finding.title}
- Severity: ${finding.severity}
- Details: ${finding.details || 'None'}
- Target: ${finding.scanTarget || 'Unknown'}
${finding.cveId ? '- CVE: ' + finding.cveId : ''}
${finding.package ? '- Package: ' + finding.package + ' ' + (finding.installedVersion || '') : ''}
${finding.fixedVersion ? '- Fix available: ' + finding.fixedVersion : ''}

Provide a response with:
1. Root Cause: Why this vulnerability exists (1-2 sentences)
2. Impact: What an attacker could do (1-2 sentences)
3. Remediation Steps: Specific, actionable steps to fix this (numbered list, 3-5 steps)
4. Risk if Unpatched: What happens if this is ignored (1 sentence)

Keep it concise and actionable. No markdown headers.`;

      const analysis = await askAI(prompt, { timeout: 25000 });

      res.json({
        findingId: finding.id,
        analysis: analysis || 'AI analysis unavailable. Review the finding details manually.',
        analyzedAt: new Date().toISOString(),
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // PATCH /api/findings/:id — update status
  app.patch('/api/findings/:id', requireRole('analyst'), (req, res) => {
    try {
      const { status } = req.body;
      if (!status || !['open', 'investigating', 'resolved', 'false_positive'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status. Use: open, investigating, resolved, false_positive' });
      }

      const scans = readJSON(SCANS_PATH, []);
      let updated = false;

      for (const scan of scans) {
        if (scan.findings && Array.isArray(scan.findings)) {
          const finding = scan.findings.find(f => f.id === req.params.id);
          if (finding) {
            finding.status = status;
            finding.statusUpdatedAt = new Date().toISOString();
            finding.statusUpdatedBy = req.user ? req.user.username : 'unknown';
            updated = true;
            break;
          }
        }
      }

      if (!updated) return res.status(404).json({ error: 'Finding not found' });
      writeJSON(SCANS_PATH, scans);
      res.json({ success: true, status });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

};
