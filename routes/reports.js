/**
 * Reports Routes — Security report generation via AI
 * POST /api/reports awaits AI generation before responding.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA = path.join(__dirname, '..', 'data');
const REPORTS_PATH = path.join(DATA, 'reports.json');
const REPORTS_DIR = path.join(DATA, 'reports');

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

function escapeHtml(s) { return String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }

module.exports = function (app, ctx) {
  const { requireAuth, requireRole, requireAdmin, askAI } = ctx;

  fs.mkdirSync(REPORTS_DIR, { recursive: true });

  // Collect context data for reports
  async function gatherReportData() {
    const data = {};

    if (ctx.getPostureScore) {
      try { data.posture = await ctx.getPostureScore(); } catch {}
    }

    const scans = readJSON(path.join(DATA, 'scans.json'), []);
    const allFindings = [];
    for (const s of scans) { if (s.findings) allFindings.push(...s.findings); }
    data.findings = {
      total: allFindings.length,
      open: allFindings.filter(f => f.status !== 'resolved' && f.status !== 'false_positive').length,
      critical: allFindings.filter(f => (f.severity || '').toLowerCase() === 'critical').length,
      high: allFindings.filter(f => (f.severity || '').toLowerCase() === 'high').length,
      medium: allFindings.filter(f => (f.severity || '').toLowerCase() === 'medium').length,
      low: allFindings.filter(f => (f.severity || '').toLowerCase() === 'low').length,
      topFindings: allFindings
        .filter(f => (f.severity || '').toLowerCase() === 'critical' || (f.severity || '').toLowerCase() === 'high')
        .slice(0, 10)
        .map(f => ({ title: f.title || f.name || 'Unnamed', severity: f.severity, type: f.type, status: f.status || 'open' })),
    };

    data.scans = {
      total: scans.length,
      completed: scans.filter(s => s.status === 'completed').length,
      failed: scans.filter(s => s.status === 'failed').length,
      types: [...new Set(scans.map(s => s.type).filter(Boolean))],
    };

    const threats = readJSON(path.join(DATA, 'threats.json'), []);
    data.threats = {
      total: threats.length,
      active: threats.filter(t => t.status === 'active').length,
      critical: threats.filter(t => (t.severity || '').toLowerCase() === 'critical').length,
    };

    const incidents = readJSON(path.join(DATA, 'incidents.json'), []);
    data.incidents = {
      total: incidents.length,
      open: incidents.filter(i => i.status === 'open' || i.status === 'investigating').length,
      closed: incidents.filter(i => i.status === 'closed').length,
    };

    if (ctx.getSystemInfo) {
      try { data.system = ctx.getSystemInfo(); } catch {}
    }

    return data;
  }

  // Build a data-driven report without AI (fallback)
  function buildFallbackReport(type, data, scope) {
    const score = data.posture ? data.posture.score : '--';
    const grade = data.posture ? data.posture.grade : '--';
    const now = new Date().toISOString().split('T')[0];
    const sysLine = data.system ? `System: ${data.system.hostname}, ${data.system.platform}, ${data.system.cpuCount} CPUs, ${data.system.usedMemPct}% memory used` : '';

    const header = `${type.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase())} Report\nGenerated: ${now}\nScope: ${scope}\n${sysLine}\n`;

    const findingsBlock = `\nVULNERABILITY SUMMARY\n` +
      `Total findings: ${data.findings.total}\n` +
      `Open: ${data.findings.open} | Critical: ${data.findings.critical} | High: ${data.findings.high} | Medium: ${data.findings.medium} | Low: ${data.findings.low}\n` +
      (data.findings.topFindings.length > 0
        ? `\nTop Findings:\n${data.findings.topFindings.map(f => `  [${(f.severity || '').toUpperCase()}] ${f.title} (${f.status})`).join('\n')}\n`
        : '\nNo critical or high findings detected.\n');

    const threatsBlock = `\nTHREAT STATUS\n` +
      `Total threats: ${data.threats.total} | Active: ${data.threats.active} | Critical: ${data.threats.critical}\n`;

    const incidentsBlock = `\nINCIDENT STATUS\n` +
      `Total incidents: ${data.incidents.total} | Open: ${data.incidents.open} | Closed: ${data.incidents.closed}\n`;

    const scansBlock = `\nSCAN ACTIVITY\n` +
      `Total scans: ${data.scans.total} | Completed: ${data.scans.completed} | Failed: ${data.scans.failed}\n` +
      `Scan types used: ${data.scans.types.join(', ') || 'None'}\n`;

    const postureBlock = `\nSECURITY POSTURE\n` +
      `Score: ${score}/100 (Grade ${grade})\n`;

    let recommendations = '\nRECOMMENDATIONS\n';
    if (data.findings.critical > 0) recommendations += `- URGENT: Address ${data.findings.critical} critical vulnerabilities immediately\n`;
    if (data.findings.high > 0) recommendations += `- Remediate ${data.findings.high} high-severity findings within 7 days\n`;
    if (data.threats.active > 0) recommendations += `- Investigate and triage ${data.threats.active} active threats\n`;
    if (data.scans.total === 0) recommendations += `- Run initial vulnerability and network scans on all assets\n`;
    if (data.incidents.open > 0) recommendations += `- Resolve ${data.incidents.open} open incidents\n`;
    if (recommendations === '\nRECOMMENDATIONS\n') recommendations += '- Continue regular scanning and monitoring\n- Review security policies quarterly\n';

    return header + postureBlock + findingsBlock + threatsBlock + incidentsBlock + scansBlock + recommendations;
  }

  // GET /api/reports
  app.get('/api/reports', requireAuth, (req, res) => {
    const reports = readJSON(REPORTS_PATH, []);
    res.json({
      reports: reports.map(r => ({
        id: r.id, type: r.type, title: r.title, scope: r.scope,
        status: r.status,
        created_at: r.createdAt || r.created_at,
        createdAt: r.createdAt,
        createdBy: r.createdBy,
      })).reverse(),
    });
  });

  // POST /api/reports — generate report (synchronous, awaits AI)
  app.post('/api/reports', requireRole('analyst'), async (req, res) => {
    try {
      const { type, scope } = req.body;
      if (!type) return res.status(400).json({ error: 'type required' });

      // Accept all frontend type values
      const validTypes = ['security-assessment', 'security-audit', 'vulnerability', 'compliance', 'pentest', 'incident', 'executive'];
      if (!validTypes.includes(type)) {
        return res.status(400).json({ error: 'Invalid type. Use: ' + validTypes.join(', ') });
      }

      const report = {
        id: crypto.randomUUID(),
        type,
        title: `${type.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase())} Report`,
        scope: escapeHtml(scope || 'Full system'),
        status: 'generating',
        createdAt: new Date().toISOString(),
        createdBy: req.user ? req.user.user : 'unknown',
      };

      // Gather real data
      const data = await gatherReportData();

      // Map type to AI prompt
      const promptKey = type === 'security-assessment' ? 'security-audit' : type;
      const prompts = {
        'security-audit': `Generate a comprehensive security audit report for a server/application.

Security Data:
- Posture Score: ${data.posture ? data.posture.score + '/100 (Grade ' + data.posture.grade + ')' : 'Not calculated'}
- Open Vulnerabilities: ${data.findings.open} (${data.findings.critical} critical, ${data.findings.high} high)
- Active Threats: ${data.threats.active}
- Open Incidents: ${data.incidents.open}
- Scans Completed: ${data.scans.completed}
${data.system ? `- System: ${data.system.hostname}, ${data.system.platform}, ${data.system.cpuCount} cores, ${data.system.usedMemPct}% memory` : ''}

Top Findings:
${data.findings.topFindings.map(f => `- [${(f.severity || '').toUpperCase()}] ${f.title}`).join('\n') || 'None'}

Write a professional security audit report with sections: Executive Summary, Scope, Methodology, Findings, Risk Assessment, Recommendations, Conclusion. Be specific and actionable.`,

        'vulnerability': `Generate a vulnerability assessment report.

Vulnerability Data:
- Total Findings: ${data.findings.total}
- Critical: ${data.findings.critical}, High: ${data.findings.high}, Medium: ${data.findings.medium}, Low: ${data.findings.low}
- Open: ${data.findings.open}
- Scan Types Used: ${data.scans.types.join(', ') || 'None'}

Top Findings:
${data.findings.topFindings.map(f => `- [${(f.severity || '').toUpperCase()}] ${f.title} (${f.type || 'unknown'}) — ${f.status}`).join('\n') || 'None'}

Write a vulnerability assessment report with: Executive Summary, Scope, Findings by Severity, Remediation Priorities, Risk Matrix, Recommendations.`,

        'compliance': `Generate a compliance status report.

Security Posture: ${data.posture ? data.posture.score + '/100' : 'Not calculated'}
Findings: ${data.findings.total} total, ${data.findings.open} open
Threats: ${data.threats.active} active
Incidents: ${data.incidents.open} open

Write a compliance readiness report covering SOC 2, ISO 27001, and NIST 800-53 frameworks. Include: Current State, Gap Analysis, Remediation Roadmap, Timeline Estimate.`,

        'pentest': `Generate a penetration test summary report.

Test Data:
- Vulnerabilities Found: ${data.findings.total} (${data.findings.critical} critical, ${data.findings.high} high, ${data.findings.medium} medium, ${data.findings.low} low)
- Scan Types Used: ${data.scans.types.join(', ') || 'None'}
- Active Threats Detected: ${data.threats.active}

Top Findings:
${data.findings.topFindings.map(f => `- [${(f.severity || '').toUpperCase()}] ${f.title}`).join('\n') || 'None'}

Write a pentest report with: Executive Summary, Scope & Methodology, Findings (by severity), Attack Paths, Exploitation Evidence, Remediation Plan, Risk Rating.`,

        'incident': `Generate an incident summary report.

Incident Data:
- Total Incidents: ${data.incidents.total}
- Open: ${data.incidents.open}
- Closed: ${data.incidents.closed}
- Active Threats: ${data.threats.active}

Write an incident summary report with: Overview, Active Incidents, Resolution Metrics, Lessons Learned, Recommendations.`,

        'executive': `Generate an executive security briefing.

Key Metrics:
- Security Score: ${data.posture ? data.posture.score + '/100 (Grade ' + data.posture.grade + ')' : 'Not calculated'}
- Open Vulnerabilities: ${data.findings.open} (${data.findings.critical} critical)
- Active Threats: ${data.threats.active}
- Open Incidents: ${data.incidents.open}
- Scans Run: ${data.scans.completed}
${data.system ? `- Infrastructure: ${data.system.hostname}, ${data.system.uptimeHours}h uptime` : ''}

Write a concise executive security briefing (1-2 pages). Include: Security Posture Summary, Key Risks, Action Items, Resource Recommendations. Use business-friendly language.`,
      };

      // Generate report content — await AI, fall back to data-driven
      let content;
      try {
        content = await askAI(prompts[promptKey] || prompts['security-audit'], { timeout: 60000 });
      } catch {
        content = null;
      }

      if (!content) {
        content = buildFallbackReport(type, data, report.scope);
      }

      report.content = content;
      report.status = 'completed';
      report.completedAt = new Date().toISOString();
      report.data = data;

      // Save content to file
      const filename = `${report.id}.txt`;
      fs.writeFileSync(path.join(REPORTS_DIR, filename), report.content, 'utf8');
      report.filename = filename;

      // Save to reports index
      const reports = readJSON(REPORTS_PATH, []);
      reports.push(report);
      if (reports.length > 200) reports.splice(0, reports.length - 200);
      writeJSON(REPORTS_PATH, reports);

      res.json(report);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/reports/:id
  app.get('/api/reports/:id', requireAuth, (req, res) => {
    const reports = readJSON(REPORTS_PATH, []);
    const report = reports.find(r => r.id === req.params.id);
    if (!report) return res.status(404).json({ error: 'Report not found' });

    if (report.filename && !report.content) {
      try {
        report.content = fs.readFileSync(path.join(REPORTS_DIR, report.filename), 'utf8');
      } catch {}
    }

    res.json(report);
  });

  // DELETE /api/reports/:id
  app.delete('/api/reports/:id', requireAdmin, (req, res) => {
    let reports = readJSON(REPORTS_PATH, []);
    const report = reports.find(r => r.id === req.params.id);
    if (!report) return res.status(404).json({ error: 'Report not found' });

    if (report.filename) {
      try { fs.unlinkSync(path.join(REPORTS_DIR, report.filename)); } catch {}
    }

    reports = reports.filter(r => r.id !== req.params.id);
    writeJSON(REPORTS_PATH, reports);
    res.json({ success: true });
  });
};
