/**
 * Briefing Routes — Daily security briefing
 * GET /api/briefing auto-generates if none exists for today (data-driven + optional AI).
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA = path.join(__dirname, '..', 'data');
const BRIEFINGS_PATH = path.join(DATA, 'briefings.json');
const SCANS_PATH = path.join(DATA, 'scans.json');
const THREATS_PATH = path.join(DATA, 'threats.json');
const INCIDENTS_PATH = path.join(DATA, 'incidents.json');

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

module.exports = function (app, ctx) {
  const { requireAuth, askAI } = ctx;

  function todayKey() {
    return new Date().toISOString().split('T')[0];
  }

  // Gather security context for briefing
  async function gatherContext() {
    let postureData = null;
    if (ctx.getPostureScore) {
      try { postureData = await ctx.getPostureScore(); } catch {}
    }

    const scans = readJSON(SCANS_PATH, []);
    const allFindings = [];
    for (const s of scans) { if (s.findings) allFindings.push(...s.findings); }
    const yesterday = new Date(Date.now() - 86400000).toISOString();
    const newFindings = allFindings.filter(f => (f.scanDate || f.statusUpdatedAt || '') > yesterday);
    const openFindings = allFindings.filter(f => f.status !== 'resolved' && f.status !== 'false_positive');

    const threats = readJSON(THREATS_PATH, []);
    const activeThreats = threats.filter(t => t.status === 'active');

    const incidents = readJSON(INCIDENTS_PATH, []);
    const openIncidents = incidents.filter(i => i.status === 'open' || i.status === 'investigating');

    let systemInfo = null;
    if (ctx.getSystemInfo) {
      try { systemInfo = ctx.getSystemInfo(); } catch {}
    }

    return { postureData, scans, allFindings, newFindings, openFindings, threats, activeThreats, incidents, openIncidents, systemInfo };
  }

  // Build a data-driven briefing (no AI needed)
  function buildDataBriefing(c) {
    const score = c.postureData ? c.postureData.score : null;
    const grade = c.postureData ? c.postureData.grade : null;
    const critCount = c.openFindings.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
    const highCount = c.openFindings.filter(f => (f.severity || '').toLowerCase() === 'high').length;

    // Summary
    let summary;
    if (score !== null && score >= 80) {
      summary = `Security posture is healthy at ${score}/100 (Grade ${grade}). ${c.openFindings.length} open findings and ${c.activeThreats.length} active threats across ${c.scans.length} completed scans.`;
    } else if (score !== null) {
      summary = `Security posture needs attention — score ${score}/100 (Grade ${grade}). ${c.openFindings.length} open vulnerabilities (${critCount} critical, ${highCount} high) and ${c.activeThreats.length} active threats require review.`;
    } else if (c.scans.length > 0) {
      summary = `${c.scans.length} scans completed. ${c.openFindings.length} open findings detected (${critCount} critical, ${highCount} high). ${c.activeThreats.length} active threats being tracked.`;
    } else {
      summary = `No scans have been run yet. Run your first vulnerability or network scan to establish a security baseline. Configure scanners in Settings if needed.`;
    }

    // Highlights
    const highlights = [];
    if (score !== null) highlights.push(`Security posture score: ${score}/100 (Grade ${grade})`);
    highlights.push(`${c.openFindings.length} open vulnerabilities across ${c.scans.length} scans`);
    if (c.newFindings.length > 0) highlights.push(`${c.newFindings.length} new findings in the last 24 hours`);
    highlights.push(`${c.activeThreats.length} active threats being monitored`);
    if (c.openIncidents.length > 0) highlights.push(`${c.openIncidents.length} open incidents requiring attention`);
    if (c.scans.length === 0) highlights.push('No scans run yet — run a scan to populate security data');

    // Risks
    const risks = [];
    if (critCount > 0) risks.push(`${critCount} critical vulnerabilities require immediate remediation`);
    if (highCount > 0) risks.push(`${highCount} high-severity findings should be addressed within 7 days`);
    if (c.activeThreats.length > 0) {
      const critThreats = c.activeThreats.filter(t => (t.severity || '').toLowerCase() === 'critical');
      if (critThreats.length > 0) risks.push(`${critThreats.length} critical active threats: ${critThreats.slice(0, 2).map(t => t.title).join(', ')}`);
      else risks.push(`${c.activeThreats.length} active threats need investigation`);
    }
    if (risks.length === 0) risks.push('No critical risk items — continue regular monitoring and scanning');

    // Recommendations
    const recommendations = [];
    if (c.scans.length === 0) {
      recommendations.push('Run an initial network scan to discover open ports and services');
      recommendations.push('Run a vulnerability scan against your primary targets');
    }
    if (critCount > 0) recommendations.push('Prioritize remediation of critical vulnerabilities');
    if (c.activeThreats.length > 0) recommendations.push('Triage active threats in the Threat Feed view');
    if (c.openIncidents.length > 0) recommendations.push('Review and update open incident status');
    if (recommendations.length === 0) {
      recommendations.push('Schedule recurring scans for continuous monitoring');
      recommendations.push('Review compliance posture against your target framework');
    }

    return { summary, highlights, risks, recommendations };
  }

  // Generate or retrieve today's briefing
  async function generateBriefing() {
    const c = await gatherContext();

    // Always build data-driven briefing first
    const dataBriefing = buildDataBriefing(c);
    let aiBriefingText = null;

    // Try AI enhancement
    try {
      const prompt = `Security Operations Daily Briefing Data:

POSTURE:
${c.postureData ? `Score: ${c.postureData.score}/100 (Grade ${c.postureData.grade})` : 'Posture score not available'}

VULNERABILITIES:
- Total open: ${c.openFindings.length} (${c.openFindings.filter(f => (f.severity || '').toLowerCase() === 'critical').length} critical, ${c.openFindings.filter(f => (f.severity || '').toLowerCase() === 'high').length} high)
- New since yesterday: ${c.newFindings.length}

THREATS:
- Active: ${c.activeThreats.length}
${c.activeThreats.slice(0, 5).map(t => `  - [${t.severity}] ${t.title}`).join('\n') || '  None active'}

INCIDENTS:
- Open: ${c.openIncidents.length}
${c.openIncidents.slice(0, 5).map(i => `  - [${i.severity}] ${i.title} (${i.status})`).join('\n') || '  None open'}

SYSTEM:
${c.systemInfo ? `Hostname: ${c.systemInfo.hostname}, CPU: ${c.systemInfo.cpuPct}%, Memory: ${c.systemInfo.usedMemPct}%, Uptime: ${c.systemInfo.uptimeHours}h` : 'System info not available'}

You are a Chief Information Security Officer preparing a daily security briefing. Write a concise 3-5 sentence summary of the current security status, key risks, and top priority action items. No markdown, no headers — just the narrative.`;

      aiBriefingText = await askAI(prompt, { timeout: 20000 });
    } catch {}

    const briefing = {
      id: crypto.randomUUID(),
      date: todayKey(),
      generated: true,
      summary: aiBriefingText || dataBriefing.summary,
      highlights: dataBriefing.highlights,
      risks: dataBriefing.risks,
      recommendations: dataBriefing.recommendations,
      data: {
        postureScore: c.postureData ? c.postureData.score : null,
        postureGrade: c.postureData ? c.postureData.grade : null,
        openFindings: c.openFindings.length,
        criticalFindings: c.openFindings.filter(f => (f.severity || '').toLowerCase() === 'critical').length,
        newFindings: c.newFindings.length,
        activeThreats: c.activeThreats.length,
        openIncidents: c.openIncidents.length,
        totalScans: c.scans.length,
      },
      generatedAt: new Date().toISOString(),
    };

    // Save
    const briefings = readJSON(BRIEFINGS_PATH, []);
    const filtered = briefings.filter(b => b.date !== todayKey());
    filtered.push(briefing);
    if (filtered.length > 90) filtered.splice(0, filtered.length - 90);
    writeJSON(BRIEFINGS_PATH, filtered);

    return briefing;
  }

  // GET /api/briefing — get today's briefing, auto-generate if missing
  app.get('/api/briefing', requireAuth, async (req, res) => {
    try {
      const briefings = readJSON(BRIEFINGS_PATH, []);
      const today = todayKey();
      const existing = briefings.find(b => b.date === today);

      if (existing) {
        return res.json(existing);
      }

      // Auto-generate
      const briefing = await generateBriefing();
      res.json(briefing);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/briefing/generate — force regenerate
  app.post('/api/briefing/generate', requireAuth, async (req, res) => {
    try {
      const briefing = await generateBriefing();
      res.json(briefing);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
};
