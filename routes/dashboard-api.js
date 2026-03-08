/**
 * Dashboard API Routes — Aggregates data from scans, threats, findings
 * Provides the 3 missing endpoints the dashboard view needs,
 * plus auto-generates alerts/threats from scan findings so all views show real data.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA = path.join(__dirname, '..', 'data');
const SCANS_PATH = path.join(DATA, 'scans.json');
const THREATS_PATH = path.join(DATA, 'threats.json');
const ALERTS_PATH = path.join(DATA, 'alerts.json');

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


module.exports = function (app, ctx) {
  const { requireAuth } = ctx;

  // ════════════════════════════════════════════════════════════════════════
  // GET /api/dashboard/stats — Aggregated stat cards
  // ════════════════════════════════════════════════════════════════════════
  app.get('/api/dashboard/stats', requireAuth, (req, res) => {
    try {
      const threats = readJSON(THREATS_PATH, []);
      const scans = readJSON(SCANS_PATH, []);
      const findings = getAllFindings();

      const activeThreats = threats.filter(t => t.status === 'active').length;
      const openFindings = findings.length;

      // Last scan time
      let lastScan = null;
      if (scans.length > 0) {
        const sorted = scans.filter(s => s.completedAt).sort((a, b) =>
          new Date(b.completedAt) - new Date(a.completedAt)
        );
        if (sorted.length > 0) lastScan = sorted[0].completedAt;
      }

      // Compliance score — derived from posture if available, else from findings
      const critCount = findings.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
      const highCount = findings.filter(f => (f.severity || '').toLowerCase() === 'high').length;
      let complianceScore = 100;
      if (critCount > 0) complianceScore -= critCount * 15;
      if (highCount > 0) complianceScore -= highCount * 5;
      if (complianceScore < 0) complianceScore = 0;

      res.json({
        activeThreats,
        openFindings,
        lastScan,
        complianceScore,
        totalScans: scans.length,
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ════════════════════════════════════════════════════════════════════════
  // GET /api/dashboard/threat-activity — 24h threat timeline
  // ════════════════════════════════════════════════════════════════════════
  app.get('/api/dashboard/threat-activity', requireAuth, (req, res) => {
    try {
      const threats = readJSON(THREATS_PATH, []);
      const scans = readJSON(SCANS_PATH, []);
      const now = Date.now();
      const labels = [];
      const values = [];

      for (let i = 23; i >= 0; i--) {
        const hourStart = now - (i + 1) * 3600000;
        const hourEnd = now - i * 3600000;
        labels.push(i + 'h');

        // Count threats detected in this hour
        let count = threats.filter(t => {
          const ts = new Date(t.detectedAt || t.timestamp || t.created_at).getTime();
          return ts >= hourStart && ts < hourEnd;
        }).length;

        // Also count scan findings created in this hour (security events)
        count += scans.filter(s => {
          const ts = new Date(s.completedAt || s.createdAt).getTime();
          return ts >= hourStart && ts < hourEnd;
        }).reduce((sum, s) => sum + (s.findingsCount || 0), 0);

        values.push(count);
      }

      res.json({ labels, values });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ════════════════════════════════════════════════════════════════════════
  // GET /api/dashboard/severity-breakdown — Findings by severity
  // ════════════════════════════════════════════════════════════════════════
  app.get('/api/dashboard/severity-breakdown', requireAuth, (req, res) => {
    try {
      const findings = getAllFindings();
      const breakdown = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const f of findings) {
        const sev = (f.severity || 'info').toLowerCase();
        if (breakdown.hasOwnProperty(sev)) breakdown[sev]++;
      }
      res.json(breakdown);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ════════════════════════════════════════════════════════════════════════
  // Auto-generate alerts + threats from scan findings
  // Called internally after each scan completes (scan-api.js saveScanResult)
  // Also runs on first dashboard load to backfill from existing scans
  // ════════════════════════════════════════════════════════════════════════
  ctx.syncFindingsToAlertsAndThreats = function syncFindingsToAlertsAndThreats() {
    try {
      const scans = readJSON(SCANS_PATH, []);
      const alerts = readJSON(ALERTS_PATH, []);
      const threats = readJSON(THREATS_PATH, []);

      const existingAlertTitles = new Set(alerts.map(a => a.title));
      const existingThreatTitles = new Set(threats.map(t => t.title));
      let newAlerts = 0;
      let newThreats = 0;

      for (const scan of scans) {
        if (!scan.findings || !Array.isArray(scan.findings)) continue;

        for (const f of scan.findings) {
          const sev = (f.severity || 'info').toLowerCase();
          const title = f.title || f.name || 'Unnamed finding';
          const target = f.target || f.matched_at || scan.target || 'unknown';

          // Critical + High findings → alerts (for triage)
          if ((sev === 'critical' || sev === 'high') && !existingAlertTitles.has(title)) {
            alerts.push({
              id: crypto.randomUUID(),
              title,
              description: f.description || title,
              severity: sev,
              source: scan.type || 'scan',
              target,
              status: 'pending',
              created_at: scan.completedAt || scan.createdAt || new Date().toISOString(),
              timestamp: scan.completedAt || scan.createdAt || new Date().toISOString(),
            });
            existingAlertTitles.add(title);
            newAlerts++;
          }

          // Critical findings → threats (for threat feed)
          if (sev === 'critical' && !existingThreatTitles.has(title)) {
            threats.push({
              id: crypto.randomUUID(),
              type: 'vulnerability',
              title,
              severity: sev,
              source: scan.type || 'scan',
              details: (f.description || title) + ' — Target: ' + target,
              detectedAt: scan.completedAt || scan.createdAt || new Date().toISOString(),
              timestamp: scan.completedAt || scan.createdAt || new Date().toISOString(),
              status: 'active',
            });
            existingThreatTitles.add(title);
            newThreats++;
          }

          // High findings from vuln/web scans → threats too
          if (sev === 'high' && (scan.type === 'nuclei' || scan.type === 'native-vuln') && !existingThreatTitles.has(title)) {
            threats.push({
              id: crypto.randomUUID(),
              type: 'vulnerability',
              title,
              severity: sev,
              source: scan.type || 'scan',
              details: (f.description || title) + ' — Target: ' + target,
              detectedAt: scan.completedAt || scan.createdAt || new Date().toISOString(),
              timestamp: scan.completedAt || scan.createdAt || new Date().toISOString(),
              status: 'active',
            });
            existingThreatTitles.add(title);
            newThreats++;
          }
        }
      }

      // Cap and save
      if (newAlerts > 0) {
        if (alerts.length > 500) alerts.splice(0, alerts.length - 500);
        writeJSON(ALERTS_PATH, alerts);
      }
      if (newThreats > 0) {
        if (threats.length > 500) threats.splice(0, threats.length - 500);
        writeJSON(THREATS_PATH, threats);
      }

      return { newAlerts, newThreats };
    } catch {
      return { newAlerts: 0, newThreats: 0 };
    }
  };

  // Run initial sync on load
  const result = ctx.syncFindingsToAlertsAndThreats();
  if (result.newAlerts > 0 || result.newThreats > 0) {
    console.log(`  Dashboard sync: ${result.newAlerts} new alerts, ${result.newThreats} new threats from scan history`);
  }
};
