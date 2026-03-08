/**
 * Posture Routes — Security posture score, history, breakdown
 */
const fs = require('fs');
const path = require('path');
const os = require('os');

const DATA = path.join(__dirname, '..', 'data');
const HISTORY_PATH = path.join(DATA, 'posture-history.json');
const SCANS_PATH = path.join(DATA, 'scans.json');
const THREATS_PATH = path.join(DATA, 'threats.json');
const INCIDENTS_PATH = path.join(DATA, 'incidents.json');

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
  const { requireAuth, execCommand } = ctx;

  async function calculatePosture() {
    const categories = {};
    let totalScore = 100;
    const deductions = [];

    // 1. System Hardening (25 points)
    let systemScore = 25;
    const systemChecks = [];

    // Check for unattended upgrades
    if (process.platform !== 'win32') {
      try {
        const result = await execCommand('dpkg -l unattended-upgrades 2>/dev/null | grep -c "^ii" || echo 0', { timeout: 3000 });
        const installed = parseInt(result.stdout.trim()) > 0;
        systemChecks.push({ name: 'Unattended Upgrades', pass: installed });
        if (!installed) { systemScore -= 5; deductions.push('Unattended upgrades not installed (-5)'); }
      } catch { systemChecks.push({ name: 'Unattended Upgrades', pass: false, skipped: true }); }

      // Check firewall
      try {
        const result = await execCommand('ufw status 2>/dev/null | head -1 || echo inactive', { timeout: 3000 });
        const active = result.stdout.includes('active') && !result.stdout.includes('inactive');
        systemChecks.push({ name: 'Firewall Active', pass: active });
        if (!active) { systemScore -= 8; deductions.push('Firewall not active (-8)'); }
      } catch { systemChecks.push({ name: 'Firewall Active', pass: false, skipped: true }); }

      // Check SSH root login disabled
      try {
        const result = await execCommand("grep -c 'PermitRootLogin no' /etc/ssh/sshd_config 2>/dev/null || echo 0", { timeout: 3000 });
        const disabled = parseInt(result.stdout.trim()) > 0;
        systemChecks.push({ name: 'SSH Root Login Disabled', pass: disabled });
        if (!disabled) { systemScore -= 5; deductions.push('SSH root login may be enabled (-5)'); }
      } catch { systemChecks.push({ name: 'SSH Root Login Disabled', pass: false, skipped: true }); }

      // Check for password authentication in SSH
      try {
        const result = await execCommand("grep -c 'PasswordAuthentication no' /etc/ssh/sshd_config 2>/dev/null || echo 0", { timeout: 3000 });
        const disabled = parseInt(result.stdout.trim()) > 0;
        systemChecks.push({ name: 'SSH Password Auth Disabled', pass: disabled });
        if (!disabled) { systemScore -= 4; deductions.push('SSH password authentication may be enabled (-4)'); }
      } catch { systemChecks.push({ name: 'SSH Password Auth Disabled', pass: false, skipped: true }); }
    } else {
      systemScore = 20; // Assume basic on Windows
      systemChecks.push({ name: 'System Hardening', pass: true, detail: 'Windows — basic checks only' });
    }

    systemScore = Math.max(0, systemScore);
    categories.system = { score: systemScore, maxScore: 25, checks: systemChecks };

    // 2. Vulnerability Management (25 points)
    let vulnScore = 25;
    const scans = readJSON(SCANS_PATH, []);
    const completedScans = scans.filter(s => s.status === 'completed');
    const allFindings = [];
    for (const s of scans) {
      if (s.findings) allFindings.push(...s.findings);
    }
    const openFindings = allFindings.filter(f => f.status === 'open');
    const criticalOpen = openFindings.filter(f => f.severity === 'critical').length;
    const highOpen = openFindings.filter(f => f.severity === 'high').length;

    if (completedScans.length === 0) { vulnScore -= 10; deductions.push('No completed vulnerability scans (-10)'); }
    if (criticalOpen > 0) { vulnScore -= Math.min(10, criticalOpen * 5); deductions.push(`${criticalOpen} critical open vulnerabilities (-${Math.min(10, criticalOpen * 5)})`); }
    if (highOpen > 0) { vulnScore -= Math.min(5, highOpen * 2); deductions.push(`${highOpen} high open vulnerabilities (-${Math.min(5, highOpen * 2)})`); }

    vulnScore = Math.max(0, vulnScore);
    categories.vulnerabilities = {
      score: vulnScore, maxScore: 25,
      totalFindings: allFindings.length,
      openCritical: criticalOpen,
      openHigh: highOpen,
      scansCompleted: completedScans.length,
    };

    // 3. Threat Detection (25 points)
    let threatScore = 25;
    const threats = readJSON(THREATS_PATH, []);
    const activeThreats = threats.filter(t => t.status === 'active');
    const criticalThreats = activeThreats.filter(t => t.severity === 'critical').length;

    if (criticalThreats > 0) { threatScore -= Math.min(15, criticalThreats * 5); deductions.push(`${criticalThreats} critical active threats (-${Math.min(15, criticalThreats * 5)})`); }
    if (activeThreats.length > 5) { threatScore -= 5; deductions.push('More than 5 active threats (-5)'); }

    threatScore = Math.max(0, threatScore);
    categories.threats = {
      score: threatScore, maxScore: 25,
      activeThreats: activeThreats.length,
      criticalThreats,
    };

    // 4. Incident Response (25 points)
    let irScore = 25;
    const incidents = readJSON(INCIDENTS_PATH, []);
    const openIncidents = incidents.filter(i => i.status === 'open' || i.status === 'investigating');
    const criticalIncidents = openIncidents.filter(i => i.severity === 'critical').length;

    if (criticalIncidents > 0) { irScore -= Math.min(15, criticalIncidents * 5); deductions.push(`${criticalIncidents} critical open incidents (-${Math.min(15, criticalIncidents * 5)})`); }
    if (openIncidents.length > 3) { irScore -= 5; deductions.push('More than 3 open incidents (-5)'); }

    irScore = Math.max(0, irScore);
    categories.incidents = {
      score: irScore, maxScore: 25,
      openIncidents: openIncidents.length,
      criticalIncidents,
    };

    totalScore = categories.system.score + categories.vulnerabilities.score + categories.threats.score + categories.incidents.score;
    const grade = totalScore >= 90 ? 'A' : totalScore >= 75 ? 'B' : totalScore >= 60 ? 'C' : totalScore >= 40 ? 'D' : 'F';

    return {
      score: totalScore,
      maxScore: 100,
      grade,
      categories,
      deductions,
      calculatedAt: new Date().toISOString(),
    };
  }

  // Expose for other routes
  ctx.getPostureScore = async () => {
    try { return await calculatePosture(); }
    catch { return { score: 0, grade: 'F', error: 'Calculation failed' }; }
  };

  // GET /api/posture
  app.get('/api/posture', requireAuth, async (req, res) => {
    try {
      const posture = await calculatePosture();
      res.json(posture);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/posture/history
  app.get('/api/posture/history', requireAuth, (req, res) => {
    const history = readJSON(HISTORY_PATH, []);
    res.json({ history: history.slice(-90) });
  });

  // GET /api/posture/breakdown
  app.get('/api/posture/breakdown', requireAuth, async (req, res) => {
    try {
      const posture = await calculatePosture();
      res.json({
        score: posture.score,
        grade: posture.grade,
        categories: posture.categories,
        deductions: posture.deductions,
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/posture/refresh — force recalculation and save to history
  app.post('/api/posture/refresh', requireAuth, async (req, res) => {
    try {
      const posture = await calculatePosture();

      // Save to history
      const history = readJSON(HISTORY_PATH, []);
      history.push({
        score: posture.score,
        grade: posture.grade,
        date: new Date().toISOString().split('T')[0],
        timestamp: posture.calculatedAt,
        categories: {
          system: posture.categories.system.score,
          vulnerabilities: posture.categories.vulnerabilities.score,
          threats: posture.categories.threats.score,
          incidents: posture.categories.incidents.score,
        },
      });
      if (history.length > 365) history.splice(0, history.length - 365);
      writeJSON(HISTORY_PATH, history);

      res.json(posture);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
};
