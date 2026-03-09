/**
 * Hunt Routes — AI-driven threat hunting with hypothesis-based investigation
 * Synchronous: POST /api/hunt awaits completion and returns full results.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const DATA = path.join(__dirname, '..', 'data');
const HUNTS_PATH = path.join(DATA, 'hunts.json');

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

// Limit concurrent hunts
let activeHuntCount = 0;
const MAX_CONCURRENT = 3;

module.exports = function (app, ctx) {
  const { requireAuth, requireRole, execCommand, askAI, askAIJSON } = ctx;

  // Safe commands for evidence gathering — read-only only
  const SAFE_COMMANDS_LINUX = {
    processes: "ps aux --sort=-%cpu 2>/dev/null | head -30",
    network_connections: "ss -tunapl 2>/dev/null || netstat -tunapl 2>/dev/null | head -50",
    listening_ports: "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null | head -30",
    cron_jobs: "(crontab -l 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null; cat /etc/crontab 2>/dev/null) | head -50",
    docker_containers: "docker ps -a --format 'table {{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.Ports}}' 2>/dev/null | head -30",
    recent_logins: "last -20 2>/dev/null || echo 'last command unavailable'",
    failed_logins: "grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -20 || journalctl -u sshd --since '24 hours ago' 2>/dev/null | grep 'Failed' | tail -20",
    tmp_files: "find /tmp /var/tmp -type f -mtime -1 2>/dev/null | head -30",
    setuid_binaries: "find /usr/bin /usr/sbin /usr/local/bin -perm -4000 2>/dev/null | head -20",
    suspicious_files: "find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | head -20",
    kernel_modules: "lsmod 2>/dev/null | head -20",
    open_files: "lsof -i -n -P 2>/dev/null | head -30",
    dns_config: "cat /etc/resolv.conf 2>/dev/null",
    hosts_file: "cat /etc/hosts 2>/dev/null",
    env_secrets: "env 2>/dev/null | grep -iE '(KEY|SECRET|TOKEN|PASS|API)' | sed 's/=.*/=***REDACTED***/' | head -20",
    systemd_services: "systemctl list-units --type=service --state=running 2>/dev/null | head -30",
    disk_usage: "df -h 2>/dev/null",
    memory_info: "free -h 2>/dev/null",
    uptime_info: "uptime 2>/dev/null",
  };

  const SAFE_COMMANDS_WIN = {
    processes: 'tasklist /V /FO CSV 2>nul | more +1',
    network_connections: 'netstat -an 2>nul',
    listening_ports: 'netstat -an 2>nul | findstr LISTENING',
    docker_containers: 'docker ps -a --format "table {{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.Ports}}" 2>nul',
    dns_config: 'ipconfig /all 2>nul | findstr /C:"DNS Servers"',
    hosts_file: 'type %SystemRoot%\\System32\\drivers\\etc\\hosts 2>nul',
    disk_usage: 'wmic logicaldisk get size,freespace,caption 2>nul',
    uptime_info: 'wmic os get lastbootuptime 2>nul',
  };

  // Cross-platform evidence via Node.js APIs (no shell needed)
  function gatherNodeEvidence(key) {
    switch (key) {
      case 'memory_info':
        return `Total: ${(os.totalmem() / 1073741824).toFixed(1)} GB\nFree:  ${(os.freemem() / 1073741824).toFixed(1)} GB\nUsed:  ${((os.totalmem() - os.freemem()) / 1073741824).toFixed(1)} GB (${((1 - os.freemem() / os.totalmem()) * 100).toFixed(0)}%)`;
      case 'uptime_info':
        return `System uptime: ${(os.uptime() / 3600).toFixed(1)} hours\nHostname: ${os.hostname()}\nPlatform: ${os.platform()} ${os.release()}\nArch: ${os.arch()}\nCPUs: ${os.cpus().length}`;
      case 'env_secrets': {
        const secrets = [];
        for (const [k, v] of Object.entries(process.env)) {
          if (/key|secret|token|pass|api/i.test(k)) {
            secrets.push(`${k}=***REDACTED***`);
          }
        }
        return secrets.slice(0, 20).join('\n') || 'No secret-like env vars found';
      }
      default:
        return null;
    }
  }

  // Parse a single-word verdict from AI analysis text
  function parseVerdict(analysisText) {
    if (!analysisText) return 'inconclusive';
    const lower = analysisText.toLowerCase();
    // Check for explicit VERDICT: line
    const match = lower.match(/verdict\s*:\s*(confirmed|not[_ ]confirmed|inconclusive|clear)/);
    if (match) {
      const v = match[1].replace(/[_ ]/g, '_');
      if (v === 'confirmed') return 'confirmed';
      if (v.includes('not')) return 'clear';
      return 'inconclusive';
    }
    // Fallback heuristics
    if (lower.includes('confirmed') && !lower.includes('not confirmed')) return 'confirmed';
    if (lower.includes('not confirmed') || lower.includes('no evidence')) return 'clear';
    return 'inconclusive';
  }

  // POST /api/hunt — submit hypothesis, await full investigation results
  app.post('/api/hunt', requireRole('analyst'), async (req, res) => {
    try {
      const { hypothesis } = req.body;
      if (!hypothesis) return res.status(400).json({ error: 'hypothesis required' });
      if (activeHuntCount >= MAX_CONCURRENT) return res.status(429).json({ error: `Maximum ${MAX_CONCURRENT} concurrent hunts. Wait for one to complete.` });

      activeHuntCount++;

      const hunt = {
        id: crypto.randomUUID(),
        hypothesis: escapeHtml(hypothesis),
        status: 'planning',
        plan: null,
        evidence: [],
        analysis: null,
        verdict: null,
        createdAt: new Date().toISOString(),
        createdBy: req.user ? req.user.username : 'unknown',
      };

      const isWin = process.platform === 'win32';
      const SAFE_COMMANDS = isWin ? SAFE_COMMANDS_WIN : SAFE_COMMANDS_LINUX;
      const allCommandKeys = Object.keys(isWin ? { ...SAFE_COMMANDS_WIN, ...{ memory_info: 1, uptime_info: 1, env_secrets: 1 } } : SAFE_COMMANDS_LINUX);

      try {
        // Step 1: AI generates investigation plan
        const planPrompt = `You are a threat hunter. Given this hypothesis, generate an investigation plan.

Hypothesis: ${hypothesis}

Available evidence-gathering commands:
${allCommandKeys.join(', ')}

Return ONLY a JSON object:
{
  "plan": "<brief 1-2 sentence investigation plan>",
  "commands": ["command_key_1", "command_key_2", ...],
  "rationale": "<why these commands will help prove/disprove the hypothesis>"
}

Choose 3-6 relevant commands from the available list. Pick the ones most likely to reveal evidence for this specific hypothesis.`;

        let plan;
        try {
          plan = await askAIJSON(planPrompt);
        } catch {
          try {
            const raw = await askAI(planPrompt, { timeout: 20000 });
            const match = raw.match(/\{[\s\S]*\}/);
            plan = match ? JSON.parse(match[0]) : null;
          } catch {
            plan = null;
          }
        }
        if (!plan) {
          plan = { plan: 'Gather system evidence', commands: ['processes', 'network_connections', 'listening_ports', 'memory_info', 'uptime_info'], rationale: 'Default broad investigation' };
        }

        hunt.plan = plan;
        hunt.status = 'gathering';

        // Step 2: Execute evidence-gathering commands
        const commandKeys = (plan.commands || []).filter(k => SAFE_COMMANDS[k] || gatherNodeEvidence(k) !== null).slice(0, 6);
        if (commandKeys.length === 0) commandKeys.push('processes', 'network_connections', 'listening_ports');

        for (const key of commandKeys) {
          // Try Node.js API first (cross-platform)
          const nodeResult = gatherNodeEvidence(key);
          if (nodeResult !== null) {
            hunt.evidence.push({ command: key, output: nodeResult, status: 'collected' });
            continue;
          }

          // Fall back to shell command
          if (!SAFE_COMMANDS[key]) {
            hunt.evidence.push({ command: key, output: '(Command not available on this platform)', status: 'skipped' });
            continue;
          }

          try {
            const result = await execCommand(SAFE_COMMANDS[key], { timeout: 15000 });
            const output = (result.stdout || result.stderr || '').trim();
            hunt.evidence.push({
              command: key,
              output: output.substring(0, 3000) || '(no output)',
              status: output ? 'collected' : 'empty',
            });
          } catch (e) {
            hunt.evidence.push({ command: key, output: 'Error: ' + e.message, status: 'failed' });
          }
        }

        // Step 3: AI analyzes evidence
        hunt.status = 'analyzing';
        const evidenceText = hunt.evidence.map(e => `[${e.command}] (${e.status})\n${e.output}`).join('\n\n---\n\n');

        const analysisPrompt = `You are a threat hunter analyzing evidence to test a hypothesis.

Hypothesis: ${hypothesis}

Investigation Plan: ${plan.plan}

Evidence Collected:
${evidenceText.substring(0, 6000)}

Analyze the evidence and provide your verdict. Return your analysis as plain text (not JSON) with these sections:

VERDICT: confirmed / not_confirmed / inconclusive
CONFIDENCE: <number 0-100>%
ANALYSIS: <3-5 sentences explaining what the evidence shows>
INDICATORS: <list specific IOCs or suspicious findings, if any>
RECOMMENDATIONS: <2-3 specific actions to take>`;

        let analysis;
        try {
          analysis = await askAI(analysisPrompt, { timeout: 30000 });
        } catch {
          analysis = 'AI analysis unavailable. Review the collected evidence manually.\n\nVERDICT: inconclusive\nCONFIDENCE: 0%\nANALYSIS: Could not reach AI provider for analysis. The evidence has been collected and is available for manual review.\nINDICATORS: N/A\nRECOMMENDATIONS: 1. Review collected evidence manually. 2. Ensure AI provider is configured in Settings.';
        }

        hunt.analysis = analysis;
        hunt.verdict = parseVerdict(analysis);
        hunt.status = 'completed';
        hunt.completedAt = new Date().toISOString();

      } catch (e) {
        hunt.status = 'failed';
        hunt.analysis = 'Investigation failed: ' + e.message;
        hunt.verdict = 'inconclusive';
        hunt.completedAt = new Date().toISOString();
      } finally {
        activeHuntCount--;
        // Save to history
        const allHunts = readJSON(HUNTS_PATH, []);
        allHunts.push(hunt);
        if (allHunts.length > 200) allHunts.splice(0, allHunts.length - 200);
        writeJSON(HUNTS_PATH, allHunts);

        if (ctx.io) ctx.io.emit('hunt_complete', { id: hunt.id, status: hunt.status, verdict: hunt.verdict });
      }

      // Return full results
      res.json({
        evidence: hunt.evidence,
        analysis: hunt.analysis,
        verdict: hunt.verdict,
        plan: hunt.plan,
        huntId: hunt.id,
        status: hunt.status,
      });

    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/hunt/history
  app.get('/api/hunt/history', requireAuth, (req, res) => {
    const hunts = readJSON(HUNTS_PATH, []);
    res.json({
      hunts: hunts.map(h => ({
        id: h.id,
        hypothesis: h.hypothesis,
        status: h.status,
        verdict: h.verdict || null,
        createdAt: h.createdAt,
        timestamp: h.createdAt,
        completedAt: h.completedAt,
        createdBy: h.createdBy,
      })).reverse(),
    });
  });

  // GET /api/hunt/:id — get hunt detail
  app.get('/api/hunt/:id', requireAuth, (req, res) => {
    const hunts = readJSON(HUNTS_PATH, []);
    const hunt = hunts.find(h => h.id === req.params.id);
    if (!hunt) return res.status(404).json({ error: 'Hunt not found' });
    res.json(hunt);
  });
};
