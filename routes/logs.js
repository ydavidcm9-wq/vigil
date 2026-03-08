/**
 * Logs Routes — Natural language security log querying with AI
 * Cross-platform: uses Vigil's own security data stores on all platforms,
 * plus Linux system logs on Linux.
 */
const fs = require('fs');
const path = require('path');

const DATA = path.join(__dirname, '..', 'data');

function escapeHtml(s) { return String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }

function readJSON(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return fallback; }
}

// Gather security data from all JSON stores for AI analysis
function gatherSecurityData(query) {
  const lowerQ = query.toLowerCase();
  const sections = [];

  // Audit log — always relevant
  const auditLog = readJSON(path.join(DATA, 'audit-log.json'), []);
  if (auditLog.length > 0) {
    sections.push({
      source: 'Audit Log',
      count: auditLog.length,
      data: auditLog.slice(-50).map(e =>
        `[${e.timestamp}] ${e.user || 'system'} ${e.action} ${e.resource || ''} ${e.details ? JSON.stringify(e.details) : ''}`
      ).join('\n'),
    });
  }

  // Scan results
  const scans = readJSON(path.join(DATA, 'scans.json'), []);
  if (scans.length > 0 && (lowerQ.includes('scan') || lowerQ.includes('vuln') || lowerQ.includes('finding') || lowerQ.includes('all') || lowerQ.includes('recent') || lowerQ.includes('activit'))) {
    sections.push({
      source: 'Scan Results',
      count: scans.length,
      data: scans.slice(-20).map(s =>
        `[${s.startedAt || s.timestamp}] ${s.type || 'scan'} target=${s.target || 'n/a'} status=${s.status || 'unknown'} findings=${s.findingCount || 0}`
      ).join('\n'),
    });
  }

  // Threats
  const threats = readJSON(path.join(DATA, 'threats.json'), []);
  if (threats.length > 0 && (lowerQ.includes('threat') || lowerQ.includes('attack') || lowerQ.includes('malware') || lowerQ.includes('ioc') || lowerQ.includes('all') || lowerQ.includes('critical') || lowerQ.includes('activit'))) {
    sections.push({
      source: 'Active Threats',
      count: threats.length,
      data: threats.slice(-20).map(t =>
        `[${t.timestamp || t.firstSeen}] ${t.name || t.title || 'Unknown'} level=${t.level || t.severity || 'unknown'} type=${t.type || 'n/a'} source=${t.source || 'n/a'}`
      ).join('\n'),
    });
  }

  // Alerts
  const alerts = readJSON(path.join(DATA, 'alerts.json'), []);
  if (alerts.length > 0 && (lowerQ.includes('alert') || lowerQ.includes('warn') || lowerQ.includes('fail') || lowerQ.includes('all') || lowerQ.includes('recent') || lowerQ.includes('activit'))) {
    sections.push({
      source: 'Security Alerts',
      count: alerts.length,
      data: alerts.slice(-30).map(a =>
        `[${a.timestamp || a.created}] ${a.severity || 'info'} ${a.title || a.message || 'Alert'} status=${a.status || 'open'} source=${a.source || 'system'}`
      ).join('\n'),
    });
  }

  // Findings
  const findings = readJSON(path.join(DATA, 'findings.json'), []);
  if (findings.length > 0 && (lowerQ.includes('finding') || lowerQ.includes('vuln') || lowerQ.includes('cve') || lowerQ.includes('critical') || lowerQ.includes('high') || lowerQ.includes('all'))) {
    const critHigh = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    const subset = critHigh.length > 0 ? critHigh.slice(-30) : findings.slice(-30);
    sections.push({
      source: 'Vulnerability Findings',
      count: findings.length,
      data: subset.map(f =>
        `[${f.timestamp || f.discovered}] ${f.severity || 'info'} ${f.title || f.name || 'Finding'} host=${f.host || f.target || 'n/a'} ${f.cve || ''}`
      ).join('\n'),
    });
  }

  // Incidents
  const incidents = readJSON(path.join(DATA, 'incidents.json'), []);
  if (incidents.length > 0 && (lowerQ.includes('incident') || lowerQ.includes('breach') || lowerQ.includes('response') || lowerQ.includes('all') || lowerQ.includes('activit'))) {
    sections.push({
      source: 'Security Incidents',
      count: incidents.length,
      data: incidents.slice(-20).map(i =>
        `[${i.timestamp || i.created}] ${i.severity || 'info'} "${i.title || 'Incident'}" status=${i.status || 'open'} assignee=${i.assignee || 'unassigned'}`
      ).join('\n'),
    });
  }

  // Agent runs
  const agentRuns = readJSON(path.join(DATA, 'agent-runs.json'), []);
  if (agentRuns.length > 0 && (lowerQ.includes('agent') || lowerQ.includes('run') || lowerQ.includes('ai') || lowerQ.includes('all') || lowerQ.includes('activit'))) {
    sections.push({
      source: 'Agent Runs',
      count: agentRuns.length,
      data: agentRuns.slice(-20).map(r =>
        `[${r.createdAt}] ${r.agentName || 'Agent'} status=${r.status} duration=${r.duration}ms input="${(r.input || '').substring(0, 80)}"`
      ).join('\n'),
    });
  }

  // Hunts
  const hunts = readJSON(path.join(DATA, 'hunts.json'), []);
  if (hunts.length > 0 && (lowerQ.includes('hunt') || lowerQ.includes('threat') || lowerQ.includes('mitre') || lowerQ.includes('all') || lowerQ.includes('activit'))) {
    sections.push({
      source: 'Threat Hunts',
      count: hunts.length,
      data: hunts.slice(-10).map(h =>
        `[${h.timestamp || h.createdAt}] "${h.query || h.hypothesis || 'Hunt'}" status=${h.status || 'complete'} findings=${h.findingCount || 0}`
      ).join('\n'),
    });
  }

  // SSL domains
  const sslDomains = readJSON(path.join(DATA, 'ssl-domains.json'), []);
  if (sslDomains.length > 0 && (lowerQ.includes('ssl') || lowerQ.includes('cert') || lowerQ.includes('tls') || lowerQ.includes('expir') || lowerQ.includes('all'))) {
    sections.push({
      source: 'SSL Certificates',
      count: sslDomains.length,
      data: sslDomains.map(d =>
        `${d.domain} grade=${d.grade || '?'} daysLeft=${d.daysLeft || '?'} issuer=${d.issuer || '?'} expires=${d.expiry || '?'}`
      ).join('\n'),
    });
  }

  // OSINT
  const osint = readJSON(path.join(DATA, 'osint-history.json'), []);
  if (osint.length > 0 && (lowerQ.includes('osint') || lowerQ.includes('domain') || lowerQ.includes('recon') || lowerQ.includes('all'))) {
    sections.push({
      source: 'OSINT History',
      count: osint.length,
      data: osint.slice(-10).map(o =>
        `[${o.timestamp || o.date}] ${o.query || o.target || 'query'} type=${o.type || 'lookup'}`
      ).join('\n'),
    });
  }

  // If no sections matched, include everything available
  if (sections.length === 0) {
    // Re-gather ALL sources regardless of query
    if (auditLog.length > 0) sections.push({ source: 'Audit Log', count: auditLog.length, data: auditLog.slice(-20).map(e => `[${e.timestamp}] ${e.user || 'system'} ${e.action} ${e.resource || ''}`).join('\n') });
    if (scans.length > 0) sections.push({ source: 'Scans', count: scans.length, data: scans.slice(-10).map(s => `[${s.startedAt || s.timestamp}] ${s.type} ${s.target} ${s.status}`).join('\n') });
    if (threats.length > 0) sections.push({ source: 'Threats', count: threats.length, data: threats.slice(-10).map(t => `[${t.timestamp}] ${t.name || t.title} ${t.level}`).join('\n') });
    if (alerts.length > 0) sections.push({ source: 'Alerts', count: alerts.length, data: alerts.slice(-10).map(a => `[${a.timestamp}] ${a.severity} ${a.title || a.message}`).join('\n') });
    if (findings.length > 0) sections.push({ source: 'Findings', count: findings.length, data: 'Total: ' + findings.length + ' findings' });
    if (incidents.length > 0) sections.push({ source: 'Incidents', count: incidents.length, data: incidents.slice(-5).map(i => `[${i.timestamp}] ${i.title} ${i.status}`).join('\n') });
  }

  return sections;
}

// Known log sources (Linux only)
const LOG_SOURCES = [
  { name: 'auth.log', path: '/var/log/auth.log', description: 'Authentication and authorization events' },
  { name: 'syslog', path: '/var/log/syslog', description: 'General system messages' },
  { name: 'kern.log', path: '/var/log/kern.log', description: 'Kernel messages' },
  { name: 'messages', path: '/var/log/messages', description: 'General messages (CentOS/RHEL)' },
  { name: 'fail2ban.log', path: '/var/log/fail2ban.log', description: 'Fail2ban intrusion prevention' },
  { name: 'ufw.log', path: '/var/log/ufw.log', description: 'Firewall events' },
  { name: 'nginx/access.log', path: '/var/log/nginx/access.log', description: 'Nginx access log' },
  { name: 'nginx/error.log', path: '/var/log/nginx/error.log', description: 'Nginx error log' },
  { name: 'apache2/access.log', path: '/var/log/apache2/access.log', description: 'Apache access log' },
  { name: 'apache2/error.log', path: '/var/log/apache2/error.log', description: 'Apache error log' },
  { name: 'docker', path: null, description: 'Docker daemon logs (journalctl)' },
  { name: 'audit/audit.log', path: '/var/log/audit/audit.log', description: 'Linux audit framework' },
];

// Whitelist of safe read-only commands for log analysis
const SAFE_PREFIXES = ['grep', 'tail', 'head', 'cat', 'wc', 'sort', 'uniq', 'awk', 'sed', 'journalctl', 'zgrep', 'zcat', 'last', 'lastb', 'who'];

function isCommandSafe(cmd) {
  if (!cmd || typeof cmd !== 'string' || cmd.length > 500) return false;
  const first = cmd.trim().split(/\s+/)[0];
  if (!SAFE_PREFIXES.includes(first)) return false;
  const dangerous = ['rm', 'mv', 'cp', 'dd', 'mkfs', 'kill', 'reboot', 'shutdown', 'chmod', 'chown', 'chroot', 'mount', 'umount', 'fdisk', 'mkswap', 'swapon', 'swapoff', 'useradd', 'userdel', 'passwd', 'su', 'sudo', 'bash', 'sh', 'python', 'perl', 'ruby', 'node', 'curl', 'wget', 'nc', 'ncat', 'netcat'];
  for (const d of dangerous) {
    if (cmd.includes(' ' + d + ' ') || cmd.includes(' ' + d + '\n') || cmd.includes('|' + d) || cmd.includes('| ' + d)) return false;
  }
  if (/[>]|`|\$\(/.test(cmd)) return false;
  if (cmd.includes(';')) return false;
  if (cmd.includes('`') || cmd.includes('$(')) return false;
  const segments = cmd.split('|').map(s => s.trim());
  for (const seg of segments) {
    const segFirst = seg.split(/\s+/)[0];
    if (!SAFE_PREFIXES.includes(segFirst) && segFirst !== '2>/dev/null') return false;
  }
  return true;
}

module.exports = function (app, ctx) {
  const { requireAuth, requireRole, execCommand, askAI, askAIJSON } = ctx;

  // POST /api/logs/query — natural language security log query (cross-platform)
  app.post('/api/logs/query', requireRole('analyst'), async (req, res) => {
    try {
      const { query, source } = req.body;
      if (!query) return res.status(400).json({ error: 'query required' });

      // On Linux with system log source selected, try system logs first
      if (process.platform === 'linux' && source !== 'auto' && source !== 'vigil') {
        const result = await querySystemLogs(query, source, { execCommand, askAI });
        if (result) return res.json(result);
      }

      // Cross-platform: analyze Vigil's own security data stores
      const sections = gatherSecurityData(query);

      if (sections.length === 0) {
        return res.json({
          query: escapeHtml(query),
          command: 'Vigil Security Data Query',
          output: 'No security data found. Run some scans, investigate threats, or use other Vigil features to generate data.',
          analysis: 'The platform has no security events yet. Start by running a network scan, checking SSL certificates, or investigating a domain with OSINT to populate the security data stores.',
        });
      }

      // Build a context summary for AI
      const dataSummary = sections.map(s =>
        `=== ${s.source} (${s.count} records) ===\n${s.data}`
      ).join('\n\n');

      const totalRecords = sections.reduce((sum, s) => sum + s.count, 0);
      const sourceNames = sections.map(s => s.source).join(', ');

      // Build output (the "command" shows what data sources were queried)
      const outputLines = sections.map(s => `[${s.source}] ${s.count} records`).join('\n');

      // AI analysis
      let analysis = '';
      if (askAI) {
        try {
          const prompt = `You are a security operations analyst reviewing security event data from a SIEM-like platform called Vigil.

User's question: "${query}"

Data sources queried: ${sourceNames}
Total records: ${totalRecords}

Security Data:
${dataSummary.substring(0, 6000)}

Instructions:
- Directly answer the user's question using the data above
- Highlight any security concerns, patterns, or anomalies
- If the data shows threats, findings, or incidents, summarize the most critical ones
- Provide specific, actionable recommendations
- Be concise (4-6 sentences) but thorough
- No markdown formatting`;

          analysis = await askAI(prompt, { timeout: 30000 }) || '';
        } catch {}
      }

      res.json({
        query: escapeHtml(query),
        command: 'Queried ' + sections.length + ' data source' + (sections.length !== 1 ? 's' : '') + ': ' + sourceNames,
        output: outputLines + '\n\n' + dataSummary.substring(0, 5000),
        analysis: analysis || 'AI analysis unavailable. Configure an AI provider in Settings.',
        lineCount: totalRecords,
      });
    } catch (e) {
      console.error('[LOGS] Error:', e.message);
      res.status(500).json({ error: 'Operation failed' });
    }
  });

  // Helper: query Linux system logs (only on Linux)
  async function querySystemLogs(query, source, { execCommand, askAI }) {
    if (process.platform !== 'linux') return null;

    try {
      const translatePrompt = `You are a Linux system administrator. Convert this natural language log query into a safe, read-only shell command.

Query: "${query}"

Available log files: /var/log/auth.log, /var/log/syslog, /var/log/kern.log, /var/log/fail2ban.log, /var/log/ufw.log, /var/log/nginx/access.log, /var/log/nginx/error.log

Rules:
- Use ONLY read commands: grep, tail, head, cat, wc, sort, uniq, awk, sed, journalctl, zgrep, last
- NEVER use: rm, mv, cp, dd, chmod, reboot, shutdown
- NEVER redirect output to files (no >, >>)
- Add "2>/dev/null" to suppress permission errors
- Limit output: add "| tail -50" or "| head -50" if the output might be large
- Use journalctl for systemd services

Return ONLY the shell command, nothing else. No explanation, no markdown.`;

      let command;
      try {
        command = await askAI(translatePrompt, { timeout: 15000 });
        command = command.replace(/```[\s\S]*?```/g, '').replace(/`/g, '').trim();
        command = command.split('\n')[0].trim();
      } catch {
        return null;
      }

      if (!command || !isCommandSafe(command)) return null;

      let output = '';
      try {
        const result = await execCommand(command, { timeout: 30000 });
        output = (result.stdout || result.stderr || '').substring(0, 10000);
      } catch (e) {
        output = 'Command failed: ' + e.message;
      }

      let analysis = '';
      if (output && output.length > 0 && !output.startsWith('Command failed')) {
        try {
          const narratePrompt = `You are a security analyst. Briefly analyze these log results (3-5 sentences).

User asked: "${query}"
Command executed: ${command}

Output (first 3000 chars):
${output.substring(0, 3000)}

Summarize what the logs show. Highlight any security concerns. Be concise and actionable. No markdown.`;
          analysis = await askAI(narratePrompt, { timeout: 15000 }) || '';
        } catch {}
      }

      return {
        query: escapeHtml(query),
        command,
        output: output || 'No results found.',
        analysis: analysis || 'No analysis available.',
        lineCount: output ? output.split('\n').filter(Boolean).length : 0,
      };
    } catch {
      return null;
    }
  }

  // GET /api/logs/sources — available data sources
  app.get('/api/logs/sources', requireAuth, async (req, res) => {
    const sources = [
      { name: 'vigil', description: 'Vigil security data (audit log, scans, threats, alerts, findings)', readable: true },
    ];

    if (process.platform === 'linux') {
      for (const source of LOG_SOURCES) {
        if (source.path) {
          try {
            await fs.promises.access(source.path, fs.constants.R_OK);
            const stat = await fs.promises.stat(source.path);
            sources.push({
              ...source,
              size: stat.size,
              sizeHuman: stat.size > 1048576 ? Math.round(stat.size / 1048576) + 'MB' : Math.round(stat.size / 1024) + 'KB',
              lastModified: stat.mtime.toISOString(),
              readable: true,
            });
          } catch {
            sources.push({ ...source, readable: false });
          }
        } else {
          sources.push({ ...source, readable: true, note: 'Uses journalctl' });
        }
      }
    }

    res.json({ sources });
  });

  // GET /api/logs/tail — tail a log file (Linux only)
  app.get('/api/logs/tail', requireAuth, async (req, res) => {
    try {
      const file = req.query.file;
      const lines = Math.min(parseInt(req.query.lines) || 100, 500);

      if (!file) return res.status(400).json({ error: 'file parameter required' });

      if (process.platform === 'win32') {
        return res.json({ lines: ['Log tailing available on Linux only. Use the query endpoint for cross-platform analysis.'], file });
      }

      const knownSource = LOG_SOURCES.find(s => s.name === file || s.path === file);
      let logPath;

      if (knownSource && knownSource.path) {
        logPath = knownSource.path;
      } else if (file.startsWith('/var/log/') && !file.includes('..') && /^[a-zA-Z0-9_\-/.]+$/.test(file)) {
        try {
          const resolved = fs.realpathSync(file);
          if (!resolved.startsWith('/var/log/')) {
            return res.status(400).json({ error: 'Path escapes /var/log/ after symlink resolution' });
          }
          logPath = resolved;
        } catch {
          return res.status(400).json({ error: 'Log file not found or not accessible' });
        }
      } else if (file === 'docker') {
        try {
          const result = await execCommand(`journalctl -u docker --no-pager -n ${lines} 2>/dev/null`, { timeout: 10000 });
          return res.json({ lines: (result.stdout || 'No docker logs').split('\n'), file });
        } catch {
          return res.json({ lines: ['Docker logs not available'], file });
        }
      } else {
        return res.status(400).json({ error: 'Invalid or disallowed log file path' });
      }

      try {
        const { execFileSafe } = ctx;
        const result = await execFileSafe('tail', ['-n', String(lines), logPath], { timeout: 10000 });
        res.json({ lines: (result.stdout || 'No content').split('\n'), file });
      } catch {
        res.json({ lines: ['Could not read ' + escapeHtml(file)], file });
      }
    } catch (e) {
      console.error('[LOGS] Error:', e.message);
      res.status(500).json({ error: 'Operation failed' });
    }
  });
};
