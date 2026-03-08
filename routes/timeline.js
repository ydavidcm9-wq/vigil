/**
 * Timeline Routes — Unified security event timeline
 * Aggregates events from ALL data stores into a single chronological feed.
 * Powers the Attack Timeline view with time-range filtering, type filtering,
 * and AI-powered pattern analysis.
 */
const fs = require('fs');
const path = require('path');

const DATA = path.join(__dirname, '..', 'data');

function readJSON(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return fallback; }
}

// Parse time range string to milliseconds
function rangeToMs(range) {
  const map = { '1h': 3600000, '6h': 21600000, '24h': 86400000, '7d': 604800000, '30d': 2592000000 };
  return map[range] || 86400000; // default 24h
}

module.exports = function (app, ctx) {
  const { requireAuth, askAI } = ctx;

  // ═══════════════════════════════════════════════════════════════════════
  // GET /api/timeline — Unified security event timeline
  // Query: range=1h|6h|24h|7d|30d, type=all|scan|finding|threat|incident|alert|auth|hunt|osint
  // ═══════════════════════════════════════════════════════════════════════
  app.get('/api/timeline', requireAuth, (req, res) => {
    try {
      const range = req.query.range || '24h';
      const typeFilter = (req.query.type || 'all').toLowerCase();
      const cutoff = Date.now() - rangeToMs(range);
      const events = [];

      // Helper: push event if within time range and type filter
      function addEvent(ev) {
        const ts = new Date(ev.timestamp).getTime();
        if (isNaN(ts) || ts < cutoff) return;
        if (typeFilter !== 'all' && ev.type !== typeFilter) return;
        events.push(ev);
      }

      // ── 1. Scans (scan started/completed) ────────────────────────
      const scans = readJSON(path.join(DATA, 'scans.json'), []);
      for (const scan of scans) {
        // Scan completion event
        const completedAt = scan.completedAt || scan.createdAt;
        if (completedAt) {
          addEvent({
            type: 'scan',
            severity: 'info',
            title: (scan.type || 'scan').toUpperCase() + ' scan completed',
            description: 'Target: ' + (scan.target || 'unknown') + ' — ' + (scan.findingsCount || 0) + ' findings',
            details: scan.findingsCount > 0
              ? scan.findingsCount + ' vulnerabilities found on ' + (scan.target || 'unknown')
              : 'Clean scan on ' + (scan.target || 'unknown'),
            timestamp: completedAt,
            source: scan.type || 'scanner',
          });
        }

        // Individual findings as events
        if (scan.findings && Array.isArray(scan.findings)) {
          for (const f of scan.findings) {
            const sev = (f.severity || 'info').toLowerCase();
            addEvent({
              type: 'finding',
              severity: sev,
              title: f.title || f.name || 'Unnamed vulnerability',
              description: (f.description || '').substring(0, 200),
              details: 'Target: ' + (f.target || f.matched_at || scan.target || 'unknown') +
                (f.cve_id ? ' | CVE: ' + f.cve_id : '') +
                (f.template_id ? ' | Template: ' + f.template_id : ''),
              timestamp: scan.completedAt || scan.createdAt || new Date().toISOString(),
              source: scan.type || 'scan',
            });
          }
        }
      }

      // ── 2. Threats ───────────────────────────────────────────────
      const threats = readJSON(path.join(DATA, 'threats.json'), []);
      for (const t of threats) {
        addEvent({
          type: 'threat',
          severity: (t.severity || 'high').toLowerCase(),
          title: t.title || 'Threat detected',
          description: t.details || t.description || '',
          details: 'Source: ' + (t.source || 'unknown') + ' | Status: ' + (t.status || 'active'),
          timestamp: t.detectedAt || t.timestamp || t.created_at,
          source: t.source || 'threat-intel',
        });
      }

      // ── 3. Alerts ────────────────────────────────────────────────
      const alerts = readJSON(path.join(DATA, 'alerts.json'), []);
      for (const a of alerts) {
        addEvent({
          type: 'alert',
          severity: (a.severity || 'medium').toLowerCase(),
          title: a.title || a.description || 'Alert triggered',
          description: a.description || '',
          details: 'Source: ' + (a.source || 'unknown') + ' | Status: ' + (a.status || 'pending') +
            (a.verdict ? ' | Verdict: ' + a.verdict : ''),
          timestamp: a.created_at || a.timestamp,
          source: a.source || 'alert-engine',
        });
      }

      // ── 4. Incidents ─────────────────────────────────────────────
      const incidents = readJSON(path.join(DATA, 'incidents.json'), []);
      for (const inc of incidents) {
        addEvent({
          type: 'incident',
          severity: (inc.severity || 'medium').toLowerCase(),
          title: 'Incident: ' + (inc.title || 'Unnamed'),
          description: inc.description || '',
          details: 'Status: ' + (inc.status || 'open') + ' | Type: ' + (inc.type || 'security') +
            (inc.assignee ? ' | Assigned: ' + inc.assignee : ''),
          timestamp: inc.createdAt || inc.created_at,
          source: 'incident-response',
        });
        // Also include incident timeline sub-events
        if (inc.timeline && Array.isArray(inc.timeline)) {
          for (const te of inc.timeline) {
            if (te.event === 'Incident created') continue; // skip dupe
            addEvent({
              type: 'incident',
              severity: (inc.severity || 'medium').toLowerCase(),
              title: te.event + ' — ' + (inc.title || ''),
              description: te.detail || '',
              details: 'Actor: ' + (te.actor || 'system'),
              timestamp: te.timestamp,
              source: 'incident-response',
            });
          }
        }
      }

      // ── 5. Hunts ─────────────────────────────────────────────────
      const hunts = readJSON(path.join(DATA, 'hunts.json'), []);
      for (const h of hunts) {
        const verdict = (h.verdict || 'inconclusive').toLowerCase();
        addEvent({
          type: 'hunt',
          severity: verdict === 'confirmed' ? 'critical' : verdict === 'clear' ? 'info' : 'medium',
          title: 'Threat Hunt: ' + (h.query || 'Unknown'),
          description: (h.analysis || '').substring(0, 200),
          details: 'Verdict: ' + verdict.toUpperCase() +
            (h.evidence ? ' | Evidence sources: ' + h.evidence.length : ''),
          timestamp: h.timestamp || h.created_at,
          source: 'threat-hunting',
        });
      }

      // ── 6. Audit log (auth events, triage actions) ───────────────
      const auditLog = readJSON(path.join(DATA, 'audit-log.json'), []);
      for (const entry of auditLog) {
        // Map audit actions to event types
        const action = entry.action || '';
        let evType = 'auth';
        let evSeverity = 'info';
        let evTitle = action;

        if (action.includes('login')) {
          evTitle = 'User login: ' + (entry.user || 'unknown');
          evSeverity = 'info';
        } else if (action.includes('logout')) {
          evTitle = 'User logout: ' + (entry.user || 'unknown');
          evSeverity = 'info';
        } else if (action.includes('triage')) {
          evTitle = 'Alert triaged by ' + (entry.user || 'unknown');
          evSeverity = 'medium';
          if (entry.details && entry.details.verdict) {
            evTitle += ' — ' + entry.details.verdict;
          }
        } else if (action.includes('scan')) {
          evType = 'scan';
          evTitle = 'Scan initiated by ' + (entry.user || 'unknown');
        } else if (action.includes('incident')) {
          evType = 'incident';
          evTitle = 'Incident action by ' + (entry.user || 'unknown');
        } else {
          evTitle = action + ' by ' + (entry.user || 'unknown');
        }

        addEvent({
          type: evType,
          severity: evSeverity,
          title: evTitle,
          description: entry.resource || '',
          details: action,
          timestamp: entry.timestamp,
          source: 'audit-log',
        });
      }

      // ── 7. OSINT lookups ─────────────────────────────────────────
      const osintHistory = readJSON(path.join(DATA, 'osint-history.json'), []);
      for (const o of osintHistory) {
        addEvent({
          type: 'osint',
          severity: 'info',
          title: 'OSINT ' + (o.type || 'lookup') + ': ' + (o.target || o.query || 'unknown'),
          description: (o.summary || '').substring(0, 200),
          details: '',
          timestamp: o.created_at || o.timestamp,
          source: 'osint',
        });
      }

      // ── Sort by timestamp descending (most recent first) ────────
      events.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

      // ── Cap results ──────────────────────────────────────────────
      const maxEvents = 200;
      const total = events.length;
      const trimmed = events.slice(0, maxEvents);

      // ── Event type counts ────────────────────────────────────────
      const counts = {};
      for (const ev of events) {
        counts[ev.type] = (counts[ev.type] || 0) + 1;
      }

      // ── Severity distribution ────────────────────────────────────
      const severities = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const ev of events) {
        const sev = (ev.severity || 'info').toLowerCase();
        if (severities.hasOwnProperty(sev)) severities[sev]++;
        else severities.info++;
      }

      res.json({
        events: trimmed,
        total,
        range,
        typeFilter,
        counts,
        severities,
      });
    } catch (e) {
      console.error('[Timeline] Error:', e.message);
      res.status(500).json({ error: 'Failed to build timeline' });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // POST /api/timeline/analyze — AI analysis of timeline events
  // ═══════════════════════════════════════════════════════════════════════
  app.post('/api/timeline/analyze', requireAuth, async (req, res) => {
    try {
      if (!askAI) return res.json({ analysis: 'AI provider not configured. Go to Settings > AI Provider.' });

      const { events, range } = req.body;
      if (!events || !Array.isArray(events) || events.length === 0) {
        return res.json({ analysis: 'No events to analyze.' });
      }

      // Build a summary of events for AI
      const eventSummary = events.slice(0, 50).map(e =>
        `[${e.timestamp}] ${(e.severity || 'info').toUpperCase()} ${e.type}: ${e.title}`
      ).join('\n');

      // Count by type/severity
      const typeCounts = {};
      const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const e of events) {
        typeCounts[e.type] = (typeCounts[e.type] || 0) + 1;
        const sev = (e.severity || 'info').toLowerCase();
        if (sevCounts.hasOwnProperty(sev)) sevCounts[sev]++;
      }

      const prompt = `You are a security operations analyst reviewing a ${range || '24h'} attack timeline. Analyze these ${events.length} security events and provide:

1. SITUATION SUMMARY (2-3 sentences — what happened)
2. PATTERN ANALYSIS (are there attack patterns, correlated events, or suspicious sequences?)
3. CRITICAL ITEMS (list the most concerning events requiring immediate attention)
4. RISK ASSESSMENT (overall risk level and trajectory — is the environment getting safer or more exposed?)
5. RECOMMENDED ACTIONS (3-5 specific, prioritized steps)

Event Distribution:
${Object.entries(typeCounts).map(([k, v]) => '- ' + k + ': ' + v).join('\n')}

Severity Breakdown:
- Critical: ${sevCounts.critical}, High: ${sevCounts.high}, Medium: ${sevCounts.medium}, Low: ${sevCounts.low}, Info: ${sevCounts.info}

Recent Events (newest first):
${eventSummary}

Be specific about which events are concerning and why. Reference specific event titles. No markdown formatting.`;

      const analysis = await askAI(prompt, { timeout: 25000 });
      res.json({ analysis: analysis || 'Analysis unavailable.' });
    } catch (e) {
      console.error('[Timeline] AI error:', e.message);
      res.status(500).json({ error: 'AI analysis failed' });
    }
  });
};
