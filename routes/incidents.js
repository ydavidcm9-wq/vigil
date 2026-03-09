/**
 * Incidents Routes — Incident management with timeline and AI playbooks
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA = path.join(__dirname, '..', 'data');
const INCIDENTS_PATH = path.join(DATA, 'incidents.json');

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
  const { requireAuth, requireRole, requireAdmin, askAI } = ctx;

  // GET /api/incidents
  app.get('/api/incidents', requireAuth, (req, res) => {
    const incidents = readJSON(INCIDENTS_PATH, []);
    const severity = req.query.severity;
    const status = req.query.status;
    let filtered = incidents;
    if (severity) filtered = filtered.filter(i => i.severity === severity);
    if (status) filtered = filtered.filter(i => i.status === status);
    res.json({ incidents: filtered.reverse() });
  });

  // POST /api/incidents — create incident
  app.post('/api/incidents', requireRole('analyst'), (req, res) => {
    const { title, severity, description, type } = req.body;
    if (!title) return res.status(400).json({ error: 'title required' });

    const incident = {
      id: crypto.randomUUID(),
      title: escapeHtml(title),
      severity: severity || 'medium',
      description: escapeHtml(description || ''),
      type: type || 'security',
      status: 'open',
      timeline: [
        {
          id: crypto.randomUUID(),
          event: 'Incident created',
          detail: escapeHtml(description || 'No description provided'),
          timestamp: new Date().toISOString(),
          actor: req.user ? req.user.username : 'system',
        },
      ],
      assignee: null,
      createdAt: new Date().toISOString(),
      createdBy: req.user ? req.user.username : 'unknown',
      updatedAt: new Date().toISOString(),
    };

    const incidents = readJSON(INCIDENTS_PATH, []);
    incidents.push(incident);
    writeJSON(INCIDENTS_PATH, incidents);

    // Notify
    if (ctx.sendNotification) {
      ctx.sendNotification('security', `New ${severity} incident: ${title}`, 'incident');
    }

    res.json({ success: true, incident });
  });

  // GET /api/incidents/:id
  app.get('/api/incidents/:id', requireAuth, (req, res) => {
    const incidents = readJSON(INCIDENTS_PATH, []);
    const incident = incidents.find(i => i.id === req.params.id);
    if (!incident) return res.status(404).json({ error: 'Incident not found' });
    res.json(incident);
  });

  // PATCH /api/incidents/:id — update status/severity
  app.patch('/api/incidents/:id', requireRole('analyst'), (req, res) => {
    const incidents = readJSON(INCIDENTS_PATH, []);
    const incident = incidents.find(i => i.id === req.params.id);
    if (!incident) return res.status(404).json({ error: 'Incident not found' });

    const { status, severity, assignee, title, description } = req.body;
    const changes = [];

    if (status && ['open', 'investigating', 'contained', 'eradicated', 'recovered', 'closed'].includes(status)) {
      changes.push(`Status changed: ${incident.status} -> ${status}`);
      incident.status = status;
    }
    if (severity && ['low', 'medium', 'high', 'critical'].includes(severity)) {
      changes.push(`Severity changed: ${incident.severity} -> ${severity}`);
      incident.severity = severity;
    }
    if (assignee !== undefined) {
      changes.push(`Assigned to: ${assignee || 'unassigned'}`);
      incident.assignee = assignee;
    }
    if (title) { incident.title = escapeHtml(title); changes.push('Title updated'); }
    if (description) { incident.description = escapeHtml(description); changes.push('Description updated'); }

    if (changes.length > 0) {
      incident.timeline.push({
        id: crypto.randomUUID(),
        event: 'Incident updated',
        detail: changes.join('; '),
        timestamp: new Date().toISOString(),
        actor: req.user ? req.user.username : 'system',
      });
      incident.updatedAt = new Date().toISOString();
      if (status === 'closed') incident.closedAt = new Date().toISOString();
    }

    writeJSON(INCIDENTS_PATH, incidents);
    res.json({ success: true, incident });
  });

  // POST /api/incidents/:id/respond — AI incident response playbook
  app.post('/api/incidents/:id/respond', requireRole('analyst'), async (req, res) => {
    try {
      const incidents = readJSON(INCIDENTS_PATH, []);
      const incident = incidents.find(i => i.id === req.params.id);
      if (!incident) return res.status(404).json({ error: 'Incident not found' });

      const timelineText = incident.timeline.map(e =>
        `[${e.timestamp}] ${e.actor}: ${e.event} — ${e.detail}`
      ).join('\n');

      const prompt = `You are an incident response commander. Generate a response playbook for this security incident.

Incident:
- Title: ${incident.title}
- Severity: ${incident.severity}
- Type: ${incident.type}
- Status: ${incident.status}
- Description: ${incident.description}

Timeline:
${timelineText}

Generate an incident response playbook with these sections:
1. IMMEDIATE ACTIONS (first 30 minutes — 3-5 specific steps)
2. CONTAINMENT (how to isolate the threat — 2-3 steps)
3. INVESTIGATION (what evidence to collect — 3-4 steps with specific commands)
4. ERADICATION (how to remove the threat — 2-3 steps)
5. RECOVERY (how to restore normal operations — 2-3 steps)
6. LESSONS LEARNED (what to document — 2-3 items)

Be specific with exact commands where applicable. Tailor to the incident type. No markdown formatting.`;

      const playbook = await askAI(prompt, { timeout: 30000 });

      // Add playbook to timeline
      incident.timeline.push({
        id: crypto.randomUUID(),
        event: 'AI playbook generated',
        detail: 'Incident response playbook created by AI',
        timestamp: new Date().toISOString(),
        actor: 'vigil-ai',
      });
      incident.playbook = playbook || 'Playbook generation unavailable.';
      incident.updatedAt = new Date().toISOString();
      writeJSON(INCIDENTS_PATH, incidents);

      res.json({ playbook: incident.playbook });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/incidents/:id/timeline — add event to timeline
  app.post('/api/incidents/:id/timeline', requireRole('analyst'), (req, res) => {
    const incidents = readJSON(INCIDENTS_PATH, []);
    const incident = incidents.find(i => i.id === req.params.id);
    if (!incident) return res.status(404).json({ error: 'Incident not found' });

    const { event, detail } = req.body;
    if (!event) return res.status(400).json({ error: 'event required' });

    incident.timeline.push({
      id: crypto.randomUUID(),
      event: escapeHtml(event),
      detail: escapeHtml(detail || ''),
      timestamp: new Date().toISOString(),
      actor: req.user ? req.user.username : 'unknown',
    });
    incident.updatedAt = new Date().toISOString();

    writeJSON(INCIDENTS_PATH, incidents);
    res.json({ success: true });
  });
};
