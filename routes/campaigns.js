/**
 * Campaigns Routes — Multi-agent campaigns
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA = path.join(__dirname, '..', 'data');
const CAMPAIGNS_PATH = path.join(DATA, 'campaigns.json');
const AGENTS_PATH = path.join(DATA, 'agents.json');
const RUNS_PATH = path.join(DATA, 'agent-runs.json');

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

function escapeHtml(s) { return String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }

// Track running campaigns to support stop
const runningCampaigns = new Map();

module.exports = function (app, ctx) {
  const { requireAuth, requireRole, askAI } = ctx;

  // Select relevant agents for a goal
  function selectAgents(goal, maxAgents) {
    const agents = readJSON(AGENTS_PATH, []);
    const enabled = agents.filter(a => a.enabled);
    const goalLower = goal.toLowerCase();

    // Keyword matching per category
    const categoryKeywords = {
      recon: ['scan', 'port', 'discover', 'enumerate', 'subdomain', 'reconnaissance', 'surface'],
      appsec: ['web', 'app', 'xss', 'sql', 'injection', 'header', 'api', 'application'],
      cloud: ['aws', 'gcp', 'azure', 'cloud', 's3', 'iam', 'bucket', 'container'],
      iam: ['user', 'password', 'auth', 'access', 'identity', 'permission', 'privilege'],
      compliance: ['comply', 'compliance', 'pci', 'hipaa', 'soc', 'audit', 'regulation'],
      'incident-response': ['incident', 'breach', 'respond', 'playbook', 'contain', 'recover'],
      'threat-hunting': ['hunt', 'threat', 'ioc', 'compromise', 'anomaly', 'suspicious', 'malware'],
      forensics: ['forensic', 'evidence', 'memory', 'disk', 'artifact', 'investigate'],
      network: ['network', 'firewall', 'tls', 'ssl', 'dns', 'port', 'connection'],
      'data-security': ['data', 'sensitive', 'pii', 'classify', 'encrypt', 'leak'],
    };

    // Score each agent
    const scored = enabled.map(agent => {
      let score = 0;
      const keywords = categoryKeywords[agent.category] || [];
      for (const kw of keywords) {
        if (goalLower.includes(kw)) score += 2;
      }
      // Name/description match
      if (goalLower.includes(agent.name.toLowerCase())) score += 5;
      const descWords = (agent.description || '').toLowerCase().split(/\s+/);
      for (const word of descWords) {
        if (word.length > 3 && goalLower.includes(word)) score += 1;
      }
      return { agent, score };
    });

    scored.sort((a, b) => b.score - a.score);
    return scored.slice(0, maxAgents).filter(s => s.score > 0).map(s => s.agent);
  }

  // POST /api/campaigns — launch campaign
  app.post('/api/campaigns', requireRole('analyst'), async (req, res) => {
    try {
      const { goal, max_agents } = req.body;
      if (!goal) return res.status(400).json({ error: 'goal required' });
      const maxAgents = Math.min(parseInt(max_agents) || 5, 10);

      const selectedAgents = selectAgents(goal, maxAgents);
      if (selectedAgents.length === 0) {
        return res.status(400).json({ error: 'No matching agents found for this goal. Try a more specific description.' });
      }

      const campaign = {
        id: crypto.randomUUID(),
        goal: escapeHtml(goal),
        maxAgents,
        status: 'running',
        agents: selectedAgents.map(a => ({ id: a.id, name: a.name, category: a.category, status: 'pending' })),
        runs: [],
        createdAt: new Date().toISOString(),
        createdBy: req.user ? req.user.user : 'unknown',
      };

      const campaigns = readJSON(CAMPAIGNS_PATH, []);
      campaigns.push(campaign);
      writeJSON(CAMPAIGNS_PATH, campaigns);

      // Run agents sequentially in background
      let stopped = false;
      runningCampaigns.set(campaign.id, { stop: () => { stopped = true; } });

      (async () => {
        for (let i = 0; i < selectedAgents.length; i++) {
          if (stopped) break;

          const agent = selectedAgents[i];
          campaign.agents[i].status = 'running';

          // Save progress
          const allCampaigns = readJSON(CAMPAIGNS_PATH, []);
          const idx = allCampaigns.findIndex(c => c.id === campaign.id);
          if (idx >= 0) allCampaigns[idx] = campaign;
          writeJSON(CAMPAIGNS_PATH, allCampaigns);

          try {
            const prompt = agent.system_prompt + '\n\n' + agent.task_prompt.replace(/\{\{input\}\}/g, goal);
            const output = await askAI(prompt, { timeout: 60000 });

            const run = {
              id: crypto.randomUUID(),
              agentId: agent.id,
              agentName: agent.name,
              campaignId: campaign.id,
              input: goal.substring(0, 500),
              output: output || 'No output',
              status: 'completed',
              createdAt: new Date().toISOString(),
            };
            campaign.runs.push(run);
            campaign.agents[i].status = 'completed';

            // Also save to global runs
            const runs = readJSON(RUNS_PATH, []);
            runs.push(run);
            if (runs.length > 1000) runs.splice(0, runs.length - 1000);
            writeJSON(RUNS_PATH, runs);
          } catch (e) {
            campaign.agents[i].status = 'failed';
            campaign.runs.push({
              id: crypto.randomUUID(),
              agentId: agent.id,
              agentName: agent.name,
              campaignId: campaign.id,
              input: goal.substring(0, 500),
              output: 'Error: ' + e.message,
              status: 'failed',
              createdAt: new Date().toISOString(),
            });
          }
        }

        campaign.status = stopped ? 'stopped' : 'completed';
        campaign.completedAt = new Date().toISOString();
        runningCampaigns.delete(campaign.id);

        const allCampaigns = readJSON(CAMPAIGNS_PATH, []);
        const idx = allCampaigns.findIndex(c => c.id === campaign.id);
        if (idx >= 0) allCampaigns[idx] = campaign;
        writeJSON(CAMPAIGNS_PATH, allCampaigns);

        if (ctx.io) ctx.io.emit('campaign_complete', { id: campaign.id, status: campaign.status });
      })();

      res.json({ campaign: { id: campaign.id, goal: campaign.goal, status: campaign.status, agentCount: selectedAgents.length } });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/campaigns
  app.get('/api/campaigns', requireAuth, (req, res) => {
    const campaigns = readJSON(CAMPAIGNS_PATH, []);
    res.json({
      campaigns: campaigns.map(c => ({
        id: c.id, goal: c.goal, status: c.status,
        agentCount: c.agents ? c.agents.length : 0,
        runCount: c.runs ? c.runs.length : 0,
        createdAt: c.createdAt, completedAt: c.completedAt,
      })).reverse(),
    });
  });

  // GET /api/campaigns/:id
  app.get('/api/campaigns/:id', requireAuth, (req, res) => {
    const campaigns = readJSON(CAMPAIGNS_PATH, []);
    const campaign = campaigns.find(c => c.id === req.params.id);
    if (!campaign) return res.status(404).json({ error: 'Campaign not found' });
    res.json(campaign);
  });

  // POST /api/campaigns/:id/stop
  app.post('/api/campaigns/:id/stop', requireRole('analyst'), (req, res) => {
    const running = runningCampaigns.get(req.params.id);
    if (!running) return res.status(400).json({ error: 'Campaign is not running' });
    running.stop();
    runningCampaigns.delete(req.params.id);
    res.json({ success: true, message: 'Campaign stop signal sent' });
  });
};
