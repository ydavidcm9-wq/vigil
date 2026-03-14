'use strict';
/**
 * Vigil AI Brain — API Routes
 * Brain chat, KB search, profile, memory, actions, section context
 */

module.exports = function (app, ctx) {
  const { requireAuth } = ctx;
  const brain = require('../lib/ai/brain');
  const { searchKB, lookupById, lookupByMitre, lookupByCWE, lookupByPort, getByDomain, getStats: getKBStats } = require('../lib/ai/brain/security-kb');
  const { getSectionContext, findSectionByQuery, getAllSectionIds } = require('../lib/ai/brain/section-context');
  const { matchIntent, getSuggestedActions, getActionsForSection } = require('../lib/ai/brain/action-catalog');
  const { getOrCreateProfile, updateProfile, getNextDiscoveryQuestion } = require('../lib/ai/brain/brain-profile');
  const { getMemories, storeMemory, deleteMemory, getMemoryStats } = require('../lib/ai/brain/memory');

  // ── Brain Chat ──────────────────────────────────────────────
  app.post('/api/brain/chat', requireAuth, async (req, res) => {
    try {
      const { message, sectionContext, conversationHistory } = req.body;
      if (!message || typeof message !== 'string') {
        return res.status(400).json({ error: 'message is required' });
      }

      const userId = req.user.username;
      const result = await brain.brainChat(message, {
        userId,
        sectionContext,
        conversationHistory: conversationHistory || [],
      });

      res.json({
        response: result.response,
        sources: (result.sources || []).map(s => ({ id: s.id, title: s.title, domain: s.domain, severity: s.severity })),
        suggestedActions: (result.suggestedActions || []).map(a => ({
          id: a.id, name: a.name, category: a.category, targetSection: a.targetSection,
        })),
        memories: (result.memories || []).map(m => ({ type: m.type, content: m.content })),
        discoveryQuestion: result.discoveryQuestion,
        profileCompletion: result.profileCompletion,
        fromKB: result.fromKB || false,
      });
    } catch (err) {
      console.error('Brain chat error:', err);
      res.status(500).json({ error: 'Brain chat failed: ' + err.message });
    }
  });

  // ── Knowledge Base Search ───────────────────────────────────
  app.get('/api/brain/kb/search', requireAuth, (req, res) => {
    const { q, domain, limit, severity } = req.query;
    if (!q) return res.status(400).json({ error: 'q (query) is required' });

    const results = searchKB(q, {
      domains: domain ? domain.split(',') : undefined,
      maxResults: parseInt(limit) || 10,
      severity: severity || undefined,
    });

    res.json({ query: q, count: results.length, results });
  });

  app.get('/api/brain/kb/lookup/:id', requireAuth, (req, res) => {
    const entry = lookupById(req.params.id);
    if (!entry) return res.status(404).json({ error: 'KB entry not found' });
    res.json(entry);
  });

  app.get('/api/brain/kb/mitre/:techniqueId', requireAuth, (req, res) => {
    const entry = lookupByMitre(req.params.techniqueId);
    if (!entry) return res.status(404).json({ error: 'MITRE technique not found' });
    res.json(entry);
  });

  app.get('/api/brain/kb/cwe/:cweId', requireAuth, (req, res) => {
    const cweId = req.params.cweId.startsWith('CWE-') ? req.params.cweId : 'CWE-' + req.params.cweId;
    const entries = lookupByCWE(cweId);
    res.json({ cweId, count: entries.length, entries });
  });

  app.get('/api/brain/kb/port/:port', requireAuth, (req, res) => {
    const port = parseInt(req.params.port);
    if (isNaN(port)) return res.status(400).json({ error: 'Invalid port number' });
    const entry = lookupByPort(port);
    if (!entry) return res.status(404).json({ error: 'Port not found in KB' });
    res.json(entry);
  });

  app.get('/api/brain/kb/stats', requireAuth, (req, res) => {
    res.json(getKBStats());
  });

  // ── Section Context ─────────────────────────────────────────
  app.get('/api/brain/sections', requireAuth, (req, res) => {
    res.json({ sections: getAllSectionIds() });
  });

  // search must come before :id param route
  app.get('/api/brain/sections/search', requireAuth, (req, res) => {
    const { q } = req.query;
    if (!q) return res.status(400).json({ error: 'q is required' });
    const sections = findSectionByQuery(q);
    res.json({ query: q, count: sections.length, sections: sections.slice(0, 5) });
  });

  app.get('/api/brain/sections/:id/context', requireAuth, (req, res) => {
    const ctx = getSectionContext(req.params.id);
    if (!ctx) {
      // Return generic context instead of 404 — panel stays useful
      return res.json({
        id: req.params.id,
        name: req.params.id.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
        group: 'other',
        description: 'Vigil security operations section.',
        capabilities: [],
        relatedKBDomains: [],
        relatedActions: [],
        helpPrompts: [
          'What can I do in this section?',
          'How do I improve my security posture?',
          'Show me recent findings',
        ],
        apiEndpoints: [],
      });
    }
    res.json(ctx);
  });

  // ── Action Matching ─────────────────────────────────────────
  app.post('/api/brain/actions/match', requireAuth, (req, res) => {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'message is required' });

    const actions = matchIntent(message);
    res.json({
      message,
      count: actions.length,
      actions: actions.slice(0, 5).map(a => ({
        id: a.id, name: a.name, category: a.category,
        targetSection: a.targetSection, riskLevel: a.riskLevel,
      })),
    });
  });

  app.get('/api/brain/actions/section/:sectionId', requireAuth, (req, res) => {
    const actions = getActionsForSection(req.params.sectionId);
    const suggested = getSuggestedActions(req.params.sectionId);
    res.json({
      sectionId: req.params.sectionId,
      actions: actions.map(a => ({ id: a.id, name: a.name, category: a.category })),
      suggested: suggested.map(a => ({ id: a.id, name: a.name, targetSection: a.targetSection })),
    });
  });

  // ── Brain Profile ───────────────────────────────────────────
  app.get('/api/brain/profile', requireAuth, (req, res) => {
    const userId = req.user.username;
    const profile = getOrCreateProfile(userId);
    res.json(profile);
  });

  app.put('/api/brain/profile', requireAuth, (req, res) => {
    const userId = req.user.username;
    const profile = updateProfile(userId, req.body);
    res.json(profile);
  });

  app.get('/api/brain/profile/next-question', requireAuth, (req, res) => {
    const userId = req.user.username;
    const profile = getOrCreateProfile(userId);
    const question = getNextDiscoveryQuestion(profile);
    res.json({
      completion: profile.completion_score,
      question: question ? question.question : null,
      field: question ? question.field : null,
      options: question ? question.options : null,
    });
  });

  // ── Brain Memory ────────────────────────────────────────────
  app.get('/api/brain/memories', requireAuth, (req, res) => {
    const userId = req.user.username;
    const { type, limit } = req.query;
    const memories = getMemories(userId, { type, limit: parseInt(limit) || 50 });
    res.json({ count: memories.length, memories });
  });

  app.post('/api/brain/memories', requireAuth, (req, res) => {
    const userId = req.user.username;
    const { type, content, tags, confidence } = req.body;
    if (!content) return res.status(400).json({ error: 'content is required' });

    const memory = storeMemory({
      userId, type: type || 'threat_note', content,
      tags: tags || [], confidence: confidence || 0.8,
      source: 'manual',
    });
    res.json(memory);
  });

  app.delete('/api/brain/memories/:id', requireAuth, (req, res) => {
    const userId = req.user.username;
    const deleted = deleteMemory(userId, req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Memory not found' });
    res.json({ deleted: true });
  });

  // ── Brain Stats ─────────────────────────────────────────────
  app.get('/api/brain/stats', requireAuth, (req, res) => {
    const userId = req.user.username;
    const stats = brain.getBrainStats(userId);
    res.json(stats);
  });

  console.log('  \u2713 Vigil AI Brain routes loaded');
};
