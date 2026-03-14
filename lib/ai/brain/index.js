'use strict';
/**
 * Vigil AI Brain — Main Entry Point
 * Orchestrates KB lookup, prompt building, provider call, and memory extraction.
 */

const { buildSystemPrompt } = require('./system-prompt-builder');
const { searchKB, lookupById, lookupByMitre, lookupByCWE, lookupByPort, getStats: getKBStats } = require('./security-kb');
const { extractMemories } = require('./memory');
const { extractProfileUpdates, updateProfile, getOrCreateProfile } = require('./brain-profile');
const { matchIntent } = require('./action-catalog');

// Import the existing AI provider
const { askAI } = require('../../ai');

/**
 * Main brain chat function
 * Enriches AI calls with full brain context.
 *
 * @param {string} message - User's message
 * @param {object} options
 * @param {string} options.userId - User ID for profile/memory
 * @param {string} options.sectionContext - Current sidebar section ID
 * @param {Array} options.conversationHistory - Previous messages [{role, content}]
 * @returns {object} { response, sources, suggestedActions, memories, discoveryQuestion, profileCompletion }
 */
async function brainChat(message, options = {}) {
  const {
    userId = 'default',
    sectionContext,
    conversationHistory = [],
  } = options;

  // 1. Check if this is a pure KB lookup (no LLM needed)
  const directAnswer = tryDirectKBAnswer(message);
  if (directAnswer) {
    // Still extract memories async
    setImmediate(() => extractMemories(userId, message, directAnswer.response, sectionContext));
    return directAnswer;
  }

  // 2. Build enriched system prompt
  const promptCtx = await buildSystemPrompt({
    userId,
    currentSection: sectionContext,
    userQuery: message,
  });

  // 3. Build conversation with system prompt
  const fullPrompt = buildConversationPrompt(message, conversationHistory, promptCtx.systemPrompt);

  // 4. Call AI provider
  let response;
  try {
    response = await askAI(fullPrompt, {
      systemPrompt: promptCtx.systemPrompt,
      timeout: 60000,
    });
  } catch (err) {
    response = `I encountered an error processing your request: ${err.message}. Let me try to answer from my knowledge base instead.`;

    // Fall back to KB-only answer
    const kbFallback = searchKB(message, { maxResults: 3 });
    if (kbFallback.length) {
      response += '\n\nFrom Vigil Knowledge Base:\n';
      for (const entry of kbFallback) {
        response += `\n**[${entry.id}] ${entry.title}**\n${entry.content}\n`;
      }
    }
  }

  // 5. Extract profile updates from user message
  const profileUpdates = extractProfileUpdates(message);
  if (profileUpdates) {
    updateProfile(userId, profileUpdates);
  }

  // 6. Extract memories asynchronously (don't block response)
  setImmediate(() => {
    try {
      extractMemories(userId, message, response || '', sectionContext);
    } catch (e) {
      // Memory extraction is best-effort
    }
  });

  return {
    response: response || 'I was unable to generate a response. Please try rephrasing your question.',
    sources: promptCtx.kbHits,
    suggestedActions: promptCtx.suggestedActions,
    memories: promptCtx.memoriesUsed,
    discoveryQuestion: promptCtx.discoveryQuestion,
    profileCompletion: promptCtx.profileCompletion,
  };
}

/**
 * Try to answer directly from KB without calling LLM
 * Returns structured answer for specific lookup patterns
 */
function tryDirectKBAnswer(message) {
  if (!message) return null;

  // MITRE technique lookup: "T1059", "what is T1190"
  const mitreMatch = message.match(/\b(T\d{4}(?:\.\d{3})?)\b/);
  if (mitreMatch) {
    const entry = lookupByMitre(mitreMatch[1]);
    if (entry) {
      return formatKBDirectAnswer(entry, [entry]);
    }
  }

  // CWE lookup: "CWE-89", "what is CWE-79"
  const cweMatch = message.match(/\bCWE-?(\d+)\b/i);
  if (cweMatch) {
    const entries = lookupByCWE('CWE-' + cweMatch[1]);
    if (entries.length) {
      const response = entries.map(e =>
        `**[${e.id}] ${e.title}**\n${e.content}\n\nSeverity: ${e.severity || 'N/A'}\nMitigation: ${e.mitigation || 'See references'}`
      ).join('\n\n---\n\n');
      return {
        response,
        sources: entries,
        suggestedActions: [],
        memories: [],
        discoveryQuestion: null,
        profileCompletion: null,
        fromKB: true,
      };
    }
  }

  // Port lookup: "port 443", "what runs on port 22"
  const portMatch = message.match(/\bport\s+(\d+)\b/i);
  if (portMatch) {
    const entry = lookupByPort(parseInt(portMatch[1]));
    if (entry) {
      return formatKBDirectAnswer(entry, [entry]);
    }
  }

  // Specific KB ID lookup: "A01:2021", "NIST-AC-1"
  const idPatterns = [/\b(A\d{2}:\d{4})\b/, /\b(NIST-[A-Z]{2}-\d+)\b/, /\b(SEC-[\d.]+)\b/, /\b(COMP-\w+)\b/];
  for (const pattern of idPatterns) {
    const match = message.match(pattern);
    if (match) {
      const entry = lookupById(match[1]);
      if (entry) {
        return formatKBDirectAnswer(entry, [entry]);
      }
    }
  }

  return null; // No direct answer — needs LLM
}

function formatKBDirectAnswer(entry, sources) {
  let response = `**[KB: ${entry.id}] ${entry.title}**\n\n${entry.content}`;

  if (entry.severity) response += `\n\n**Severity:** ${entry.severity}`;
  if (entry.detection) response += `\n\n**Detection:** ${entry.detection}`;
  if (entry.mitigation) response += `\n\n**Mitigation:** ${entry.mitigation}`;
  if (entry.cweIds && entry.cweIds.length) response += `\n\n**CWEs:** ${entry.cweIds.join(', ')}`;
  if (entry.references && entry.references.length) response += `\n\n**References:** ${entry.references.join(', ')}`;

  // Add related entries
  const { getRelated } = require('./security-kb');
  const related = getRelated(entry.id);
  if (related.length) {
    response += `\n\n**Related:** ${related.map(r => `[${r.id}] ${r.title}`).join(', ')}`;
  }

  // Suggest relevant actions
  const actions = matchIntent(entry.title + ' ' + (entry.tags || []).join(' '));

  return {
    response,
    sources,
    suggestedActions: actions.slice(0, 3),
    memories: [],
    discoveryQuestion: null,
    profileCompletion: null,
    fromKB: true,
  };
}

/**
 * Build conversation prompt including history
 */
function buildConversationPrompt(message, history, systemPrompt) {
  // For providers that don't support conversation history,
  // we include recent history in the prompt
  const recentHistory = history.slice(-6); // Last 3 exchanges

  if (!recentHistory.length) return message;

  const historyText = recentHistory.map(m =>
    `${m.role === 'user' ? 'User' : 'Assistant'}: ${m.content}`
  ).join('\n\n');

  return `Previous conversation:\n${historyText}\n\nUser: ${message}`;
}

/**
 * Get brain stats (for dashboard/API)
 */
function getBrainStats(userId) {
  const profile = getOrCreateProfile(userId);
  const kbStats = getKBStats();
  const { getMemoryStats } = require('./memory');
  const memStats = getMemoryStats(userId);

  return {
    kb: kbStats,
    profile: {
      completion: profile.completion_score,
      industry: profile.threat_model.industry || null,
    },
    memory: memStats,
  };
}

module.exports = {
  brainChat,
  getBrainStats,
  tryDirectKBAnswer,
  searchKB,
  lookupById,
  lookupByMitre,
  lookupByCWE,
  lookupByPort,
};
