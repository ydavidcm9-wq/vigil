'use strict';
/**
 * Vigil AI Brain — System Prompt Builder
 * Dynamically assembles context-aware system prompts from all brain sources.
 * Respects token budget limits per provider.
 */

const { searchKB, getStats: getKBStats } = require('./security-kb');
const { getSectionContext } = require('./section-context');
const { getSuggestedActions, matchIntent } = require('./action-catalog');
const { getOrCreateProfile, getProfileSummary, getNextDiscoveryQuestion } = require('./brain-profile');
const { recallMemories } = require('./memory');

// Approximate tokens as chars/4
function estimateTokens(text) {
  return Math.ceil((text || '').length / 4);
}

function truncateToTokens(text, maxTokens) {
  const maxChars = maxTokens * 4;
  if (text.length <= maxChars) return text;
  return text.slice(0, maxChars - 3) + '...';
}

/**
 * Build a complete system prompt with all context sources
 */
async function buildSystemPrompt(ctx) {
  const {
    userId = 'default',
    currentSection,
    userQuery,
    maxTokenBudget = 3000,
    includeActions = true,
  } = ctx;

  const sections = [];
  let tokenCount = 0;

  // ── 1. Core Identity (~250 tokens) ─────────────────────────
  const coreIdentity = `You are Vigil, an expert AI security operations analyst with deep knowledge of:
- MITRE ATT&CK framework (all 14 tactics, 200+ techniques)
- OWASP Top 10 (Web & LLM), CWE taxonomy
- NIST CSF 2.0, NIST 800-53, CIS Controls v8
- CompTIA Security+ domains (network, threats, crypto, IAM, architecture, operations)
- PCI DSS 4.0, HIPAA, SOC 2, ISO 27001
- Penetration testing methodology, forensics, incident response
- NSA/CISA hardening guides and best practices

RULES:
- Be precise and actionable. Cite specific technique IDs (T1059), CVEs, CWEs, or control numbers.
- Never hallucinate. If unsure, say so. Use [KB] tags for knowledge base citations.
- Prioritize security — always assume an adversarial mindset when analyzing.
- Match the user's technical level and response style preferences.`;

  sections.push(coreIdentity);
  tokenCount += estimateTokens(coreIdentity);

  // ── 2. Profile Summary (~200 tokens) ───────────────────────
  const profile = getOrCreateProfile(userId);
  const profileSummary = getProfileSummary(profile);
  if (profileSummary !== 'No profile configured yet.') {
    const profileBlock = `\nUSER CONTEXT:\n${profileSummary}`;
    if (tokenCount + estimateTokens(profileBlock) < maxTokenBudget) {
      sections.push(profileBlock);
      tokenCount += estimateTokens(profileBlock);
    }
  }

  // ── 3. Section Context (~150 tokens) ───────────────────────
  if (currentSection) {
    const sectionCtx = getSectionContext(currentSection);
    if (sectionCtx) {
      const sectionBlock = `\nCURRENT SECTION: ${sectionCtx.name}
${sectionCtx.description}
Available capabilities: ${sectionCtx.capabilities.join(', ')}.`;
      if (tokenCount + estimateTokens(sectionBlock) < maxTokenBudget) {
        sections.push(sectionBlock);
        tokenCount += estimateTokens(sectionBlock);
      }
    }
  }

  // ── 4. KB Hits (~500 tokens) ────────────────────────────────
  const kbHits = [];
  if (userQuery) {
    // Search KB with section-relevant domains
    const sectionCtx = currentSection ? getSectionContext(currentSection) : null;
    const domains = sectionCtx ? sectionCtx.relatedKBDomains : undefined;

    const results = searchKB(userQuery, {
      domains: domains && domains.length ? domains : undefined,
      maxResults: 5,
    });

    // Also do a general search if domain-filtered results are sparse
    if (results.length < 3) {
      const generalResults = searchKB(userQuery, { maxResults: 5 });
      for (const r of generalResults) {
        if (!results.find(e => e.id === r.id)) {
          results.push(r);
        }
      }
    }

    if (results.length) {
      const kbLines = results.slice(0, 5).map(r => {
        const line = `[${r.id}] ${r.title}: ${truncateToTokens(r.content, 100)}`;
        kbHits.push(r);
        return line;
      });

      const kbBlock = `\nRELEVANT KNOWLEDGE:\n${kbLines.join('\n')}`;
      const kbTokens = estimateTokens(kbBlock);
      if (tokenCount + kbTokens < maxTokenBudget) {
        sections.push(kbBlock);
        tokenCount += kbTokens;
      } else {
        // Truncate KB to fit
        const available = maxTokenBudget - tokenCount - 50;
        if (available > 100) {
          sections.push(truncateToTokens(kbBlock, available));
          tokenCount += available;
        }
      }
    }
  }

  // ── 5. Recalled Memories (~300 tokens) ──────────────────────
  const memoriesUsed = [];
  if (userQuery) {
    const memories = recallMemories(userId, userQuery, { maxResults: 3 });
    if (memories.length) {
      const memLines = memories.map(m => {
        memoriesUsed.push(m);
        return `- [${m.type}] ${m.content}`;
      });

      const memBlock = `\nUSER MEMORY (from past interactions):\n${memLines.join('\n')}`;
      const memTokens = estimateTokens(memBlock);
      if (tokenCount + memTokens < maxTokenBudget) {
        sections.push(memBlock);
        tokenCount += memTokens;
      }
    }
  }

  // ── 6. Action Catalog (~200 tokens) ─────────────────────────
  const suggestedActions = [];
  if (includeActions) {
    // Match user intent
    let actions = [];
    if (userQuery) {
      actions = matchIntent(userQuery).slice(0, 3);
    }
    // Add section-relevant actions
    if (currentSection) {
      const sectionActions = getSuggestedActions(currentSection);
      for (const a of sectionActions) {
        if (!actions.find(e => e.id === a.id)) actions.push(a);
      }
    }
    actions = actions.slice(0, 5);

    if (actions.length) {
      const actionLines = actions.map(a => {
        suggestedActions.push(a);
        return `- ${a.name} → navigate to "${a.targetSection}" section`;
      });

      const actionBlock = `\nAVAILABLE ACTIONS (suggest these when relevant):\n${actionLines.join('\n')}`;
      const actionTokens = estimateTokens(actionBlock);
      if (tokenCount + actionTokens < maxTokenBudget) {
        sections.push(actionBlock);
        tokenCount += actionTokens;
      }
    }
  }

  // ── 7. Guardrails (~100 tokens) ─────────────────────────────
  const guardrails = `\nGUIDELINES:
- When citing KB entries, use format: [KB: ID] (e.g., [KB: T1059])
- Suggest navigation actions with format: **Go to: Section Name** when the user needs a specific tool
- If profile is incomplete, naturally ask about their infrastructure/compliance/threat model
- For scan/tool suggestions, always mention the specific Vigil section to use`;

  if (tokenCount + estimateTokens(guardrails) < maxTokenBudget) {
    sections.push(guardrails);
    tokenCount += estimateTokens(guardrails);
  }

  // ── Assemble ────────────────────────────────────────────────
  const systemPrompt = sections.join('\n');

  // Discovery question
  const discoveryQuestion = profile.completion_score < 100
    ? getNextDiscoveryQuestion(profile)
    : null;

  return {
    systemPrompt,
    kbHits,
    memoriesUsed,
    suggestedActions,
    discoveryQuestion: discoveryQuestion ? discoveryQuestion.question : null,
    tokenEstimate: estimateTokens(systemPrompt),
    profileCompletion: profile.completion_score,
  };
}

module.exports = { buildSystemPrompt };
