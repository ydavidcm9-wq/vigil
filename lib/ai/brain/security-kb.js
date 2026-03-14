'use strict';
/**
 * Vigil AI Brain — Security Knowledge Base
 * Unified search interface over all structured security knowledge.
 * All lookups are in-memory (<1ms) — no LLM or database needed.
 */

// KB data imports (lazy-loaded on first access)
let _allEntries = null;
let _byId = null;
let _byMitre = null;
let _byCWE = null;
let _byPort = null;
let _byDomain = null;

function loadAll() {
  if (_allEntries) return;

  const sources = [];

  // Load each KB data file safely
  const dataFiles = [
    { file: './kb-data/mitre-attack', key: 'MITRE_ATTACK' },
    { file: './kb-data/owasp-web', key: 'OWASP_WEB' },
    { file: './kb-data/cve-patterns', key: 'CVE_PATTERNS' },
    { file: './kb-data/nist-controls', key: 'NIST_CONTROLS' },
    { file: './kb-data/comptia-sec', key: 'COMPTIA_SEC' },
    { file: './kb-data/port-service-map', key: 'PORT_SERVICE_MAP' },
    { file: './kb-data/compliance-matrix', key: 'COMPLIANCE_MATRIX' },
    { file: './kb-data/remediation-patterns', key: 'REMEDIATION_PATTERNS' },
  ];

  for (const { file, key } of dataFiles) {
    try {
      const mod = require(file);
      if (mod[key] && Array.isArray(mod[key])) {
        sources.push(...mod[key]);
      }
    } catch (e) {
      // Data file not yet created — skip silently
    }
  }

  // Also import existing ai-security-kb.js (OWASP LLM, ATLAS, prompt injection)
  try {
    const aiSecKB = require('../../ai-security-kb');
    if (aiSecKB.OWASP_LLM_TOP10) {
      for (const entry of aiSecKB.OWASP_LLM_TOP10) {
        sources.push({
          id: entry.id,
          domain: 'owasp-llm',
          title: entry.name,
          content: entry.description,
          tags: [entry.category.toLowerCase(), 'llm', 'ai-security'],
          severity: entry.severity,
          references: entry.references || [],
          cweIds: entry.cwe || [],
          mitreIds: [],
          relatedIds: [],
          detection: (entry.mitigations || []).slice(0, 2).join('; '),
          mitigation: (entry.mitigations || []).join('; '),
        });
      }
    }
    if (aiSecKB.MITRE_ATLAS_TECHNIQUES) {
      for (const entry of aiSecKB.MITRE_ATLAS_TECHNIQUES) {
        sources.push({
          id: entry.id,
          domain: 'mitre-atlas',
          title: entry.name,
          content: entry.description,
          tags: [entry.tactic, 'ml', 'ai-security'],
          severity: entry.severity || 'medium',
          references: entry.references || [],
          cweIds: [],
          mitreIds: [entry.id],
          relatedIds: [],
          detection: '',
          mitigation: (entry.mitigations || []).join('; '),
        });
      }
    }
    if (aiSecKB.PROMPT_INJECTION_PATTERNS) {
      for (const entry of aiSecKB.PROMPT_INJECTION_PATTERNS) {
        sources.push({
          id: entry.id,
          domain: 'owasp-llm',
          title: entry.name,
          content: entry.description + (entry.example ? ' Example: ' + entry.example : ''),
          tags: ['prompt-injection', 'llm', 'ai-security'],
          severity: entry.severity || 'high',
          references: [],
          cweIds: ['CWE-77'],
          mitreIds: [],
          relatedIds: ['LLM01'],
          detection: entry.detection || '',
          mitigation: entry.mitigation || '',
        });
      }
    }
  } catch (e) {
    // ai-security-kb.js not available
  }

  _allEntries = sources;

  // Build indexes
  _byId = new Map();
  _byMitre = new Map();
  _byCWE = new Map();
  _byPort = new Map();
  _byDomain = new Map();

  for (const entry of _allEntries) {
    _byId.set(entry.id, entry);

    // MITRE index
    if (entry.mitreIds) {
      for (const mid of entry.mitreIds) {
        _byMitre.set(mid, entry);
      }
    }
    // Also index the entry id if it looks like a MITRE technique
    if (entry.id && /^T\d{4}/.test(entry.id)) {
      _byMitre.set(entry.id, entry);
    }

    // CWE index
    if (entry.cweIds) {
      for (const cid of entry.cweIds) {
        if (!_byCWE.has(cid)) _byCWE.set(cid, []);
        _byCWE.get(cid).push(entry);
      }
    }

    // Port index
    if (entry.port !== undefined) {
      _byPort.set(entry.port, entry);
    }

    // Domain index
    if (!_byDomain.has(entry.domain)) _byDomain.set(entry.domain, []);
    _byDomain.get(entry.domain).push(entry);
  }
}

/**
 * Search the knowledge base by query string
 * Uses keyword matching against title, content, tags, and IDs
 * @param {string} query
 * @param {object} options
 * @returns {Array} matching KB entries sorted by relevance
 */
function searchKB(query, options = {}) {
  loadAll();
  const { domains, maxResults = 10, severity } = options;

  if (!query || !_allEntries.length) return [];

  const terms = query.toLowerCase().split(/\s+/).filter(t => t.length > 1);
  if (!terms.length) return [];

  // Filter by domain if specified
  let candidates = _allEntries;
  if (domains && domains.length) {
    candidates = candidates.filter(e => domains.includes(e.domain));
  }
  if (severity) {
    candidates = candidates.filter(e => e.severity === severity);
  }

  // Score each entry
  const scored = [];
  for (const entry of candidates) {
    let score = 0;
    const haystack = [
      entry.id,
      entry.title,
      entry.content,
      ...(entry.tags || []),
      ...(entry.cweIds || []),
      ...(entry.mitreIds || []),
    ].join(' ').toLowerCase();

    for (const term of terms) {
      // Exact ID match is highest
      if (entry.id.toLowerCase() === term) {
        score += 100;
      }
      // Title match
      else if (entry.title.toLowerCase().includes(term)) {
        score += 10;
      }
      // Tag match
      else if ((entry.tags || []).some(t => t.includes(term))) {
        score += 8;
      }
      // CWE/MITRE ID match
      else if ((entry.cweIds || []).some(c => c.toLowerCase().includes(term)) ||
               (entry.mitreIds || []).some(m => m.toLowerCase().includes(term))) {
        score += 15;
      }
      // Content match
      else if (haystack.includes(term)) {
        score += 3;
      }
    }

    // Boost severity
    if (entry.severity === 'critical') score *= 1.3;
    else if (entry.severity === 'high') score *= 1.15;

    if (score > 0) {
      scored.push({ entry, score });
    }
  }

  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, maxResults).map(s => s.entry);
}

/**
 * Lookup a specific entry by its ID
 */
function lookupById(id) {
  loadAll();
  return _byId.get(id) || null;
}

/**
 * Lookup by MITRE ATT&CK technique ID (e.g., T1059)
 */
function lookupByMitre(techniqueId) {
  loadAll();
  return _byMitre.get(techniqueId) || null;
}

/**
 * Lookup all entries related to a CWE ID
 */
function lookupByCWE(cweId) {
  loadAll();
  const normalized = cweId.startsWith('CWE-') ? cweId : 'CWE-' + cweId;
  return _byCWE.get(normalized) || [];
}

/**
 * Lookup by port number
 */
function lookupByPort(port) {
  loadAll();
  return _byPort.get(Number(port)) || null;
}

/**
 * Get all entries for a domain
 */
function getByDomain(domain) {
  loadAll();
  return _byDomain.get(domain) || [];
}

/**
 * Get related entries for a given entry
 */
function getRelated(entryId) {
  loadAll();
  const entry = _byId.get(entryId);
  if (!entry || !entry.relatedIds) return [];
  return entry.relatedIds.map(rid => _byId.get(rid)).filter(Boolean);
}

/**
 * Get KB statistics
 */
function getStats() {
  loadAll();
  const domainCounts = {};
  for (const [domain, entries] of _byDomain) {
    domainCounts[domain] = entries.length;
  }
  return {
    totalEntries: _allEntries.length,
    domains: domainCounts,
    mitreCount: _byMitre.size,
    cweCount: _byCWE.size,
    portCount: _byPort.size,
  };
}

/**
 * Force reload (for testing or after data updates)
 */
function reload() {
  _allEntries = null;
  _byId = null;
  _byMitre = null;
  _byCWE = null;
  _byPort = null;
  _byDomain = null;
}

module.exports = {
  searchKB,
  lookupById,
  lookupByMitre,
  lookupByCWE,
  lookupByPort,
  getByDomain,
  getRelated,
  getStats,
  reload,
};
