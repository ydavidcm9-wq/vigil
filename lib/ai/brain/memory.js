'use strict';
/**
 * Vigil AI Brain — Memory System
 * Stores and recalls security-relevant memories across conversations.
 * Persists to data/brain-memories.json.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const MEMORIES_FILE = path.join(__dirname, '..', '..', '..', 'data', 'brain-memories.json');
const MAX_MEMORIES_PER_USER = 500;

// Memory types
const MEMORY_TYPES = [
  'infrastructure_context',  // "user runs AWS EKS with 3 clusters"
  'finding_context',         // "found critical SQLi on api.example.com"
  'user_preference',         // "user prefers concise responses"
  'execution_evidence',      // "nuclei scan completed on 2026-03-10"
  'threat_note',             // "APT29 targeting healthcare sector"
  'remediation_status',      // "patched CVE-2024-1234 on prod"
];

function loadMemories() {
  try {
    if (fs.existsSync(MEMORIES_FILE)) {
      return JSON.parse(fs.readFileSync(MEMORIES_FILE, 'utf8'));
    }
  } catch {}
  return {};
}

function saveMemories(allMemories) {
  const dir = path.dirname(MEMORIES_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmp = MEMORIES_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(allMemories, null, 2));
  fs.renameSync(tmp, MEMORIES_FILE);
}

/**
 * Store a new memory (deduplicates by content hash)
 */
function storeMemory({ userId, type, content, confidence = 0.8, source = 'chat', relatedEntity, tags = [], expiresAt }) {
  if (!content || !userId) return null;

  const allMemories = loadMemories();
  if (!allMemories[userId]) allMemories[userId] = [];

  // Deduplicate by content hash
  const hash = crypto.createHash('sha1').update(content.toLowerCase().trim()).digest('hex').slice(0, 16);
  const existing = allMemories[userId].find(m => m.hash === hash);
  if (existing) {
    // Update confidence and timestamp if existing
    existing.confidence = Math.max(existing.confidence, confidence);
    existing.updated_at = new Date().toISOString();
    saveMemories(allMemories);
    return existing;
  }

  const memory = {
    id: crypto.randomUUID(),
    hash,
    user_id: userId,
    type: MEMORY_TYPES.includes(type) ? type : 'threat_note',
    content: content.trim(),
    confidence,
    source,
    related_entity: relatedEntity || null,
    tags,
    expires_at: expiresAt || null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  allMemories[userId].push(memory);

  // Enforce per-user limit (remove oldest low-confidence memories)
  if (allMemories[userId].length > MAX_MEMORIES_PER_USER) {
    allMemories[userId].sort((a, b) => b.confidence - a.confidence);
    allMemories[userId] = allMemories[userId].slice(0, MAX_MEMORIES_PER_USER);
  }

  saveMemories(allMemories);
  return memory;
}

/**
 * Recall relevant memories for a query
 * Uses keyword matching + type priority scoring
 */
function recallMemories(userId, query, options = {}) {
  const { types, maxResults = 5, minConfidence = 0.3 } = options;

  const allMemories = loadMemories();
  const userMemories = allMemories[userId] || [];

  if (!userMemories.length || !query) return [];

  const now = Date.now();
  const terms = query.toLowerCase().split(/\s+/).filter(t => t.length > 1);

  const scored = [];
  for (const memory of userMemories) {
    // Skip expired
    if (memory.expires_at && new Date(memory.expires_at).getTime() < now) continue;
    // Skip low confidence
    if (memory.confidence < minConfidence) continue;
    // Filter by type
    if (types && types.length && !types.includes(memory.type)) continue;

    let score = 0;
    const haystack = [memory.content, ...(memory.tags || [])].join(' ').toLowerCase();

    for (const term of terms) {
      if (haystack.includes(term)) {
        score += 3;
      }
    }

    // Boost by type priority
    const typePriority = {
      'infrastructure_context': 1.5,
      'user_preference': 1.4,
      'finding_context': 1.3,
      'threat_note': 1.2,
      'execution_evidence': 1.0,
      'remediation_status': 1.1,
    };
    score *= (typePriority[memory.type] || 1.0);

    // Boost by confidence
    score *= memory.confidence;

    // Recency boost (memories from last 7 days get 1.5x)
    const age = now - new Date(memory.created_at).getTime();
    if (age < 7 * 24 * 60 * 60 * 1000) score *= 1.5;
    else if (age < 30 * 24 * 60 * 60 * 1000) score *= 1.2;

    if (score > 0) {
      scored.push({ memory, score });
    }
  }

  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, maxResults).map(s => s.memory);
}

/**
 * Extract memories from conversation exchange (lightweight regex)
 * Called asynchronously after each brain chat response.
 */
function extractMemories(userId, userMessage, assistantResponse, sectionContext) {
  const extracted = [];
  const combined = userMessage + ' ' + assistantResponse;

  // Extract IP addresses mentioned
  const ips = combined.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
  if (ips) {
    for (const ip of [...new Set(ips)]) {
      // Skip common local/private IPs in generic text
      if (ip === '127.0.0.1' || ip === '0.0.0.0') continue;
      extracted.push({
        userId, type: 'infrastructure_context',
        content: `IP address mentioned: ${ip} (context: ${sectionContext || 'chat'})`,
        confidence: 0.6, source: 'chat', tags: ['ip', 'network'],
      });
    }
  }

  // Extract domains
  const domains = combined.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|org|net|io|dev|gov|edu|mil|co)\b/gi);
  if (domains) {
    for (const domain of [...new Set(domains)]) {
      // Skip common known domains
      if (['github.com', 'google.com', 'owasp.org', 'nist.gov', 'mitre.org', 'attack.mitre.org'].includes(domain.toLowerCase())) continue;
      extracted.push({
        userId, type: 'infrastructure_context',
        content: `Domain mentioned: ${domain}`,
        confidence: 0.6, source: 'chat', tags: ['domain', 'network'],
      });
    }
  }

  // Extract CVEs
  const cves = combined.match(/CVE-\d{4}-\d{4,}/g);
  if (cves) {
    for (const cve of [...new Set(cves)]) {
      extracted.push({
        userId, type: 'finding_context',
        content: `CVE discussed: ${cve}`,
        confidence: 0.7, source: 'chat', tags: ['cve', 'vulnerability'],
      });
    }
  }

  // Extract user preferences from user message
  const prefPatterns = [
    { pattern: /prefer\s+(concise|detailed|brief|verbose|executive)/i, type: 'user_preference' },
    { pattern: /i('m| am)\s+(?:a\s+)?(beginner|intermediate|expert|senior|junior)/i, type: 'user_preference' },
    { pattern: /we\s+use\s+(aws|gcp|azure|docker|kubernetes)/i, type: 'infrastructure_context' },
    { pattern: /our\s+(?:main\s+)?stack\s+(?:is|includes)\s+(.+)/i, type: 'infrastructure_context' },
    { pattern: /we\s+(?:need|require|follow)\s+(pci|hipaa|soc|iso|nist)/i, type: 'infrastructure_context' },
  ];

  for (const { pattern, type } of prefPatterns) {
    const match = userMessage.match(pattern);
    if (match) {
      extracted.push({
        userId, type,
        content: match[0],
        confidence: 0.9, source: 'user', tags: ['preference'],
      });
    }
  }

  // Store all extracted memories
  const stored = [];
  for (const mem of extracted) {
    const result = storeMemory(mem);
    if (result) stored.push(result);
  }

  return stored;
}

/**
 * Get all memories for a user
 */
function getMemories(userId, options = {}) {
  const { type, limit = 50 } = options;
  const allMemories = loadMemories();
  let userMemories = allMemories[userId] || [];

  if (type) {
    userMemories = userMemories.filter(m => m.type === type);
  }

  // Sort by created_at desc
  userMemories.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  return userMemories.slice(0, limit);
}

/**
 * Delete a specific memory
 */
function deleteMemory(userId, memoryId) {
  const allMemories = loadMemories();
  if (!allMemories[userId]) return false;

  const before = allMemories[userId].length;
  allMemories[userId] = allMemories[userId].filter(m => m.id !== memoryId);

  if (allMemories[userId].length < before) {
    saveMemories(allMemories);
    return true;
  }
  return false;
}

/**
 * Get memory stats for a user
 */
function getMemoryStats(userId) {
  const allMemories = loadMemories();
  const userMemories = allMemories[userId] || [];

  const byType = {};
  for (const m of userMemories) {
    byType[m.type] = (byType[m.type] || 0) + 1;
  }

  return {
    total: userMemories.length,
    byType,
    oldestMemory: userMemories.length ? userMemories.reduce((o, m) =>
      new Date(m.created_at) < new Date(o.created_at) ? m : o
    ).created_at : null,
    newestMemory: userMemories.length ? userMemories.reduce((n, m) =>
      new Date(m.created_at) > new Date(n.created_at) ? m : n
    ).created_at : null,
  };
}

module.exports = {
  MEMORY_TYPES,
  storeMemory,
  recallMemories,
  extractMemories,
  getMemories,
  deleteMemory,
  getMemoryStats,
};
