'use strict';
/**
 * Vigil AI Brain — Brain Profile
 * Security-focused user profile with progressive discovery.
 * Persists to data/brain-profiles.json.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PROFILES_FILE = path.join(__dirname, '..', '..', '..', 'data', 'brain-profiles.json');

// Discovery questions ordered by priority (highest weight first)
const DISCOVERY_QUESTIONS = [
  {
    field: 'infrastructure.cloud_providers',
    question: 'What cloud providers does your infrastructure use? (AWS, GCP, Azure, on-prem, hybrid)',
    type: 'multi-select',
    options: ['aws', 'gcp', 'azure', 'on-prem', 'hybrid', 'none'],
    weight: 12,
  },
  {
    field: 'threat_model.industry',
    question: 'What industry is your organization in? (fintech, healthcare, SaaS, government, retail, education, etc.)',
    type: 'text',
    weight: 11,
  },
  {
    field: 'threat_model.data_sensitivity',
    question: 'What is the sensitivity level of your most critical data? (public, internal, confidential, restricted)',
    type: 'select',
    options: ['public', 'internal', 'confidential', 'restricted'],
    weight: 10,
  },
  {
    field: 'compliance.frameworks',
    question: 'Which compliance frameworks apply to you? (PCI DSS, HIPAA, SOC 2, ISO 27001, NIST CSF, CIS, none)',
    type: 'multi-select',
    options: ['pci-dss', 'hipaa', 'soc2', 'iso27001', 'nist-csf', 'cis', 'none'],
    weight: 10,
  },
  {
    field: 'infrastructure.primary_stack',
    question: 'What is your primary tech stack? (Node.js, Python, Java, Go, .NET, PHP, Ruby, etc.)',
    type: 'multi-select',
    weight: 9,
  },
  {
    field: 'threat_model.crown_jewels',
    question: 'What are your most critical assets (crown jewels)? (customer PII, payment data, IP, credentials, health records, etc.)',
    type: 'multi-select',
    weight: 9,
  },
  {
    field: 'threat_model.attack_surface',
    question: 'Describe your attack surface: internet-facing, hybrid (some internal/some external), or purely internal?',
    type: 'select',
    options: ['internet-facing', 'hybrid', 'internal'],
    weight: 8,
  },
  {
    field: 'team.security_maturity',
    question: 'How would you rate your security program maturity? (ad-hoc, developing, managed, optimized)',
    type: 'select',
    options: ['ad-hoc', 'developing', 'managed', 'optimized'],
    weight: 8,
  },
  {
    field: 'infrastructure.container_runtime',
    question: 'Do you use containers? (Docker, Kubernetes, ECS, EKS, none)',
    type: 'select',
    options: ['docker', 'kubernetes', 'ecs', 'eks', 'none'],
    weight: 7,
  },
  {
    field: 'infrastructure.domains',
    question: 'What are your primary domains to monitor? (comma-separated)',
    type: 'text-list',
    weight: 7,
  },
  {
    field: 'threat_model.threat_actors',
    question: 'Which threat actors are most relevant? (nation-state, cybercrime, insider, hacktivist, competitor)',
    type: 'multi-select',
    options: ['nation-state', 'cybercrime', 'insider', 'hacktivist', 'competitor'],
    weight: 6,
  },
  {
    field: 'team.size',
    question: 'How large is your security team? (solo, small 2-5, medium 6-20, large 20+)',
    type: 'select',
    options: ['solo', 'small', 'medium', 'large'],
    weight: 5,
  },
  {
    field: 'preferences.technical_level',
    question: 'What technical depth do you prefer? (beginner — explain everything, intermediate, expert — skip basics)',
    type: 'select',
    options: ['beginner', 'intermediate', 'expert'],
    weight: 5,
  },
  {
    field: 'preferences.response_style',
    question: 'How should I format responses? (concise — bullets and short answers, detailed — full explanations, executive — business-focused)',
    type: 'select',
    options: ['concise', 'detailed', 'executive'],
    weight: 4,
  },
  {
    field: 'infrastructure.ci_cd',
    question: 'What CI/CD do you use? (GitHub Actions, Jenkins, GitLab CI, CircleCI, etc.)',
    type: 'multi-select',
    weight: 3,
  },
];

function createDefaultProfile(userId) {
  return {
    id: crypto.randomUUID(),
    user_id: userId,
    completion_score: 0,
    infrastructure: {
      cloud_providers: [],
      primary_stack: [],
      container_runtime: '',
      ci_cd: [],
      domains: [],
      ip_ranges: [],
    },
    compliance: {
      frameworks: [],
      audit_cycle: '',
      last_audit_date: null,
      certifications: [],
    },
    threat_model: {
      industry: '',
      data_sensitivity: '',
      threat_actors: [],
      crown_jewels: [],
      attack_surface: '',
    },
    team: {
      size: '',
      security_maturity: '',
      roles: [],
    },
    preferences: {
      response_style: 'concise',
      technical_level: 'intermediate',
      auto_scan: false,
      notification_level: 'high-and-above',
    },
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
}

function loadProfiles() {
  try {
    if (fs.existsSync(PROFILES_FILE)) {
      return JSON.parse(fs.readFileSync(PROFILES_FILE, 'utf8'));
    }
  } catch {}
  return {};
}

function saveProfiles(profiles) {
  const dir = path.dirname(PROFILES_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmp = PROFILES_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(profiles, null, 2));
  fs.renameSync(tmp, PROFILES_FILE);
}

/**
 * Get or create a brain profile for a user
 */
function getOrCreateProfile(userId) {
  const profiles = loadProfiles();
  if (profiles[userId]) return profiles[userId];

  const profile = createDefaultProfile(userId);
  profiles[userId] = profile;
  saveProfiles(profiles);
  return profile;
}

/**
 * Update profile fields (deep merge)
 */
function updateProfile(userId, patch) {
  const profiles = loadProfiles();
  const profile = profiles[userId] || createDefaultProfile(userId);

  // Deep merge patch into profile
  for (const [section, value] of Object.entries(patch)) {
    if (typeof value === 'object' && value !== null && !Array.isArray(value) && profile[section]) {
      Object.assign(profile[section], value);
    } else {
      profile[section] = value;
    }
  }

  profile.completion_score = calculateCompletionScore(profile);
  profile.updated_at = new Date().toISOString();
  profiles[userId] = profile;
  saveProfiles(profiles);
  return profile;
}

/**
 * Calculate profile completion score (0-100)
 */
function calculateCompletionScore(profile) {
  let earned = 0;
  let total = 0;

  for (const q of DISCOVERY_QUESTIONS) {
    total += q.weight;
    const value = getNestedValue(profile, q.field);
    if (value && (Array.isArray(value) ? value.length > 0 : value !== '')) {
      earned += q.weight;
    }
  }

  return total > 0 ? Math.round((earned / total) * 100) : 0;
}

/**
 * Get the next unanswered discovery question (highest weight first)
 */
function getNextDiscoveryQuestion(profile) {
  // Sort by weight descending
  const sorted = [...DISCOVERY_QUESTIONS].sort((a, b) => b.weight - a.weight);

  for (const q of sorted) {
    const value = getNestedValue(profile, q.field);
    if (!value || (Array.isArray(value) && value.length === 0) || value === '') {
      return q;
    }
  }

  return null; // All questions answered
}

/**
 * Get a summary of the profile for inclusion in system prompts
 */
function getProfileSummary(profile) {
  const parts = [];

  if (profile.threat_model.industry) {
    parts.push(`Industry: ${profile.threat_model.industry}`);
  }
  if (profile.infrastructure.cloud_providers.length) {
    parts.push(`Cloud: ${profile.infrastructure.cloud_providers.join(', ')}`);
  }
  if (profile.infrastructure.primary_stack.length) {
    parts.push(`Stack: ${profile.infrastructure.primary_stack.join(', ')}`);
  }
  if (profile.threat_model.data_sensitivity) {
    parts.push(`Data sensitivity: ${profile.threat_model.data_sensitivity}`);
  }
  if (profile.compliance.frameworks.length) {
    parts.push(`Compliance: ${profile.compliance.frameworks.join(', ')}`);
  }
  if (profile.threat_model.crown_jewels.length) {
    parts.push(`Crown jewels: ${profile.threat_model.crown_jewels.join(', ')}`);
  }
  if (profile.threat_model.attack_surface) {
    parts.push(`Attack surface: ${profile.threat_model.attack_surface}`);
  }
  if (profile.threat_model.threat_actors.length) {
    parts.push(`Threat actors: ${profile.threat_model.threat_actors.join(', ')}`);
  }
  if (profile.team.security_maturity) {
    parts.push(`Security maturity: ${profile.team.security_maturity}`);
  }
  if (profile.infrastructure.domains.length) {
    parts.push(`Domains: ${profile.infrastructure.domains.join(', ')}`);
  }

  return parts.length ? parts.join('. ') + '.' : 'No profile configured yet.';
}

/**
 * Extract profile updates from natural language (lightweight regex)
 */
function extractProfileUpdates(message) {
  const updates = {};
  const lower = message.toLowerCase();

  // Cloud providers
  const clouds = [];
  if (/\baws\b/i.test(lower)) clouds.push('aws');
  if (/\bgcp\b|google\s+cloud/i.test(lower)) clouds.push('gcp');
  if (/\bazure\b/i.test(lower)) clouds.push('azure');
  if (/\bon.?prem/i.test(lower)) clouds.push('on-prem');
  if (clouds.length) updates.infrastructure = { ...updates.infrastructure, cloud_providers: clouds };

  // Industry
  const industries = ['fintech', 'healthcare', 'saas', 'government', 'retail', 'education', 'manufacturing', 'energy', 'telecom', 'media'];
  for (const ind of industries) {
    if (lower.includes(ind)) {
      updates.threat_model = { ...updates.threat_model, industry: ind };
      break;
    }
  }

  // Compliance
  const frameworks = [];
  if (/pci[\s-]*dss/i.test(lower)) frameworks.push('pci-dss');
  if (/hipaa/i.test(lower)) frameworks.push('hipaa');
  if (/soc\s*2/i.test(lower)) frameworks.push('soc2');
  if (/iso\s*27001/i.test(lower)) frameworks.push('iso27001');
  if (/nist/i.test(lower)) frameworks.push('nist-csf');
  if (frameworks.length) updates.compliance = { ...updates.compliance, frameworks };

  return Object.keys(updates).length ? updates : null;
}

// Utility: get nested object value by dot-notation path
function getNestedValue(obj, path) {
  return path.split('.').reduce((o, k) => (o && o[k] !== undefined ? o[k] : undefined), obj);
}

module.exports = {
  DISCOVERY_QUESTIONS,
  getOrCreateProfile,
  updateProfile,
  calculateCompletionScore,
  getNextDiscoveryQuestion,
  getProfileSummary,
  extractProfileUpdates,
};
