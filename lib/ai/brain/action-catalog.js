'use strict';
/**
 * Vigil AI Brain — Action Catalog
 * Maps natural language intents to concrete Vigil actions.
 * Each action points to a sidebar section and optionally pre-fills parameters.
 */

const ACTION_CATALOG = [
  // ── Dashboard & Overview ───────────────────────────────────
  {
    id: 'view-dashboard',
    name: 'View Dashboard',
    category: 'navigate',
    intentKeywords: ['dashboard', 'overview', 'security posture', 'risk score', 'home'],
    intentPatterns: [/show\s+(me\s+)?the\s+dashboard/i, /security\s+posture/i, /risk\s+score/i],
    targetSection: 'dashboard',
    approvalMode: 'auto',
    riskLevel: 'low',
  },
  {
    id: 'search-intel',
    name: 'Search Threat Intel',
    category: 'analyze',
    intentKeywords: ['threat intel', 'intelligence', 'intel hub', 'threat feed', 'cve news'],
    intentPatterns: [/search\s+(for\s+)?intel/i, /threat\s+intelligence/i, /latest\s+(cves?|vulnerabilities|threats)/i],
    targetSection: 'intel-hub',
    approvalMode: 'auto',
    riskLevel: 'low',
  },

  // ── AI & Brain ─────────────────────────────────────────────
  {
    id: 'ask-ai',
    name: 'Ask AI',
    category: 'analyze',
    intentKeywords: ['ask ai', 'ai chat', 'ai terminal', 'ask question'],
    intentPatterns: [/ask\s+(the\s+)?ai/i, /ai\s+help/i],
    targetSection: 'ai-terminal',
    approvalMode: 'auto',
    riskLevel: 'low',
  },
  {
    id: 'ask-brain',
    name: 'Ask Vigil Brain',
    category: 'analyze',
    intentKeywords: ['brain', 'vigil brain', 'knowledge base', 'kb search'],
    intentPatterns: [/ask\s+(the\s+)?brain/i, /search\s+(the\s+)?knowledge/i, /kb\s+search/i],
    targetSection: 'brain-chat',
    approvalMode: 'auto',
    riskLevel: 'low',
  },

  // ── Agents ─────────────────────────────────────────────────
  {
    id: 'run-agent',
    name: 'Run Security Agent',
    category: 'scan',
    intentKeywords: ['run agent', 'security agent', 'ai agent', 'execute agent'],
    intentPatterns: [/run\s+(the\s+)?(\w+\s+)?agent/i, /launch\s+agent/i],
    targetSection: 'agents',
    approvalMode: 'suggest',
    riskLevel: 'medium',
  },
  {
    id: 'create-agent',
    name: 'Create Custom Agent',
    category: 'configure',
    intentKeywords: ['create agent', 'new agent', 'custom agent', 'build agent'],
    intentPatterns: [/create\s+(a\s+)?(new\s+)?(custom\s+)?agent/i],
    targetSection: 'agents',
    approvalMode: 'suggest',
    riskLevel: 'low',
  },
  {
    id: 'create-flow',
    name: 'Create Workflow',
    category: 'configure',
    intentKeywords: ['create flow', 'new flow', 'workflow', 'automation', 'pipeline'],
    intentPatterns: [/create\s+(a\s+)?(new\s+)?(auto|work)?flow/i, /build\s+(a\s+)?pipeline/i],
    targetSection: 'flows',
    approvalMode: 'suggest',
    riskLevel: 'low',
  },
  {
    id: 'run-flow',
    name: 'Run Workflow',
    category: 'scan',
    intentKeywords: ['run flow', 'execute flow', 'start flow', 'run pipeline'],
    intentPatterns: [/run\s+(the\s+)?(\w+\s+)?flow/i, /execute\s+flow/i],
    targetSection: 'flows',
    approvalMode: 'suggest',
    riskLevel: 'medium',
  },
  {
    id: 'create-campaign',
    name: 'Create Campaign',
    category: 'configure',
    intentKeywords: ['create campaign', 'new campaign', 'pentest campaign', 'assessment'],
    intentPatterns: [/create\s+(a\s+)?(new\s+)?campaign/i, /start\s+(a\s+)?campaign/i],
    targetSection: 'campaigns',
    approvalMode: 'suggest',
    riskLevel: 'low',
  },
  {
    id: 'start-pentest',
    name: 'Start Penetration Test',
    category: 'scan',
    intentKeywords: ['pentest', 'penetration test', 'pen test', 'security test'],
    intentPatterns: [/start\s+(a\s+)?pen(etration)?\s*test/i, /pentest\s+/i],
    targetSection: 'pentest',
    approvalMode: 'confirm',
    riskLevel: 'high',
  },
  {
    id: 'run-playbook',
    name: 'Run Playbook',
    category: 'analyze',
    intentKeywords: ['playbook', 'incident response', 'ir playbook', 'response procedure'],
    intentPatterns: [/run\s+(the\s+)?(\w+\s+)?playbook/i, /incident\s+response\s+play/i],
    targetSection: 'playbooks',
    approvalMode: 'suggest',
    riskLevel: 'medium',
  },

  // ── Scanning ───────────────────────────────────────────────
  {
    id: 'scan-ports',
    name: 'Port Scan',
    category: 'scan',
    intentKeywords: ['port scan', 'open ports', 'nmap', 'service discovery', 'network scan', 'scan ports'],
    intentPatterns: [/scan\s+ports?\s*(on|for|of)?/i, /what\s+ports?\s+(are\s+)?open/i, /nmap\s+/i, /port\s+scan/i],
    targetSection: 'port-scanner',
    targetRoute: '/api/scans/start',
    approvalMode: 'suggest',
    riskLevel: 'low',
  },
  {
    id: 'scan-vulns',
    name: 'Vulnerability Scan',
    category: 'scan',
    intentKeywords: ['vuln scan', 'vulnerability scan', 'nuclei', 'cve scan', 'find vulnerabilities'],
    intentPatterns: [/scan\s+for\s+vulnerabilit/i, /find\s+vulns?/i, /vuln(erability)?\s+scan/i, /nuclei\s+scan/i],
    targetSection: 'vuln-scanner',
    approvalMode: 'suggest',
    riskLevel: 'medium',
  },
  {
    id: 'scan-web',
    name: 'Web Application Scan',
    category: 'scan',
    intentKeywords: ['web scan', 'web app scan', 'zap', 'xss scan', 'sqli scan', 'web security'],
    intentPatterns: [/scan\s+(the\s+)?web\s*(app|site|application)?/i, /web\s+app\s+scan/i, /test\s+for\s+(xss|sql|injection)/i],
    targetSection: 'web-scanner',
    approvalMode: 'suggest',
    riskLevel: 'medium',
  },
  {
    id: 'scan-container',
    name: 'Container Security Scan',
    category: 'scan',
    intentKeywords: ['container scan', 'docker scan', 'image scan', 'trivy', 'kubernetes security', 'k8s scan'],
    intentPatterns: [/scan\s+(my\s+)?(docker|container|image)/i, /container\s+security/i, /trivy\s+scan/i],
    targetSection: 'container-security',
    approvalMode: 'suggest',
    riskLevel: 'low',
  },
  {
    id: 'check-ssl',
    name: 'Check SSL/TLS',
    category: 'scan',
    intentKeywords: ['ssl check', 'tls check', 'certificate', 'cert expiry', 'cipher suite', 'https check'],
    intentPatterns: [/check\s+(ssl|tls|cert|certificate)/i, /ssl\s+(scan|check|test)/i, /cert(ificate)?\s+expir/i],
    targetSection: 'ssl-monitor',
    approvalMode: 'auto',
    riskLevel: 'low',
  },
  {
    id: 'check-dns',
    name: 'Check DNS Security',
    category: 'scan',
    intentKeywords: ['dns check', 'dns security', 'dmarc', 'spf', 'dkim', 'dnssec', 'zone transfer'],
    intentPatterns: [/check\s+dns/i, /dns\s+(security|check|audit)/i, /dmarc|spf|dkim|dnssec/i],
    targetSection: 'dns-security',
    approvalMode: 'auto',
    riskLevel: 'low',
  },
  {
    id: 'audit-code',
    name: 'Code Security Audit',
    category: 'scan',
    intentKeywords: ['code audit', 'code review', 'sast', 'source code', 'security review', 'code scan'],
    intentPatterns: [/audit\s+(the\s+)?code/i, /code\s+(audit|review|scan)/i, /review\s+code\s+for\s+security/i],
    targetSection: 'code-audit',
    approvalMode: 'suggest',
    riskLevel: 'low',
  },

  // ── Threat Operations ──────────────────────────────────────
  {
    id: 'check-threats',
    name: 'Check Threats',
    category: 'analyze',
    intentKeywords: ['check threats', 'new threats', 'threat feed', 'active threats', 'threat landscape'],
    intentPatterns: [/check\s+(for\s+)?(new\s+)?threats/i, /threat\s+feed/i, /any\s+new\s+threats/i],
    targetSection: 'threats',
    approvalMode: 'auto',
    riskLevel: 'low',
  },
  {
    id: 'triage-alerts',
    name: 'Triage Alerts',
    category: 'analyze',
    intentKeywords: ['triage', 'alerts', 'triage alerts', 'review alerts', 'security alerts'],
    intentPatterns: [/triage\s+(the\s+)?(latest\s+)?alerts/i, /review\s+alerts/i],
    targetSection: 'triage',
    approvalMode: 'auto',
    riskLevel: 'low',
  },
  {
    id: 'threat-hunt',
    name: 'Threat Hunt',
    category: 'hunt',
    intentKeywords: ['threat hunt', 'hunt', 'hunting', 'ioc search', 'indicator', 'proactive search'],
    intentPatterns: [/hunt\s+for\s+/i, /threat\s+hunt/i, /search\s+for\s+(ioc|indicator|threat)/i, /start\s+a\s+hunt/i],
    targetSection: 'hunt',
    approvalMode: 'suggest',
    riskLevel: 'medium',
  },
  {
    id: 'create-hypothesis',
    name: 'Create Hunt Hypothesis',
    category: 'hunt',
    intentKeywords: ['hypothesis', 'hunt hypothesis', 'create hypothesis'],
    intentPatterns: [/create\s+(a\s+)?hunt\s+hypothesis/i, /new\s+hypothesis/i],
    targetSection: 'hunt',
    approvalMode: 'auto',
    riskLevel: 'low',
  },

  // ── Intelligence ───────────────────────────────────────────
  {
    id: 'run-osint',
    name: 'OSINT Reconnaissance',
    category: 'scan',
    intentKeywords: ['osint', 'reconnaissance', 'recon', 'domain lookup', 'whois', 'intel gathering'],
    intentPatterns: [/osint\s+(on|for|lookup)/i, /run\s+osint/i, /recon(naissance)?\s+(on|for)/i, /whois\s+/i],
    targetSection: 'osint',
    approvalMode: 'suggest',
    riskLevel: 'low',
  },
  {
    id: 'list-findings',
    name: 'View Findings',
    category: 'analyze',
    intentKeywords: ['findings', 'vulnerabilities found', 'open findings', 'critical findings', 'show findings'],
    intentPatterns: [/show\s+(me\s+)?(the\s+)?findings/i, /list\s+findings/i, /open\s+findings/i, /critical\s+findings/i],
    targetSection: 'findings',
    approvalMode: 'auto',
    riskLevel: 'low',
  },
  {
    id: 'export-findings',
    name: 'Export Findings',
    category: 'report',
    intentKeywords: ['export findings', 'download findings', 'findings report'],
    intentPatterns: [/export\s+findings/i, /download\s+findings/i],
    targetSection: 'findings',
    approvalMode: 'suggest',
    riskLevel: 'low',
  },
  {
    id: 'view-timeline',
    name: 'View Attack Timeline',
    category: 'analyze',
    intentKeywords: ['timeline', 'attack timeline', 'event timeline', 'kill chain'],
    intentPatterns: [/show\s+(the\s+)?timeline/i, /attack\s+timeline/i, /event\s+timeline/i],
    targetSection: 'timeline',
    approvalMode: 'auto',
    riskLevel: 'low',
  },

  // ── Compliance ─────────────────────────────────────────────
  {
    id: 'check-compliance',
    name: 'Check Compliance',
    category: 'analyze',
    intentKeywords: ['compliance', 'compliance check', 'pci dss', 'hipaa', 'soc 2', 'iso 27001', 'framework'],
    intentPatterns: [/check\s+(pci|hipaa|soc|iso|nist|compliance)/i, /compliance\s+(status|check|audit)/i, /am\s+i\s+compliant/i],
    targetSection: 'compliance',
    approvalMode: 'auto',
    riskLevel: 'low',
  },
  {
    id: 'map-controls',
    name: 'Map Controls',
    category: 'analyze',
    intentKeywords: ['map controls', 'control mapping', 'cross-framework', 'framework mapping'],
    intentPatterns: [/map\s+controls/i, /control\s+mapping/i, /cross.?framework/i],
    targetSection: 'compliance',
    approvalMode: 'auto',
    riskLevel: 'low',
  },
  {
    id: 'generate-report',
    name: 'Generate Report',
    category: 'report',
    intentKeywords: ['generate report', 'create report', 'security report', 'executive summary', 'pentest report'],
    intentPatterns: [/generate\s+(a\s+)?(security\s+)?report/i, /create\s+(a\s+)?report/i, /executive\s+summary/i],
    targetSection: 'reports',
    approvalMode: 'suggest',
    riskLevel: 'low',
  },
  {
    id: 'view-audit',
    name: 'View Audit Log',
    category: 'analyze',
    intentKeywords: ['audit log', 'audit trail', 'activity log', 'who did what'],
    intentPatterns: [/audit\s+log/i, /show\s+(the\s+)?audit/i, /who\s+(made|did)/i],
    targetSection: 'audit-log',
    approvalMode: 'auto',
    riskLevel: 'low',
  },

  // ── Infrastructure ─────────────────────────────────────────
  {
    id: 'map-network',
    name: 'Map Network',
    category: 'scan',
    intentKeywords: ['network map', 'topology', 'network topology', 'network scan'],
    intentPatterns: [/map\s+(the\s+)?network/i, /network\s+(topology|map)/i],
    targetSection: 'network',
    approvalMode: 'suggest',
    riskLevel: 'low',
  },
  {
    id: 'analyze-logs',
    name: 'Analyze Logs',
    category: 'hunt',
    intentKeywords: ['analyze logs', 'log analysis', 'parse logs', 'search logs', 'siem'],
    intentPatterns: [/analyze\s+(the\s+)?logs/i, /log\s+analysis/i, /search\s+logs/i, /parse\s+logs/i],
    targetSection: 'log-analysis',
    approvalMode: 'auto',
    riskLevel: 'low',
  },
  {
    id: 'manage-creds',
    name: 'Manage Credentials',
    category: 'configure',
    intentKeywords: ['credentials', 'api key', 'password', 'secret', 'vault'],
    intentPatterns: [/store\s+(an?\s+)?api\s+key/i, /manage\s+cred/i, /credential\s+vault/i, /rotate\s+(cred|secret|key)/i],
    targetSection: 'credentials',
    approvalMode: 'suggest',
    riskLevel: 'medium',
  },
  {
    id: 'configure-settings',
    name: 'Configure Settings',
    category: 'configure',
    intentKeywords: ['settings', 'configure', 'setup', 'preferences', 'ai provider'],
    intentPatterns: [/change\s+(the\s+)?(ai\s+)?provider/i, /configure\s+/i, /update\s+settings/i, /setup\s+/i],
    targetSection: 'settings',
    approvalMode: 'auto',
    riskLevel: 'low',
  },

  // ── Workspace ──────────────────────────────────────────────
  {
    id: 'schedule-scan',
    name: 'Schedule Scan',
    category: 'configure',
    intentKeywords: ['schedule scan', 'recurring scan', 'cron scan', 'automated scan'],
    intentPatterns: [/schedule\s+(a\s+)?(recurring\s+)?scan/i, /automate\s+scan/i],
    targetSection: 'calendar',
    approvalMode: 'suggest',
    riskLevel: 'low',
  },
  {
    id: 'create-note',
    name: 'Create Note',
    category: 'configure',
    intentKeywords: ['create note', 'new note', 'save note', 'write note'],
    intentPatterns: [/create\s+(a\s+)?note/i, /save\s+(a\s+)?note/i],
    targetSection: 'notes',
    approvalMode: 'auto',
    riskLevel: 'low',
  },

  // ── Notification ───────────────────────────────────────────
  {
    id: 'configure-notifications',
    name: 'Configure Notifications',
    category: 'configure',
    intentKeywords: ['notifications', 'alerts config', 'email alerts', 'webhook alerts'],
    intentPatterns: [/configure\s+notification/i, /set\s+up\s+alerts/i, /email\s+alert/i],
    targetSection: 'notifications',
    approvalMode: 'auto',
    riskLevel: 'low',
  },
];

/**
 * Match user message to actions using keywords and regex patterns
 * @param {string} message - user's natural language message
 * @returns {Array} matched actions sorted by relevance
 */
function matchIntent(message) {
  if (!message) return [];
  const lower = message.toLowerCase();

  const scored = [];
  for (const action of ACTION_CATALOG) {
    let score = 0;

    // Check regex patterns first (highest signal)
    for (const pattern of action.intentPatterns) {
      if (pattern.test(message)) {
        score += 20;
        break; // one pattern match is enough
      }
    }

    // Check keywords
    for (const kw of action.intentKeywords) {
      if (lower.includes(kw.toLowerCase())) {
        score += 10;
      }
    }

    if (score > 0) {
      scored.push({ action, score });
    }
  }

  scored.sort((a, b) => b.score - a.score);
  return scored.map(s => s.action);
}

/**
 * Get all actions that target a specific section
 */
function getActionsForSection(sectionId) {
  return ACTION_CATALOG.filter(a => a.targetSection === sectionId);
}

/**
 * Get suggested actions based on current section and profile
 */
function getSuggestedActions(currentSection, profile) {
  const sectionActions = getActionsForSection(currentSection);

  // Add contextually related actions
  const related = [];
  const sectionMap = {
    'dashboard': ['scan-ports', 'scan-vulns', 'check-threats', 'check-compliance'],
    'findings': ['scan-vulns', 'generate-report', 'check-compliance'],
    'port-scanner': ['scan-vulns', 'run-osint'],
    'vuln-scanner': ['scan-web', 'generate-report'],
    'compliance': ['generate-report', 'scan-vulns', 'check-ssl'],
    'hunt': ['analyze-logs', 'check-threats', 'run-agent'],
    'agents': ['create-flow', 'create-campaign'],
    'threats': ['threat-hunt', 'triage-alerts', 'scan-vulns'],
    'triage': ['threat-hunt', 'run-playbook'],
  };

  if (sectionMap[currentSection]) {
    for (const actionId of sectionMap[currentSection]) {
      const action = ACTION_CATALOG.find(a => a.id === actionId);
      if (action && !sectionActions.includes(action)) {
        related.push(action);
      }
    }
  }

  return [...sectionActions, ...related].slice(0, 5);
}

/**
 * Get action by ID
 */
function getActionById(actionId) {
  return ACTION_CATALOG.find(a => a.id === actionId) || null;
}

module.exports = {
  ACTION_CATALOG,
  matchIntent,
  getActionsForSection,
  getSuggestedActions,
  getActionById,
};
