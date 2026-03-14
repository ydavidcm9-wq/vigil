'use strict';
/**
 * Vigil AI Brain — Section Context Registry
 * Maps every sidebar section to brain context: what it does, capabilities, help prompts.
 * This is what makes the brain section-aware.
 */

const SECTION_REGISTRY = {
  // ── Dashboard ──────────────────────────────────────────────
  'dashboard': {
    id: 'dashboard',
    name: 'Dashboard',
    group: 'home',
    description: 'Security posture overview with risk score, active threats, recent findings, and system health metrics.',
    capabilities: ['View risk score', 'See recent findings', 'Monitor active threats', 'Check system health', 'View scan status'],
    relatedKBDomains: ['nist', 'comptia'],
    relatedActions: ['view-dashboard', 'get-posture'],
    helpPrompts: [
      'What does my risk score mean?',
      'How can I improve my security posture?',
      'What should I prioritize first?',
      'Explain the threat level indicators',
    ],
    apiEndpoints: ['/api/dashboard/stats', '/api/dashboard/posture'],
  },
  'intel-hub': {
    id: 'intel-hub',
    name: 'Intel Hub',
    group: 'home',
    description: 'Threat intelligence aggregation from RSS feeds, CISA KEV, NVD, and custom sources. Real-time security news.',
    capabilities: ['View threat feeds', 'Search intel', 'Track CVEs', 'Subscribe to feeds', 'Filter by severity'],
    relatedKBDomains: ['cve-pattern', 'mitre-attack'],
    relatedActions: ['search-intel', 'subscribe-feed'],
    helpPrompts: [
      'What are the latest critical vulnerabilities?',
      'How do I add a custom threat feed?',
      'What CVEs should I prioritize patching?',
    ],
    apiEndpoints: ['/api/intel', '/api/threats'],
  },

  // ── AI & Intel ─────────────────────────────────────────────
  'ai-terminal': {
    id: 'ai-terminal',
    name: 'AI Terminal',
    group: 'ai-intel',
    description: 'Interactive AI terminal with streaming output. Run Claude/Ollama/Codex with full terminal experience.',
    capabilities: ['Stream AI responses', 'Multi-turn conversations', 'Code analysis', 'Security question answering'],
    relatedKBDomains: ['comptia', 'mitre-attack'],
    relatedActions: ['ask-ai'],
    helpPrompts: [
      'How do I switch AI providers?',
      'Can I analyze code snippets here?',
      'What kind of security questions can I ask?',
    ],
    apiEndpoints: ['/api/claude/stream'],
  },
  'ai-chat': {
    id: 'ai-chat',
    name: 'AI Chat',
    group: 'ai-intel',
    description: 'Conversational AI security analyst. Ask about threats, vulnerabilities, compliance, or get security guidance.',
    capabilities: ['Security Q&A', 'Threat analysis', 'Vulnerability explanation', 'Compliance guidance', 'Incident advice'],
    relatedKBDomains: ['comptia', 'mitre-attack', 'owasp-web', 'nist'],
    relatedActions: ['ask-ai'],
    helpPrompts: [
      'Explain a specific MITRE technique',
      'How do I respond to a ransomware incident?',
      'What are the OWASP Top 10 risks?',
    ],
    apiEndpoints: ['/api/claude/run'],
  },
  'brain-chat': {
    id: 'brain-chat',
    name: 'Vigil Brain',
    group: 'ai-intel',
    description: 'Vigil AI Brain with built-in security knowledge base, contextual help, memory, and guided navigation.',
    capabilities: ['Instant KB lookup', 'Section-aware guidance', 'Memory recall', 'Action suggestions', 'Profile-aware responses'],
    relatedKBDomains: ['comptia', 'mitre-attack', 'owasp-web', 'nist', 'compliance'],
    relatedActions: ['ask-brain'],
    helpPrompts: [
      'What can you help me with?',
      'Search the knowledge base for ransomware',
      'What should I do next to improve security?',
    ],
    apiEndpoints: ['/api/brain/chat'],
  },
  'knowledge': {
    id: 'knowledge',
    name: 'Knowledge Base',
    group: 'ai-intel',
    description: 'Security knowledge base with articles, threat intel notes, and research findings. Searchable with semantic and keyword matching.',
    capabilities: ['Search knowledge', 'Add articles', 'Tag and organize', 'Semantic search'],
    relatedKBDomains: ['comptia', 'mitre-attack', 'owasp-web', 'nist'],
    relatedActions: ['ask-brain'],
    helpPrompts: [
      'How do I add knowledge articles?',
      'Search for threat intelligence',
      'What topics are covered in the knowledge base?',
    ],
    apiEndpoints: ['/api/knowledge'],
  },
  'mcp-playground': {
    id: 'mcp-playground',
    name: 'MCP Playground',
    group: 'ai-intel',
    description: 'Model Context Protocol playground for testing MCP tool integrations and JSON-RPC communication.',
    capabilities: ['Test MCP tools', 'Inspect JSON-RPC', 'Configure MCP servers'],
    relatedKBDomains: [],
    relatedActions: [],
    helpPrompts: [
      'What is MCP and how does it work?',
      'How do I connect an MCP server?',
    ],
    apiEndpoints: ['/mcp'],
  },

  // ── Agents ─────────────────────────────────────────────────
  'agents': {
    id: 'agents',
    name: 'Security Agents',
    group: 'agents',
    description: '37 specialized AI security agents: scanners, analyzers, defenders, and hunters. Each agent has domain-specific prompts and capabilities.',
    capabilities: ['Run security agents', 'View agent results', 'Create custom agents', 'Schedule agent runs', 'Compare results'],
    relatedKBDomains: ['mitre-attack', 'owasp-web', 'comptia'],
    relatedActions: ['run-agent', 'create-agent'],
    helpPrompts: [
      'Which agent should I use for web app testing?',
      'How do I run the Autonomous Pentester?',
      'What agents detect lateral movement?',
      'How do I create a custom agent?',
    ],
    apiEndpoints: ['/api/agents', '/api/agents/:id/run'],
  },
  'flows': {
    id: 'flows',
    name: 'Flows',
    group: 'agents',
    description: 'DAG-based workflow automation. Chain agents, conditions, HTTP calls, and delays into automated security pipelines.',
    capabilities: ['Create workflows', 'Chain agents together', 'Add conditions/loops', 'Schedule flows', 'Monitor execution'],
    relatedKBDomains: ['nist'],
    relatedActions: ['create-flow', 'run-flow'],
    helpPrompts: [
      'How do I create a recon pipeline flow?',
      'Can I schedule automated scans?',
      'How do flows handle failures?',
    ],
    apiEndpoints: ['/api/flows', '/api/flows/:id/execute'],
  },
  'campaigns': {
    id: 'campaigns',
    name: 'Campaigns',
    group: 'agents',
    description: 'Multi-phase security assessment campaigns. Organize pentests, red team exercises, and security audits into structured campaigns.',
    capabilities: ['Create campaigns', 'Track phases', 'Assign targets', 'Generate reports'],
    relatedKBDomains: ['mitre-attack', 'nist'],
    relatedActions: ['create-campaign'],
    helpPrompts: [
      'How do I set up a pentest campaign?',
      'What phases should a red team campaign have?',
      'How do I track campaign progress?',
    ],
    apiEndpoints: ['/api/campaigns'],
  },
  'pentest': {
    id: 'pentest',
    name: 'Pentest',
    group: 'agents',
    description: 'Penetration testing workspace. Plan, execute, and document penetration tests with AI-assisted methodology.',
    capabilities: ['Plan pentest methodology', 'Execute tools', 'Document findings', 'Generate pentest report'],
    relatedKBDomains: ['mitre-attack', 'owasp-web', 'cve-pattern'],
    relatedActions: ['start-pentest', 'run-exploit'],
    helpPrompts: [
      'What methodology should I follow for a web app pentest?',
      'How do I document pentest findings?',
      'What tools are available for network pentesting?',
    ],
    apiEndpoints: ['/api/pentest'],
  },
  'playbooks': {
    id: 'playbooks',
    name: 'Playbooks',
    group: 'agents',
    description: 'Incident response and security operations playbooks. Step-by-step procedures for handling security events.',
    capabilities: ['Browse playbooks', 'Run playbook steps', 'Create custom playbooks', 'Track playbook execution'],
    relatedKBDomains: ['nist', 'mitre-attack', 'comptia'],
    relatedActions: ['run-playbook'],
    helpPrompts: [
      'What playbook should I use for a phishing incident?',
      'How do I create a custom playbook?',
      'What are the steps for ransomware response?',
    ],
    apiEndpoints: ['/api/playbooks'],
  },

  // ── Workspace ──────────────────────────────────────────────
  'calendar': {
    id: 'calendar',
    name: 'Calendar',
    group: 'workspace',
    description: 'Security operations calendar. Schedule scans, audits, reviews, and security events.',
    capabilities: ['Schedule scans', 'Plan audits', 'Track deadlines', 'Set reminders'],
    relatedKBDomains: ['compliance'],
    relatedActions: ['schedule-scan', 'view-events'],
    helpPrompts: [
      'How do I schedule a recurring scan?',
      'When is the next compliance audit due?',
    ],
    apiEndpoints: ['/api/calendar'],
  },
  'notes': {
    id: 'notes',
    name: 'Notes',
    group: 'workspace',
    description: 'Security notes and documentation. Store investigation notes, meeting minutes, and security memos.',
    capabilities: ['Create notes', 'Tag and organize', 'Search notes', 'Link to findings'],
    relatedKBDomains: [],
    relatedActions: ['create-note'],
    helpPrompts: [
      'How do I organize my security notes?',
      'Can I link notes to findings?',
    ],
    apiEndpoints: ['/api/notes'],
  },
  'git': {
    id: 'git',
    name: 'Git',
    group: 'workspace',
    description: 'Git repository integration for tracking security code changes, config files, and infrastructure-as-code.',
    capabilities: ['View git status', 'Browse commits', 'Track changes', 'Code review'],
    relatedKBDomains: [],
    relatedActions: [],
    helpPrompts: [
      'How do I track security config changes?',
      'Show me recent code changes',
    ],
    apiEndpoints: ['/api/git'],
  },
  'github-hub': {
    id: 'github-hub',
    name: 'GitHub Hub',
    group: 'workspace',
    description: 'GitHub integration for security workflows. Monitor repos, PRs, issues, and GitHub Actions.',
    capabilities: ['Browse repos', 'View PRs', 'Track issues', 'Monitor Actions', 'Security alerts'],
    relatedKBDomains: [],
    relatedActions: [],
    helpPrompts: [
      'How do I connect my GitHub repos?',
      'Show me security alerts from GitHub',
    ],
    apiEndpoints: ['/api/github'],
  },

  // ── Threat Operations ──────────────────────────────────────
  'threats': {
    id: 'threats',
    name: 'Threat Feed',
    group: 'threat-ops',
    description: 'Real-time threat intelligence feed. Aggregates CISA KEV, NVD, US-CERT, and custom threat sources.',
    capabilities: ['View threats', 'Filter by severity', 'Search CVEs', 'Subscribe to sources', 'Track emerging threats'],
    relatedKBDomains: ['mitre-attack', 'cve-pattern'],
    relatedActions: ['check-threats', 'subscribe-feed'],
    helpPrompts: [
      'What are the most critical active threats?',
      'Is my infrastructure affected by recent CVEs?',
      'How do I add a custom threat source?',
    ],
    apiEndpoints: ['/api/threats'],
  },
  'triage': {
    id: 'triage',
    name: 'Alert Triage',
    group: 'threat-ops',
    description: 'Security alert triage and prioritization. Review, classify, and respond to security alerts.',
    capabilities: ['Review alerts', 'Classify severity', 'Assign to analysts', 'Mark false positives', 'Escalate incidents'],
    relatedKBDomains: ['mitre-attack', 'nist'],
    relatedActions: ['triage-alerts', 'update-finding'],
    helpPrompts: [
      'How should I prioritize these alerts?',
      'What makes a good triage decision?',
      'When should I escalate to an incident?',
    ],
    apiEndpoints: ['/api/triage'],
  },
  'hunt': {
    id: 'hunt',
    name: 'Threat Hunt',
    group: 'threat-ops',
    description: 'Proactive threat hunting. Create hypotheses, search for indicators, and investigate suspicious activity.',
    capabilities: ['Create hunt hypotheses', 'Search IOCs', 'Investigate anomalies', 'Document findings', 'MITRE mapping'],
    relatedKBDomains: ['mitre-attack', 'cve-pattern'],
    relatedActions: ['threat-hunt', 'create-hypothesis'],
    helpPrompts: [
      'How do I start a threat hunt?',
      'What are good hunting hypotheses for ransomware?',
      'How do I hunt for lateral movement?',
      'Which MITRE techniques should I hunt for?',
    ],
    apiEndpoints: ['/api/hunt'],
  },

  // ── Scanning ───────────────────────────────────────────────
  'port-scanner': {
    id: 'port-scanner',
    name: 'Port Scanner',
    group: 'scanning',
    description: 'Network port scanning using Nmap. Discovers open ports, running services, and OS fingerprints on target hosts.',
    capabilities: ['Scan single host', 'Scan IP range', 'Service detection (-sV)', 'OS fingerprinting (-O)', 'Stealth scan (-sS)'],
    relatedKBDomains: ['mitre-attack', 'port-service'],
    relatedActions: ['scan-ports'],
    helpPrompts: [
      'What ports should I check on a web server?',
      'How do I interpret these scan results?',
      'What do these open ports mean for my attack surface?',
      'Which ports are commonly targeted by attackers?',
    ],
    apiEndpoints: ['/api/scans/start', '/api/scans/list'],
  },
  'vuln-scanner': {
    id: 'vuln-scanner',
    name: 'Vulnerability Scanner',
    group: 'scanning',
    description: 'Vulnerability scanning using Nuclei templates. Detects CVEs, misconfigurations, and security weaknesses.',
    capabilities: ['Scan for CVEs', 'Check misconfigurations', 'Run custom templates', 'Severity filtering', 'Batch scanning'],
    relatedKBDomains: ['cve-pattern', 'owasp-web', 'remediation'],
    relatedActions: ['scan-vulns'],
    helpPrompts: [
      'How do I scan for specific CVEs?',
      'What nuclei templates should I run?',
      'How do I prioritize vulnerabilities to fix?',
      'What is a CVSS score?',
    ],
    apiEndpoints: ['/api/scans/start'],
  },
  'web-scanner': {
    id: 'web-scanner',
    name: 'Web Scanner',
    group: 'scanning',
    description: 'Web application security scanning. Detects XSS, SQLi, CSRF, and other web vulnerabilities.',
    capabilities: ['Spider/crawl', 'Active scan', 'Passive analysis', 'API testing', 'Authentication testing'],
    relatedKBDomains: ['owasp-web', 'cve-pattern', 'remediation'],
    relatedActions: ['scan-web'],
    helpPrompts: [
      'How do I test for XSS vulnerabilities?',
      'What is the difference between active and passive scanning?',
      'How do I scan an authenticated application?',
      'What OWASP risks should I test for?',
    ],
    apiEndpoints: ['/api/scans/start'],
  },
  'container-security': {
    id: 'container-security',
    name: 'Container Security',
    group: 'scanning',
    description: 'Container and image scanning with Trivy. Detects vulnerabilities in Docker images, Kubernetes configs, and IaC.',
    capabilities: ['Scan Docker images', 'Check Kubernetes configs', 'IaC scanning', 'SBOM generation', 'License compliance'],
    relatedKBDomains: ['cve-pattern', 'compliance', 'nist'],
    relatedActions: ['scan-container'],
    helpPrompts: [
      'How do I scan my Docker images for vulnerabilities?',
      'What are common container security risks?',
      'How do I harden my Kubernetes cluster?',
    ],
    apiEndpoints: ['/api/docker/scan'],
  },
  'ssl-monitor': {
    id: 'ssl-monitor',
    name: 'SSL/TLS Monitor',
    group: 'scanning',
    description: 'SSL/TLS certificate and configuration monitoring. Checks certificate validity, cipher suites, and protocol versions.',
    capabilities: ['Check certificate expiry', 'Audit cipher suites', 'Test protocol versions', 'Detect weak configs', 'Monitor renewals'],
    relatedKBDomains: ['comptia', 'compliance', 'remediation'],
    relatedActions: ['check-ssl'],
    helpPrompts: [
      'Is my TLS configuration secure?',
      'What cipher suites should I enable?',
      'When does my certificate expire?',
      'How do I fix a weak TLS configuration?',
    ],
    apiEndpoints: ['/api/ssl/check'],
  },
  'dns-security': {
    id: 'dns-security',
    name: 'DNS Security',
    group: 'scanning',
    description: 'DNS security analysis. Checks DNSSEC, SPF, DKIM, DMARC, zone transfers, and DNS misconfigurations.',
    capabilities: ['Check DNSSEC', 'Verify SPF/DKIM/DMARC', 'Test zone transfers', 'DNS enumeration', 'Subdomain discovery'],
    relatedKBDomains: ['comptia', 'remediation'],
    relatedActions: ['check-dns'],
    helpPrompts: [
      'Is my DNS properly secured?',
      'How do I set up DMARC correctly?',
      'What is DNSSEC and do I need it?',
    ],
    apiEndpoints: ['/api/dns/check'],
  },
  'code-audit': {
    id: 'code-audit',
    name: 'Code Audit',
    group: 'scanning',
    description: 'Source code security analysis. Reviews code for vulnerabilities, secrets, and insecure patterns using AI and SAST rules.',
    capabilities: ['Scan for secrets', 'Find insecure patterns', 'Review dependencies', 'SAST analysis', 'AI-powered review'],
    relatedKBDomains: ['owasp-web', 'cve-pattern', 'remediation'],
    relatedActions: ['audit-code'],
    helpPrompts: [
      'What security issues should I look for in code?',
      'How do I prevent secrets from being committed?',
      'What are common insecure code patterns?',
    ],
    apiEndpoints: ['/api/code-audit/scan'],
  },
  'proxy-nodes': {
    id: 'proxy-nodes',
    name: 'Proxy Nodes',
    group: 'scanning',
    description: 'Distributed proxy and scanner node management. Deploy scanning infrastructure across networks.',
    capabilities: ['Manage proxy nodes', 'Distribute scans', 'Monitor node health'],
    relatedKBDomains: [],
    relatedActions: [],
    helpPrompts: [
      'How do I add a proxy node?',
      'What is the benefit of distributed scanning?',
    ],
    apiEndpoints: ['/api/proxy'],
  },

  // ── Intelligence ───────────────────────────────────────────
  'osint': {
    id: 'osint',
    name: 'OSINT',
    group: 'intelligence',
    description: 'Open Source Intelligence gathering. Domain recon, WHOIS, DNS, social media, email enumeration, and more.',
    capabilities: ['Domain recon', 'WHOIS lookup', 'Email enumeration', 'Social media search', 'IP geolocation', 'Subdomain discovery'],
    relatedKBDomains: ['mitre-attack', 'comptia'],
    relatedActions: ['run-osint'],
    helpPrompts: [
      'How do I perform reconnaissance on a target?',
      'What OSINT tools are available?',
      'How do I find subdomains for a domain?',
    ],
    apiEndpoints: ['/api/osint'],
  },
  'findings': {
    id: 'findings',
    name: 'Findings',
    group: 'intelligence',
    description: 'Security findings database. All discovered vulnerabilities, misconfigurations, and issues tracked with severity and status.',
    capabilities: ['View findings', 'Filter by severity', 'Update status', 'Export reports', 'Track remediation'],
    relatedKBDomains: ['cve-pattern', 'remediation'],
    relatedActions: ['list-findings', 'export-findings'],
    helpPrompts: [
      'What are my most critical open findings?',
      'How do I prioritize remediation?',
      'How do I export findings for stakeholders?',
    ],
    apiEndpoints: ['/api/findings'],
  },
  'timeline': {
    id: 'timeline',
    name: 'Attack Timeline',
    group: 'intelligence',
    description: 'Visual attack timeline and event correlation. Map attack chains and identify patterns across security events.',
    capabilities: ['View event timeline', 'Correlate attacks', 'Map kill chains', 'Identify patterns'],
    relatedKBDomains: ['mitre-attack'],
    relatedActions: ['view-timeline'],
    helpPrompts: [
      'How do I read an attack timeline?',
      'What patterns indicate a coordinated attack?',
      'How do I map events to the kill chain?',
    ],
    apiEndpoints: ['/api/timeline'],
  },

  // ── Compliance ─────────────────────────────────────────────
  'compliance': {
    id: 'compliance',
    name: 'Compliance Frameworks',
    group: 'compliance',
    description: 'Compliance framework management. Track adherence to PCI DSS, HIPAA, SOC 2, ISO 27001, NIST CSF, and CIS Controls.',
    capabilities: ['View framework status', 'Map controls', 'Track gaps', 'Generate evidence', 'Cross-framework mapping'],
    relatedKBDomains: ['compliance', 'nist'],
    relatedActions: ['check-compliance', 'map-controls'],
    helpPrompts: [
      'What compliance frameworks apply to my organization?',
      'How do I map controls across frameworks?',
      'What are the key PCI DSS requirements?',
      'How do I prepare for a SOC 2 audit?',
    ],
    apiEndpoints: ['/api/compliance'],
  },
  'reports': {
    id: 'reports',
    name: 'Reports',
    group: 'compliance',
    description: 'Security report generation. Executive summaries, technical reports, compliance reports, and trend analysis.',
    capabilities: ['Generate reports', 'Executive summaries', 'Compliance reports', 'Trend analysis', 'Export PDF/CSV'],
    relatedKBDomains: ['compliance', 'nist'],
    relatedActions: ['generate-report'],
    helpPrompts: [
      'How do I generate an executive security report?',
      'What should I include in a pentest report?',
      'How do I create a compliance gap report?',
    ],
    apiEndpoints: ['/api/reports'],
  },
  'audit-log': {
    id: 'audit-log',
    name: 'Audit Log',
    group: 'compliance',
    description: 'System audit trail. All actions, logins, configuration changes, and security events logged with timestamps.',
    capabilities: ['View audit events', 'Filter by action', 'Search by user', 'Export logs'],
    relatedKBDomains: ['nist', 'compliance'],
    relatedActions: ['view-audit'],
    helpPrompts: [
      'Who made recent configuration changes?',
      'How do I investigate suspicious activity?',
      'What events should I monitor in the audit log?',
    ],
    apiEndpoints: ['/api/audit-log'],
  },

  // ── Infrastructure ─────────────────────────────────────────
  'network': {
    id: 'network',
    name: 'Network',
    group: 'infrastructure',
    description: 'Network topology and monitoring. View network maps, monitor traffic, and detect anomalies.',
    capabilities: ['View network map', 'Monitor traffic', 'Detect anomalies', 'Track connections'],
    relatedKBDomains: ['mitre-attack', 'comptia'],
    relatedActions: ['map-network'],
    helpPrompts: [
      'How do I map my network topology?',
      'What network anomalies should I watch for?',
      'How do I segment my network for security?',
    ],
    apiEndpoints: ['/api/network'],
  },
  'log-analysis': {
    id: 'log-analysis',
    name: 'Log Analysis',
    group: 'infrastructure',
    description: 'Security log analysis and correlation. Parse, search, and analyze logs from multiple sources.',
    capabilities: ['Parse logs', 'Search events', 'Correlate sources', 'Detect patterns', 'Alert on anomalies'],
    relatedKBDomains: ['mitre-attack', 'nist'],
    relatedActions: ['analyze-logs'],
    helpPrompts: [
      'How do I analyze logs for intrusion signs?',
      'What log sources should I collect?',
      'How do I detect brute force attacks in logs?',
    ],
    apiEndpoints: ['/api/logs'],
  },
  'credentials': {
    id: 'credentials',
    name: 'Credentials',
    group: 'infrastructure',
    description: 'Secure credential vault. Store API keys, passwords, and secrets with encryption at rest.',
    capabilities: ['Store credentials', 'Manage API keys', 'Rotate secrets', 'Access control'],
    relatedKBDomains: ['comptia', 'nist'],
    relatedActions: ['manage-creds'],
    helpPrompts: [
      'How do I securely store API keys?',
      'When should I rotate credentials?',
      'What is the best practice for secret management?',
    ],
    apiEndpoints: ['/api/credentials'],
  },
  'notifications': {
    id: 'notifications',
    name: 'Notifications',
    group: 'infrastructure',
    description: 'Alert and notification management. Configure email, webhook, and in-app notifications for security events.',
    capabilities: ['Configure alerts', 'Set thresholds', 'Manage channels', 'View notification history'],
    relatedKBDomains: [],
    relatedActions: ['configure-notifications'],
    helpPrompts: [
      'How do I set up email alerts for critical findings?',
      'What events should trigger notifications?',
    ],
    apiEndpoints: ['/api/notifications'],
  },

  // ── System ─────────────────────────────────────────────────
  'settings': {
    id: 'settings',
    name: 'Settings',
    group: 'system',
    description: 'System configuration. AI provider selection, theme, scan intervals, SMTP, webhooks, and user management.',
    capabilities: ['Change AI provider', 'Configure theme', 'Set scan intervals', 'Manage SMTP', 'Configure webhooks'],
    relatedKBDomains: [],
    relatedActions: ['configure-settings'],
    helpPrompts: [
      'How do I switch to a different AI provider?',
      'How do I configure Ollama?',
      'How do I set up email notifications?',
    ],
    apiEndpoints: ['/api/settings'],
  },
  'docs': {
    id: 'docs',
    name: 'Documentation',
    group: 'system',
    description: 'Vigil documentation and help. User guides, API reference, and security operations guides.',
    capabilities: ['Browse docs', 'Search help', 'API reference', 'Getting started guide'],
    relatedKBDomains: [],
    relatedActions: [],
    helpPrompts: [
      'How do I get started with Vigil?',
      'Where is the API documentation?',
      'What features are available?',
    ],
    apiEndpoints: [],
  },
};

/**
 * Get section context by ID
 */
function getSectionContext(sectionId) {
  return SECTION_REGISTRY[sectionId] || null;
}

/**
 * Get all sections for a group
 */
function getSectionsForGroup(groupId) {
  return Object.values(SECTION_REGISTRY).filter(s => s.group === groupId);
}

/**
 * Find sections matching a query (for natural language navigation)
 */
function findSectionByQuery(query) {
  if (!query) return [];
  const terms = query.toLowerCase().split(/\s+/).filter(t => t.length > 1);
  if (!terms.length) return [];

  const scored = [];
  for (const section of Object.values(SECTION_REGISTRY)) {
    let score = 0;
    const haystack = [
      section.id,
      section.name,
      section.description,
      ...section.capabilities,
      ...section.helpPrompts,
    ].join(' ').toLowerCase();

    for (const term of terms) {
      if (section.id.includes(term) || section.name.toLowerCase().includes(term)) score += 10;
      else if (section.capabilities.some(c => c.toLowerCase().includes(term))) score += 5;
      else if (haystack.includes(term)) score += 2;
    }

    if (score > 0) scored.push({ section, score });
  }

  scored.sort((a, b) => b.score - a.score);
  return scored.map(s => s.section);
}

/**
 * Get all section IDs
 */
function getAllSectionIds() {
  return Object.keys(SECTION_REGISTRY);
}

module.exports = {
  SECTION_REGISTRY,
  getSectionContext,
  getSectionsForGroup,
  findSectionByQuery,
  getAllSectionIds,
};
