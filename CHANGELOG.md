# Changelog

All notable changes to Vigil will be documented in this file.

## [1.1.0] — 2026-03-14

### Vigil Brain — Embedded Security Knowledge Engine
- 356 pre-built security knowledge entries with instant lookup (<1ms, no LLM needed)
- 85 MITRE ATT&CK Enterprise techniques across all 14 tactics with CVEs, detections, mitigations
- 89 port-to-service mappings with known vulnerabilities (port 21 through 50000)
- 48 NIST controls (CSF 2.0 functions + 800-53 Rev 5 key controls)
- 40 CompTIA Security+ SY0-701 domain entries
- 30 cross-framework compliance mappings (PCI DSS 4.0, HIPAA, SOC 2, ISO 27001, CIS v8)
- 27 remediation templates with language-specific fixes (Node.js, Python, Java, Go, PHP)
- 17 CVE vulnerability patterns (SQLi, XSS, SSRF, deserialization, buffer overflow, etc.)
- 10 OWASP Top 10 Web (2021) with CWE mappings
- 10 OWASP LLM Top 10 + MITRE ATLAS (from existing ai-security-kb.js)
- Dynamic system prompt builder — assembles context from profile, section, KB hits, memory, actions
- Brain profile with 15 discovery questions (infrastructure, compliance, threat model, preferences)
- Memory system — auto-extracts IPs, domains, CVEs, preferences from conversations
- Section-aware context for all 38+ sidebar views
- Action catalog with 40+ intent-to-action mappings and keyword/regex matching
- Draggable floating chatbox (Ctrl+Shift+B) with section-aware suggested questions
- Brain-enriched AI Terminal and AI Chat — all AI calls go through Brain first
- KB fallback when LLM provider is unavailable

### Flows — DAG Workflow Automation
- DAG-based flow execution engine with sequential BFS walker
- Node types: start, end, LLM, agent, tool, condition, loop, HTTP, delay, human_input, notify
- 4 built-in templates: Recon Pipeline, Compliance Check, Incident Response, Vulnerability Triage
- Visual flow editor with drag-drop node placement and edge drawing
- Conditional branching with state evaluation
- HTTP nodes for webhooks/callbacks
- Real-time execution progress via Socket.IO
- PostgreSQL persistence with versioning
- Flow runs tracked with full status lifecycle

### Smart AI Provider Routing
- Multi-provider support: Claude API, Claude CLI, Claude Code, Codex CLI, Ollama
- Strategy-based routing: balanced, premium, speed, economy
- Route-based assignment (scans → Ollama, analysis → Claude API)
- Per-agent and per-flow provider pinning with inheritance cascade
- Automatic fallback chains when primary provider unavailable
- Custom system prompt passthrough to Ollama and Anthropic API

### Agent Enhancements
- Agent catalog expanded to 28 built-in security agents
- Per-agent AI provider selection
- Agent editor with custom system prompts
- New agents: Prompt Injection Tester, API Key Detector

### Docker & Infrastructure
- Ollama integration in Docker Compose (qwen3:8b default)
- Security bridge with supervisord process management
- Claude CLI credential mounting from host to container
- Entrypoint fixes for .claude directory ownership

### UI & Auth
- Glass card visibility fix (surface opacity 65% → 92%, brighter borders/text)
- 2FA hardened with TOTP challenge-token flow and inline forms
- Auth hardening with bootstrap passwords and RBAC enforcement
- Express upgraded to 5.2.1
- Cache busting across all JS assets

---

## [1.0.0] — 2026-03-07

### Initial Release

**Scanning & Vulnerability Management**
- Nmap network scanning (ports, hosts, services, OS detection)
- Nuclei vulnerability scanning (9000+ templates, severity filtering)
- Trivy container/filesystem scanning (SBOM, secrets, misconfig)
- Nikto web server scanning
- OpenSSL certificate chain analysis and cipher grading
- DNS reconnaissance (dig, whois, zone transfer)
- Scheduled scans with cron-based configuration
- Scan history with filtering, comparison, and export

**Intelligence & Hunting**
- Threat intelligence feed ingestion (RSS/Atom)
- Threat hunting with AI-assisted hypothesis testing
- OSINT reconnaissance (domain, IP, email, infrastructure)
- CVE tracker with CVSS scoring

**Incidents & Response**
- Incident management lifecycle (create, assign, escalate, resolve)
- Pre-built playbooks (ransomware, phishing, data breach, DDoS)
- Attack timeline visualization and event correlation
- AI-generated postmortem reports

**Agents & Campaigns**
- 20 built-in autonomous security agents
- Campaign mode for parallel agent execution
- Agent scheduling and evaluation framework

**Compliance & Reporting**
- SOC 2, ISO 27001, NIST 800-53, PCI-DSS, HIPAA frameworks
- Security policy editor with enforcement rules
- Report generation (PDF, JSON, CSV)
- Immutable audit log

**AI Integration (BYOK)**
- Claude CLI and Codex CLI passthrough (zero cost)
- AI-powered vulnerability triage and remediation guidance
- Natural language to scanner command translation

**MCP Server**
- 25+ tools for Claude Desktop, Claude Code, Cursor
- 3 resources (security posture, scan summary, vulnerability summary)
- 4 prompts (security audit, incident response, vulnerability assessment, compliance review)
- Streamable HTTP transport at POST /mcp

**Platform**
- Express.js + Socket.IO real-time architecture
- Vanilla JS frontend with 30 views (ViewRegistry pattern)
- Vigil Dark theme (glass treatment, cyan/orange signal system)
- PBKDF2 authentication with TOTP 2FA
- RBAC (admin, analyst, viewer)
- AES-256-GCM credential vault
- JSON file stores (works without database)
- Optional PostgreSQL 17 support
- Docker image with all scanners pre-installed
- Docker Compose with PostgreSQL
- 6 npm dependencies
