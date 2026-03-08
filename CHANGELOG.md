# Changelog

All notable changes to Vigil will be documented in this file.

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
