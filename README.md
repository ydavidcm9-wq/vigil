```
 ╦  ╦╦╔═╗╦╦
 ╚╗╔╝║║ ╦║║
  ╚╝ ╩╚═╝╩╩═╝
```

# Vigil

**The Security Agency That Never Sleeps.**

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Node 18+](https://img.shields.io/badge/Node-18%2B-green.svg)](https://nodejs.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](Dockerfile)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-cyan.svg)](CONTRIBUTING.md)

Open-source, AI-powered security operations platform. Vulnerability scanning, autonomous agents, incident response, compliance tracking, and MCP server — all in a single Express.js process.

Nmap + Nuclei + Trivy + Nikto + OpenSSL + DNS

6 npm dependencies. No React. No build step. BYOK AI.

---

[Website](https://vigil.agency) | [GitHub](https://github.com/vigil-agency/vigil) | [Docs](https://vigil.agency/docs.html) | [Twitter](https://x.com/vigaborofficial)

---

Built by [Autopilot AI Tech LLC](https://www.autopilotaitech.com)

---

## Features

- **6 Built-in Scanners** — Nmap, Nuclei, Trivy, Nikto, OpenSSL, DNS/WHOIS — no external dependencies
- **20 Autonomous Agents** — Run parallel security campaigns with scheduling
- **Incident Response** — Full lifecycle workflow with playbooks, timeline, and AI postmortems
- **Compliance Tracking** — SOC 2, ISO 27001, NIST 800-53, PCI-DSS, HIPAA
- **MCP Server** — 25+ tools, 3 resources, 4 prompts for Claude Desktop/Code/Cursor
- **BYOK AI** — Bring your own Claude or Codex CLI. Zero AI cost baked in
- **Works without a database** — JSON file stores by default, optional PostgreSQL
- **RBAC + 2FA** — Admin, Analyst, Viewer roles with TOTP two-factor auth
- **Credential Vault** — AES-256-GCM encrypted storage
- **30 Views** — Glass-themed dashboard with real-time Socket.IO updates

## Quick Start

### Option 1: npm (bare metal)

```bash
git clone https://github.com/vigil-agency/vigil.git
cd vigil
cp .env.example .env
npm install
npm start
# → http://localhost:4100  (admin / admin)
```

### Option 2: Docker Compose

```bash
git clone https://github.com/vigil-agency/vigil.git
cd vigil
cp .env.example .env
docker compose up -d
# → http://localhost:4100  (admin / admin)
```

This starts Vigil + PostgreSQL 17. Scanner tools (nmap, nuclei, trivy, nikto) are included in the Docker image.

### Option 3: Docker (standalone)

```bash
docker run -d \
  -p 4100:4100 \
  -e VIGIL_USER=admin \
  -e VIGIL_PASS=admin \
  vigil-agency/vigil:latest
```

### Prerequisites (bare metal)

- **Node.js 22+** and npm
- **Scanners** (optional, for full functionality):
  - `nmap` — network scanning
  - `nuclei` — vulnerability scanning (9000+ templates)
  - `trivy` — container/filesystem scanning
  - `nikto` — web server scanning
  - `openssl` — certificate analysis
  - `dig` + `whois` — DNS reconnaissance
- **Docker CLI** (optional, for container security scanning)
- **PostgreSQL 17** (optional — works without it using JSON file stores)
- **AI CLI** (optional — `claude` or `codex` for AI features)

See [CLAUDE.md](CLAUDE.md) for the full bare metal install guide.

## Features

### Scanning & Vulnerability Management
- **Network Scan** — Nmap port scanning, host discovery, service detection, OS fingerprinting
- **Vulnerability Scan** — Nuclei template-based scanning with severity filtering
- **Container Scan** — Trivy image/filesystem scanning, SBOM generation
- **Web Scan** — Nikto web server misconfiguration detection
- **SSL Audit** — Certificate chain validation, cipher suite grading, protocol testing
- **DNS Recon** — DNS enumeration, zone transfer, WHOIS lookup
- **Scheduled Scans** — Cron-based recurring scan configuration

### Intelligence & Hunting
- **Threat Intelligence** — RSS feed ingestion, IOC matching, adversary profiles
- **Threat Hunting** — AI-assisted hypothesis testing, MITRE ATT&CK mapping
- **OSINT** — Domain, IP, email, and infrastructure reconnaissance
- **CVE Tracker** — CVE database search, CVSS scoring, affected assets

### Incidents & Response
- **Incident Management** — Full lifecycle workflow with severity, assignment, timeline
- **Playbooks** — Pre-built response templates (ransomware, phishing, data breach, DDoS)
- **Attack Timeline** — Event correlation and visualization
- **Postmortem** — AI-generated post-incident review with lessons learned

### Agents & Campaigns
- **20 Built-in Agents** — From vulnerability scanning to compliance auditing
- **Campaign Mode** — Run multiple agents in parallel with scheduled execution
- **AI Triage** — Automated vulnerability prioritization and remediation guidance

### Compliance & Reporting
- **Compliance Frameworks** — SOC 2, ISO 27001, NIST 800-53, PCI-DSS, HIPAA
- **Policy Editor** — Security policy CRUD with enforcement rules
- **Reports** — PDF, JSON, CSV generation with scheduling
- **Audit Log** — Immutable audit trail with filtering and export

### System
- **Terminal** — Embedded terminal for manual scanner commands
- **Credentials Vault** — AES-256-GCM encrypted credential storage
- **Knowledge Base** — Notes and FAQ for team knowledge sharing
- **MCP Playground** — Interactive tool testing for Claude Desktop/Code/Cursor
- **Notifications** — Real-time alerts via Socket.IO
- **RBAC** — Admin, Analyst, Viewer roles with 2FA (TOTP)

## Screenshots

<details>
<summary>Click to expand all screenshots</summary>

| View | Screenshot |
|------|-----------|
| Dashboard | ![Dashboard](public/img/Dashboard.png) |
| AI Terminal | ![AI Terminal](public/img/AI_terminal.png) |
| Security Agents | ![Security Agents](public/img/SecurityAgents.png) |
| Campaigns | ![Campaigns](public/img/Campaigns.png) |
| Findings | ![Findings](public/img/Findings.png) |
| Threat Feed | ![Threat Feed](public/img/threatfeed.png) |
| Threat Hunt | ![Threat Hunt](public/img/ThreatHunt.png) |
| OSINT | ![OSINT](public/img/OSINT.png) |
| Attack Timeline | ![Attack Timeline](public/img/AttackTimeline.png) |
| Alert Triage | ![Alert Triage](public/img/AlertTriage.png) |
| Compliance | ![Compliance](public/img/complainace_framework.png) |
| Playbooks | ![Playbooks](public/img/playbook.png) |
| Pentest | ![Pentest](public/img/Penttest.png) |
| Reports | ![Reports](public/img/reports.png) |
| Audit Log | ![Audit Log](public/img/audit_log.png) |
| Credentials Vault | ![Credentials](public/img/credentials.png) |
| Knowledge Base | ![Knowledge Base](public/img/Knowledge_base_with_custom_note_taking.png) |
| MCP Playground | ![MCP Playground](public/img/MCP_Playground.png) |
| Notifications | ![Notifications](public/img/notifications.png) |
| Settings | ![Settings](public/img/settings.png) |
| Vigil AI | ![Vigil AI](public/img/vigial_ai.png) |

</details>

## Architecture

```
server.js                    → Express + Socket.IO, auth middleware, .env loader
routes/  (~25 modules)       → REST API endpoints (scans, vulns, incidents, compliance, MCP, …)
lib/     (~17 modules)       → Scanner wrappers, AI, RBAC, audit, crypto, sessions
data/                        → Runtime JSON stores (works without database)
public/                      → Vanilla JS frontend (ViewRegistry pattern)
  css/                       → Vigil Dark theme (glass treatment, cyan/orange signal system)
  js/views/ (30 views)       → Self-registering view modules
docker/                      → Kali bridge, PostgreSQL schema, WARP proxy
```

### Signal System
- **Cyan (#22d3ee)** — secure, healthy, passing, active
- **Orange (#ff6b2b)** — threat, vulnerability, warning, critical

### Auth
- PBKDF2 password hashing
- Session tokens in cookies (`vigil_session`) or Bearer header
- Optional TOTP 2FA
- RBAC: admin, analyst, viewer

### AI Integration (BYOK)
Users bring their own AI subscriptions. Vigil shells out to locally-installed CLI tools:
- **Claude CLI** (`claude --print`) — requires Anthropic subscription
- **Codex CLI** (`codex`) — requires OpenAI API key
- **None** — AI features disabled, graceful degradation

## MCP Server

Vigil includes a built-in [Model Context Protocol](https://modelcontextprotocol.io) server at `POST /mcp` (Streamable HTTP transport).

Connect from Claude Desktop, Claude Code, Cursor, or any MCP client:

```json
{
  "mcpServers": {
    "vigil": {
      "url": "http://localhost:4100/mcp",
      "transport": "streamable-http"
    }
  }
}
```

### 25+ Tools
Scanning (nmap, nuclei, trivy, nikto, SSL, DNS) • Vulnerabilities (search, get, list CVEs) • Assets (list, details, discover hosts) • Docker (list containers, inspect, scan image) • Compliance (check framework, policy status) • Incidents (create, update, timeline) • Reports (generate, get scan results) • System (posture score, metrics, alerts)

### 3 Resources
`vigil://security-posture` • `vigil://scan-summary` • `vigil://vulnerability-summary`

### 4 Prompts
`security_audit` • `incident_response` • `vulnerability_assessment` • `compliance_review`

## Configuration

Copy `.env.example` to `.env` and customize:

| Variable | Default | Description |
|----------|---------|-------------|
| `VIGIL_PORT` | `4100` | Server port |
| `VIGIL_USER` | `admin` | Default admin username |
| `VIGIL_PASS` | `admin` | Default admin password (change immediately) |
| `DATABASE_URL` | — | PostgreSQL connection string (optional) |
| `AI_PROVIDER` | — | `claude-cli` or `codex` (optional) |
| `ENCRYPTION_KEY` | auto | 32-byte hex for credential vault |
| `DOCKER_HOST` | — | Docker socket path for container scanning |

## Scanners

| Scanner | Purpose | Install |
|---------|---------|---------|
| Nmap | Network scanning, port discovery, service detection | `apt install nmap` |
| Nuclei | Template-based vulnerability scanning (9000+ templates) | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |
| Trivy | Container/filesystem vuln scanning, SBOM, secrets | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) |
| Nikto | Web server misconfiguration detection | `apt install nikto` |
| OpenSSL | Certificate chain analysis, cipher grading | Pre-installed on most systems |
| dig/whois | DNS reconnaissance, WHOIS lookup | `apt install dnsutils whois` |

## Testing

```bash
# Health check
curl http://localhost:4100/api/health

# With auth
curl -b "vigil_session=TOKEN" http://localhost:4100/api/system
curl -b "vigil_session=TOKEN" http://localhost:4100/api/scans
curl -b "vigil_session=TOKEN" http://localhost:4100/api/vulnerabilities

# Smoke tests
node scripts/chat-smoke.mjs
node scripts/agents-smoke.mjs
node scripts/brain-smoke.mjs
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

[AGPL-3.0](LICENSE) — free for personal and commercial use. If you modify and deploy Vigil as a service, you must open-source your modifications.

## Safety

- Only scan targets you own or have written authorization to test.
- Keep credentials out of AI prompts.
- Change the default admin password immediately after first login.
- Use the built-in credential vault for sensitive data (AES-256-GCM encrypted).
