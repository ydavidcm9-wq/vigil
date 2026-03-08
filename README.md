<p align="center">
  <img src="public/img/Dashboard.png" alt="Vigil Dashboard" width="100%" />
</p>

<h1 align="center">Vigil</h1>

<p align="center">
  <strong>The Security Agency That Never Sleeps</strong><br>
  AI-powered security operations platform — scanners, agents, incidents, compliance, MCP
</p>

<p align="center">
  <a href="https://github.com/vigil-agency/vigil/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="License"></a>
  <a href="https://github.com/vigil-agency/vigil/releases"><img src="https://img.shields.io/github/v/release/vigil-agency/vigil" alt="Release"></a>
  <img src="https://img.shields.io/badge/node-%3E%3D18-brightgreen" alt="Node">
  <img src="https://img.shields.io/badge/dependencies-6-blue" alt="Dependencies">
  <a href="https://github.com/vigil-agency/vigil/actions/workflows/ci.yml"><img src="https://github.com/vigil-agency/vigil/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://vigil.agency"><img src="https://img.shields.io/badge/website-vigil.agency-cyan" alt="Website"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#screenshots">Screenshots</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#mcp-server">MCP Server</a> •
  <a href="#contributing">Contributing</a> •
  <a href="https://vigil.agency">Website</a>
</p>

---

## Why Vigil

Most security teams fail audits because they lack a **repeatable workflow**, not because they lack tools.

Vigil combines automated scanners, AI-powered triage, autonomous agents, incident response, and compliance tracking into a single platform — with zero vendor lock-in.

- **BYOK AI** — Bring your own Claude or Codex CLI subscription. Zero AI cost for the product.
- **6 scanners built-in** — Nmap, Nuclei, Trivy, Nikto, OpenSSL, DNS/WHOIS
- **20 autonomous agents** — Run parallel security campaigns
- **MCP server** — 25+ tools, 3 resources, 4 prompts for Claude Desktop/Code/Cursor
- **Works without a database** — JSON file stores by default, optional PostgreSQL
- **6 npm dependencies** — Express, Socket.IO, pg, node-pty, multer, MCP SDK

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
