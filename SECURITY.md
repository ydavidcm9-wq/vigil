# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Vigil, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email: **hello@vigil.agency**

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Security Considerations

Vigil is a security operations platform that executes scanner tools (nmap, nuclei, trivy, nikto) on the host system. Operators should be aware of:

- **Scanner execution** — Vigil runs CLI tools with user-provided targets. Input is sanitized but operators should restrict network access appropriately.
- **Bootstrap credentials** — Set `VIGIL_USER`/`VIGIL_PASS` explicitly, or let Vigil generate a one-time bootstrap password on first launch and rotate it immediately after login.
- **Credential vault** — Uses AES-256-GCM encryption. The encryption key is auto-generated if not set via `ENCRYPTION_KEY` in `.env`.
- **Session management** — Cookie-based sessions (`vigil_session`). Enable HTTPS in production.
- **Docker socket** — If mounted for container scanning, the Docker socket grants elevated access. Use `DOCKER_GID` to restrict.
- **AI CLI passthrough** — BYOK AI features shell out to `claude` or `codex` CLI. Ensure these are installed from trusted sources.
