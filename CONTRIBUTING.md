# Contributing to Vigil

Thanks for your interest in contributing! Vigil is open-source under AGPL-3.0.

## Development Setup

```bash
git clone https://github.com/vigil-agency/vigil.git
cd vigil
cp .env.example .env
npm install
npm start
# → http://localhost:4100  (admin / admin)
```

### Prerequisites

- Node.js 22+
- npm
- (Optional) PostgreSQL 17 — works without it using JSON file stores
- (Optional) Docker — for container security scanning
- (Optional) Security scanners: nmap, nuclei, trivy, nikto

## Architecture

Vigil is a **vanilla JavaScript** project. No React, no build step, no bundler, no transpiler.

### Backend
- **Express.js** + **Socket.IO** — `server.js`
- Route modules in `routes/` — each exports `(app, ctx) => { ... }`
- Shared libraries in `lib/` — scanners, AI, RBAC, audit, crypto
- Data stored in `data/` as JSON files (or PostgreSQL when configured)

### Frontend
- **ViewRegistry pattern** — each view in `public/js/views/` self-registers on `window.Views`
- Views have `init()`, `show()`, `hide()`, `update()` lifecycle methods
- Glass theme with CSS variables in `public/css/theme.css`
- Modal system: `Modal.open()`, `Modal.confirm()`, `Modal.loading()`
- Toast system: `Toast.success()`, `Toast.error()`, `Toast.info()`

### Signal System
- **Cyan (#22d3ee)** — secure, healthy, passing, active
- **Orange (#ff6b2b)** — threat, vulnerability, warning, critical
- Never use green for success or red for error

## Code Style

- Vanilla JavaScript — no TypeScript, no JSX, no compile step
- `escapeHtml()` for all user-generated content rendered in views
- Scanner commands are sanitized — never interpolate user input into shell commands
- Keep dependencies minimal (currently 6 npm packages)

## Pull Request Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b my-feature`
3. Make your changes
4. Test locally: `npm start` and verify affected views
5. Commit with a descriptive message
6. Push and open a PR against `main`

### PR Guidelines
- Keep changes focused — one feature or fix per PR
- Include screenshots for UI changes
- Update `CLAUDE.md` if you add routes, views, or libs
- Add smoke tests in `scripts/` for new API endpoints

## Reporting Issues

- Use GitHub Issues with the provided templates
- Include: steps to reproduce, expected vs actual behavior, screenshots
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

## License

By contributing, you agree that your contributions will be licensed under the [AGPL-3.0](LICENSE) license.
