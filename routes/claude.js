/**
 * Claude Routes — Claude CLI integration, AI terminal, prompt execution
 */
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

function getAIProvider() {
  try {
    const f = path.join(__dirname, '..', 'data', 'settings.json');
    if (fs.existsSync(f)) return JSON.parse(fs.readFileSync(f, 'utf8')).aiProvider || 'claude-cli';
  } catch {}
  return 'claude-cli';
}

function getAICommand(provider, prompt) {
  switch (provider) {
    case 'codex': return { cmd: 'codex', args: [prompt] };
    case 'claude-cli':
    default: return { cmd: 'claude', args: ['--print', prompt] };
  }
}

module.exports = function (app, ctx) {
  const { io, execCommand, requireAuth, requireRole, REPO_DIR } = ctx;
  let activeClaudeProc = null;

  // Expose for socket events
  ctx.activeClaudeProc = () => activeClaudeProc;

  function runClaude(prompt) {
    const provider = getAIProvider();
    if (provider === 'none') {
      io.emit('claude_output', '\r\n[INFO] AI provider is disabled. Configure in Settings > AI Provider.\r\n');
      return;
    }
    if (activeClaudeProc) {
      io.emit('claude_output', '\r\n[ERROR] AI already running.\r\n');
      return;
    }

    const { cmd, args } = getAICommand(provider, prompt);
    io.emit('claude_output', `\r\n[STARTING] ${cmd} "${prompt.substring(0, 80)}..."\r\n\r\n`);

    const child = spawn(cmd, args, { cwd: REPO_DIR, env: { ...process.env }, shell: true });
    activeClaudeProc = child;
    let output = '';

    child.stdout.on('data', (d) => {
      const t = d.toString();
      output += t;
      io.emit('claude_output', t);
    });

    child.stderr.on('data', (d) => {
      const t = d.toString();
      output += t;
      io.emit('claude_output', t);
    });

    child.on('close', (code) => {
      activeClaudeProc = null;
      io.emit('claude_done', { code, output, prompt });
    });

    child.on('error', (err) => {
      activeClaudeProc = null;
      io.emit('claude_output', `\r\n[ERROR] ${err.message}\r\n`);
      io.emit('claude_done', { code: 1, output: err.message, prompt });
    });
  }

  ctx.runClaude = runClaude;

  // askAI helper — runs AI CLI and returns text
  async function askAI(prompt, options) {
    const provider = getAIProvider();
    if (provider === 'none') return null;

    const timeout = (options && options.timeout) || 30000;
    const { cmd } = getAICommand(provider, prompt);
    const cleanEnv = { ...process.env };
    delete cleanEnv.CLAUDECODE;

    return new Promise((resolve, reject) => {
      const child = spawn(cmd, provider === 'codex' ? [] : ['--print'], {
        stdio: ['pipe', 'pipe', 'pipe'],
        shell: true,
        timeout,
        env: cleanEnv,
      });
      let stdout = '', stderr = '';

      child.stdout.on('data', d => { stdout += d; });
      child.stderr.on('data', d => { stderr += d; });
      child.on('close', code => {
        const result = stdout.trim() || stderr.trim();
        if (code === 0 && result) resolve(result);
        else resolve(result || null);
      });
      child.on('error', e => resolve(null));

      child.stdin.on('error', () => {});
      child.stdin.write(prompt);
      child.stdin.end();
    });
  }

  // askAIJSON helper — runs AI CLI and parses JSON from response
  async function askAIJSON(prompt, options) {
    const text = await askAI(prompt, options);
    if (!text) return null;
    try { return JSON.parse(text); }
    catch {
      // Try to extract JSON from response
      const match = text.match(/\{[\s\S]*\}/);
      if (match) {
        try { return JSON.parse(match[0]); }
        catch { return null; }
      }
      return null;
    }
  }

  // Expose AI helpers on ctx for other routes
  ctx.askAI = askAI;
  ctx.askAIJSON = askAIJSON;

  // POST /api/claude/run — run prompt through Claude CLI
  app.post('/api/claude/run', requireRole('analyst'), (req, res) => {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: 'prompt required' });
    if (activeClaudeProc) return res.status(409).json({ error: 'AI already running' });
    runClaude(prompt);
    res.json({ started: true });
  });

  // POST /api/claude/ask — one-shot AI query (returns response)
  app.post('/api/claude/ask', requireRole('analyst'), async (req, res) => {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: 'prompt required' });

    const provider = getAIProvider();
    if (provider === 'none') return res.json({ response: 'AI provider is disabled.', fallback: true });

    try {
      const response = await askAI(prompt, { timeout: 30000 });
      res.json({ response: response || 'No response from AI', cached: false });
    } catch (e) {
      res.json({ response: 'AI unavailable: ' + e.message, fallback: true });
    }
  });

  // POST /api/claude/stop — stop running AI process
  app.post('/api/claude/stop', requireRole('analyst'), (req, res) => {
    if (activeClaudeProc) {
      activeClaudeProc.kill('SIGTERM');
      activeClaudeProc = null;
      io.emit('claude_output', '\r\n[STOPPED]\r\n');
      res.json({ stopped: true });
    } else {
      res.json({ stopped: false });
    }
  });

  // GET /api/claude/status — check if AI is running
  app.get('/api/claude/status', requireAuth, (req, res) => {
    res.json({
      running: !!activeClaudeProc,
      provider: getAIProvider(),
    });
  });

  // ── Terminal Management (node-pty) ──────────────────────────────────────

  let terminals = new Map();

  // Socket.IO events for terminal — verify auth on connection
  io.on('connection', (socket) => {
    // Authenticate socket connection via cookie or auth token
    const cookieHeader = socket.handshake.headers.cookie || '';
    const tokenMatch = cookieHeader.match(/vigil_session=([^;]+)/);
    const token = tokenMatch ? tokenMatch[1] : (socket.handshake.auth && socket.handshake.auth.token);
    const { getSession } = require('../lib/sessions');
    const session = token ? getSession(token) : null;
    if (!session) {
      socket.emit('terminal_output', '\r\n[ERROR] Authentication required for terminal access.\r\n');
      socket.disconnect();
      return;
    }
    socket.user = { username: session.username, role: session.role };

    socket.on('terminal_start', (data) => {
      try {
        const pty = require('node-pty');
        const shell = process.platform === 'win32' ? 'powershell.exe' : (process.env.SHELL || '/bin/bash');
        const cols = (data && data.cols) || 80;
        const rows = (data && data.rows) || 24;

        // Filter sensitive env vars before passing to terminal
        const safeEnv = { ...process.env };
        const sensitiveKeys = ['ENCRYPTION_KEY', 'DATABASE_URL', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'GITHUB_TOKEN', 'STRIPE_SECRET_KEY', 'JWT_SECRET', 'CLAUDECODE'];
        sensitiveKeys.forEach(k => delete safeEnv[k]);

        const term = pty.spawn(shell, [], {
          name: 'xterm-color',
          cols,
          rows,
          cwd: REPO_DIR,
          env: safeEnv,
        });

        terminals.set(socket.id, term);

        term.onData((data) => {
          socket.emit('terminal_output', data);
        });

        term.onExit(() => {
          terminals.delete(socket.id);
        });
      } catch (e) {
        socket.emit('terminal_output', '\r\n[ERROR] Terminal not available: ' + e.message + '\r\n');
      }
    });

    socket.on('terminal_input', (data) => {
      const term = terminals.get(socket.id);
      if (term) term.write(data);
    });

    socket.on('terminal_resize', (data) => {
      const term = terminals.get(socket.id);
      if (term && data && data.cols && data.rows) {
        try { term.resize(data.cols, data.rows); } catch {}
      }
    });

    socket.on('claude_run', (data) => {
      // Only analyst+ roles can run AI commands
      if (socket.user && socket.user.role !== 'viewer' && data && data.prompt) {
        runClaude(data.prompt);
      }
    });

    socket.on('disconnect', () => {
      const term = terminals.get(socket.id);
      if (term) {
        try { term.kill(); } catch {}
        terminals.delete(socket.id);
      }
    });
  });
};
