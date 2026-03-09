/**
 * Tunnel Manager — pgrok-inspired SSH tunnel + callback listener infrastructure
 *
 * SSH tunnel types:
 *   Forward  (-L): Access remote services through local ports
 *   Reverse  (-R): Expose local services through remote server
 *   Dynamic  (-D): SOCKS5 proxy through remote server
 *
 * Callback Listener:
 *   Built-in HTTP server that captures all incoming requests for OOB
 *   (out-of-band) vulnerability detection during authorized pentests.
 *   Replaces interactsh / Burp Collaborator / ad-hoc netcat listeners.
 *
 * Auto-reconnect with exponential backoff (pgrok pattern):
 *   2s → 4s → 8s → 16s, reset after 60s stable connection.
 */
const { spawn } = require('child_process');
const http = require('http');
const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DATA = path.join(__dirname, '..', 'data');
const TUNNELS_PATH = path.join(DATA, 'tunnels.json');
const CALLBACK_LOG_PATH = path.join(DATA, 'callback-log.json');

function readJSON(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return fallback; }
}
function writeJSON(p, data) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + '.tmp.' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, p);
}

// ═══════════════════════════════════════════════════════════════════════════
// TUNNEL MANAGER
// ═══════════════════════════════════════════════════════════════════════════

/** @type {Map<string, TunnelInfo>} */
const activeTunnels = new Map();

/**
 * @typedef {object} TunnelInfo
 * @property {string} id
 * @property {string} type - forward|reverse|dynamic
 * @property {string} sshTarget - user@host
 * @property {number} localPort
 * @property {string} remoteHost
 * @property {number} remotePort
 * @property {string} status - connecting|connected|reconnecting|stopped|failed
 * @property {object} process - child process
 * @property {string} createdAt
 * @property {number} reconnectDelay - current backoff delay
 * @property {number} reconnectCount
 * @property {number} connectedSince - timestamp of last stable connection
 * @property {boolean} autoReconnect
 */

const BACKOFF_BASE = 2000;
const BACKOFF_MAX = 16000;
const STABLE_THRESHOLD = 60000; // Reset backoff after 60s stable

/**
 * Create an SSH tunnel
 * @param {object} options
 * @param {string} options.type - forward|reverse|dynamic
 * @param {string} options.sshTarget - user@host (e.g., root@vps.example.com)
 * @param {number} options.localPort - local port
 * @param {string} [options.remoteHost] - remote bind host (for forward/reverse)
 * @param {number} [options.remotePort] - remote port (for forward/reverse)
 * @param {number} [options.sshPort] - SSH port (default 22)
 * @param {string} [options.sshKey] - path to SSH private key
 * @param {boolean} [options.autoReconnect] - auto-reconnect on disconnect (default true)
 * @returns {Promise<object>} tunnel info
 */
async function createTunnel(options) {
  const { type, sshTarget, localPort, remoteHost, remotePort, sshPort, sshKey, autoReconnect } = options;

  if (!type || !['forward', 'reverse', 'dynamic'].includes(type)) {
    throw new Error('Invalid tunnel type: must be forward, reverse, or dynamic');
  }
  if (!sshTarget) throw new Error('sshTarget required (e.g., user@host)');
  if (!localPort) throw new Error('localPort required');

  // Validate SSH target format
  if (!/^[a-zA-Z0-9._\-]+@[a-zA-Z0-9.\-]+$/.test(sshTarget)) {
    throw new Error('Invalid sshTarget format — use user@host');
  }

  // Check port not in use (for forward and dynamic types)
  if (type !== 'reverse') {
    const inUse = await isPortInUse(localPort);
    if (inUse) throw new Error('Local port ' + localPort + ' is already in use');
  }

  const id = crypto.randomUUID();
  const tunnel = {
    id,
    type,
    sshTarget,
    localPort,
    remoteHost: remoteHost || 'localhost',
    remotePort: remotePort || localPort,
    sshPort: sshPort || 22,
    sshKey: sshKey || null,
    status: 'connecting',
    createdAt: new Date().toISOString(),
    reconnectDelay: BACKOFF_BASE,
    reconnectCount: 0,
    connectedSince: null,
    autoReconnect: autoReconnect !== false,
    process: null,
    pid: null,
  };

  await _startTunnelProcess(tunnel);
  return _tunnelSummary(tunnel);
}

/**
 * Start the actual SSH process for a tunnel
 */
async function _startTunnelProcess(tunnel) {
  const args = [
    '-N',                                    // No remote command
    '-o', 'StrictHostKeyChecking=no',
    '-o', 'ServerAliveInterval=15',          // Keep-alive every 15s
    '-o', 'ServerAliveCountMax=3',           // 3 missed = disconnect
    '-o', 'ExitOnForwardFailure=yes',        // Fail if port forward fails
    '-p', String(tunnel.sshPort),
  ];

  if (tunnel.sshKey) {
    args.push('-i', tunnel.sshKey);
  }

  // Build tunnel spec
  switch (tunnel.type) {
    case 'forward':
      args.push('-L', `${tunnel.localPort}:${tunnel.remoteHost}:${tunnel.remotePort}`);
      break;
    case 'reverse':
      args.push('-R', `${tunnel.remotePort}:localhost:${tunnel.localPort}`);
      break;
    case 'dynamic':
      args.push('-D', `127.0.0.1:${tunnel.localPort}`);
      break;
  }

  args.push(tunnel.sshTarget);

  const child = spawn('ssh', args, {
    stdio: ['pipe', 'pipe', 'pipe'],
    detached: false,
  });

  child.stdin.end();
  tunnel.process = child;
  tunnel.pid = child.pid;
  tunnel.status = 'connecting';

  activeTunnels.set(tunnel.id, tunnel);
  _persistTunnels();

  // Collect stderr for diagnostics
  let stderrBuf = '';
  child.stderr.on('data', (d) => { stderrBuf += d.toString(); });

  child.on('exit', (code, signal) => {
    console.log(`  [TUNNEL] ${tunnel.id.substring(0, 8)} (${tunnel.type}) exited: code=${code} signal=${signal}`);
    tunnel.process = null;
    tunnel.pid = null;

    if (tunnel.status === 'stopped') return; // Intentional stop

    if (tunnel.autoReconnect && tunnel.status !== 'stopped') {
      tunnel.status = 'reconnecting';
      tunnel.reconnectCount++;
      _persistTunnels();

      // Exponential backoff
      const delay = Math.min(tunnel.reconnectDelay, BACKOFF_MAX);
      console.log(`  [TUNNEL] Reconnecting ${tunnel.id.substring(0, 8)} in ${delay}ms (attempt ${tunnel.reconnectCount})`);

      setTimeout(() => {
        if (tunnel.status === 'stopped') return;
        _startTunnelProcess(tunnel).catch((e) => {
          console.error(`  [TUNNEL] Reconnect failed:`, e.message);
          tunnel.status = 'failed';
          tunnel.error = e.message;
          _persistTunnels();
        });
      }, delay);

      tunnel.reconnectDelay = Math.min(delay * 2, BACKOFF_MAX);
    } else {
      tunnel.status = 'failed';
      tunnel.error = stderrBuf.substring(0, 500) || 'SSH process exited';
      _persistTunnels();
    }
  });

  child.on('error', (err) => {
    console.error(`  [TUNNEL] Process error:`, err.message);
    tunnel.status = 'failed';
    tunnel.error = err.message;
    _persistTunnels();
  });

  // Wait for connection to establish
  await new Promise(r => setTimeout(r, 3000));

  // Verify connection
  if (tunnel.type !== 'reverse') {
    const healthy = await isPortListening(tunnel.localPort);
    if (healthy) {
      tunnel.status = 'connected';
      tunnel.connectedSince = Date.now();
      // Reset backoff on stable connection
      tunnel.reconnectDelay = BACKOFF_BASE;
      tunnel.error = null;
    }
  } else {
    // For reverse tunnels we can't easily verify from here
    if (tunnel.process && !tunnel.process.killed) {
      tunnel.status = 'connected';
      tunnel.connectedSince = Date.now();
      tunnel.reconnectDelay = BACKOFF_BASE;
      tunnel.error = null;
    }
  }

  _persistTunnels();
}

/**
 * Stop a tunnel
 */
function stopTunnel(id) {
  const tunnel = activeTunnels.get(id);
  if (!tunnel) throw new Error('Tunnel not found: ' + id);

  tunnel.status = 'stopped';
  tunnel.autoReconnect = false;

  if (tunnel.process) {
    try {
      tunnel.process.kill('SIGTERM');
      setTimeout(() => {
        if (tunnel.process && !tunnel.process.killed) {
          tunnel.process.kill('SIGKILL');
        }
      }, 2000);
    } catch {}
  }

  activeTunnels.delete(id);
  _persistTunnels();
  return { id, status: 'stopped' };
}

/**
 * List all tunnels
 */
function listTunnels() {
  const tunnels = [];
  for (const [, t] of activeTunnels) {
    tunnels.push(_tunnelSummary(t));
  }
  return {
    tunnels,
    totalCount: tunnels.length,
    connectedCount: tunnels.filter(t => t.status === 'connected').length,
  };
}

/**
 * Get a specific tunnel
 */
function getTunnel(id) {
  const tunnel = activeTunnels.get(id);
  if (!tunnel) return null;
  return _tunnelSummary(tunnel);
}

/**
 * Health check a tunnel's local port
 */
async function checkTunnelHealth(id) {
  const tunnel = activeTunnels.get(id);
  if (!tunnel) return { healthy: false, error: 'Tunnel not found' };

  if (tunnel.type === 'reverse') {
    // For reverse tunnels, check process is alive
    const alive = tunnel.process && !tunnel.process.killed;
    return { healthy: alive, type: 'reverse', pid: tunnel.pid };
  }

  const listening = await isPortListening(tunnel.localPort);
  if (listening && tunnel.status !== 'connected') {
    tunnel.status = 'connected';
    tunnel.connectedSince = Date.now();
    tunnel.reconnectDelay = BACKOFF_BASE;
    _persistTunnels();
  }
  return { healthy: listening, port: tunnel.localPort, status: tunnel.status };
}

function _tunnelSummary(t) {
  let spec = '';
  switch (t.type) {
    case 'forward': spec = `L:${t.localPort} → ${t.remoteHost}:${t.remotePort}`; break;
    case 'reverse': spec = `R:${t.remotePort} ← localhost:${t.localPort}`; break;
    case 'dynamic': spec = `D:${t.localPort} (SOCKS5)`; break;
  }
  return {
    id: t.id,
    type: t.type,
    sshTarget: t.sshTarget,
    localPort: t.localPort,
    remoteHost: t.remoteHost,
    remotePort: t.remotePort,
    spec,
    status: t.status,
    pid: t.pid,
    createdAt: t.createdAt,
    reconnectCount: t.reconnectCount,
    connectedSince: t.connectedSince ? new Date(t.connectedSince).toISOString() : null,
    autoReconnect: t.autoReconnect,
    error: t.error || null,
  };
}

function _persistTunnels() {
  const tunnels = [];
  for (const [, t] of activeTunnels) {
    tunnels.push({
      id: t.id, type: t.type, sshTarget: t.sshTarget,
      localPort: t.localPort, remoteHost: t.remoteHost, remotePort: t.remotePort,
      sshPort: t.sshPort, sshKey: t.sshKey, status: t.status,
      createdAt: t.createdAt, reconnectCount: t.reconnectCount,
      autoReconnect: t.autoReconnect, error: t.error,
    });
  }
  writeJSON(TUNNELS_PATH, tunnels);
}

// ═══════════════════════════════════════════════════════════════════════════
// CALLBACK LISTENER — OOB vulnerability detection
// ═══════════════════════════════════════════════════════════════════════════

let callbackServer = null;
let callbackPort = null;
let callbackSecret = null; // Unique token in URL path for filtering noise

// ═══════════════════════════════════════════════════════════════════════════
// PAYLOAD HOSTING — fluffy-barnacle cs-serve inspired
// ═══════════════════════════════════════════════════════════════════════════

/** @type {Map<string, HostedPayload>} */
const hostedPayloads = new Map();

const PAYLOADS_PATH = path.join(DATA, 'hosted-payloads.json');

/**
 * SSRF redirect presets — common internal metadata endpoints
 */
const SSRF_PRESETS = [
  { name: 'AWS Metadata (IMDSv1)', target: 'http://169.254.169.254/latest/meta-data/', description: 'AWS EC2 instance metadata service' },
  { name: 'AWS IAM Credentials', target: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', description: 'AWS IAM role credentials' },
  { name: 'AWS User Data', target: 'http://169.254.169.254/latest/user-data/', description: 'EC2 user-data scripts (may contain secrets)' },
  { name: 'GCP Metadata', target: 'http://metadata.google.internal/computeMetadata/v1/?recursive=true', description: 'GCP instance metadata (requires Metadata-Flavor header)' },
  { name: 'GCP Service Account Token', target: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', description: 'GCP OAuth token for attached service account' },
  { name: 'Azure Metadata', target: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', description: 'Azure Instance Metadata Service (IMDS)' },
  { name: 'Azure Managed Identity', target: 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/', description: 'Azure managed identity token' },
  { name: 'DigitalOcean Metadata', target: 'http://169.254.169.254/metadata/v1/', description: 'DigitalOcean droplet metadata' },
  { name: 'Kubernetes API', target: 'https://kubernetes.default.svc/api/v1/namespaces', description: 'K8s API server namespace listing' },
  { name: 'Kubernetes Secrets', target: 'https://kubernetes.default.svc/api/v1/namespaces/default/secrets', description: 'K8s secrets in default namespace' },
  { name: 'Docker Socket', target: 'http://127.0.0.1:2375/containers/json', description: 'Docker Engine API — list containers' },
  { name: 'Consul Agent', target: 'http://127.0.0.1:8500/v1/agent/self', description: 'HashiCorp Consul agent info' },
];

/**
 * Add a hosted payload (file or redirect)
 * @param {object} options
 * @param {string} options.type - 'file' or 'redirect'
 * @param {string} options.path - URL path to serve at (e.g., '/payload')
 * @param {string} [options.content] - file content (for type='file')
 * @param {string} [options.contentType] - MIME type (for type='file', default 'text/html')
 * @param {string} [options.target] - redirect target URL (for type='redirect')
 * @param {number} [options.statusCode] - redirect status code (default 302)
 * @param {string} [options.description] - human-readable description
 */
function addPayload(options) {
  const { type, content, contentType, target, statusCode, description } = options;
  let payloadPath = options.path;

  if (!type || !['file', 'redirect'].includes(type)) {
    throw new Error('type must be "file" or "redirect"');
  }
  if (!payloadPath || typeof payloadPath !== 'string') {
    throw new Error('path is required');
  }
  if (!payloadPath.startsWith('/')) payloadPath = '/' + payloadPath;
  if (type === 'redirect' && !target) {
    throw new Error('target URL required for redirects');
  }
  if (type === 'file' && !content) {
    throw new Error('content required for file payloads');
  }

  const id = crypto.randomUUID();
  const payload = {
    id,
    type,
    path: payloadPath,
    content: type === 'file' ? content : null,
    contentType: contentType || 'text/html',
    target: type === 'redirect' ? target : null,
    statusCode: type === 'redirect' ? (statusCode || 302) : null,
    description: description || '',
    createdAt: new Date().toISOString(),
    hitCount: 0,
  };

  hostedPayloads.set(id, payload);
  _persistPayloads();

  return { id, type, path: payloadPath, description: payload.description, createdAt: payload.createdAt };
}

/**
 * Remove a hosted payload
 */
function removePayload(id) {
  if (!hostedPayloads.has(id)) throw new Error('Payload not found: ' + id);
  hostedPayloads.delete(id);
  _persistPayloads();
  return { id, removed: true };
}

/**
 * List all hosted payloads
 */
function listPayloads() {
  const payloads = [];
  for (const [, p] of hostedPayloads) {
    payloads.push({
      id: p.id, type: p.type, path: p.path,
      contentType: p.contentType, target: p.target,
      statusCode: p.statusCode, description: p.description,
      createdAt: p.createdAt, hitCount: p.hitCount,
    });
  }
  return { payloads, count: payloads.length };
}

/**
 * Get SSRF redirect presets
 */
function getSSRFPresets() {
  return SSRF_PRESETS;
}

function _persistPayloads() {
  const payloads = [];
  for (const [, p] of hostedPayloads) {
    payloads.push({
      id: p.id, type: p.type, path: p.path,
      content: p.content, contentType: p.contentType,
      target: p.target, statusCode: p.statusCode,
      description: p.description, createdAt: p.createdAt,
      hitCount: p.hitCount,
    });
  }
  writeJSON(PAYLOADS_PATH, payloads);
}

// Load persisted payloads on startup
try {
  const saved = readJSON(PAYLOADS_PATH, []);
  for (const p of saved) {
    hostedPayloads.set(p.id, p);
  }
} catch {}

/**
 * Check if a request matches a hosted payload and serve it
 * @returns {boolean} true if handled
 */
function _servePayload(req, res) {
  const reqPath = req.url.split('?')[0];
  for (const [, payload] of hostedPayloads) {
    if (payload.path === reqPath) {
      payload.hitCount++;
      _persistPayloads();
      if (payload.type === 'redirect') {
        res.writeHead(payload.statusCode || 302, { 'Location': payload.target });
        res.end();
      } else {
        res.writeHead(200, { 'Content-Type': payload.contentType || 'text/html' });
        res.end(payload.content || '');
      }
      return true;
    }
  }
  return false;
}

/**
 * Start callback listener HTTP server
 * @param {number} port - port to listen on
 * @returns {object} listener info with secret URL path
 */
function startCallbackListener(port) {
  if (callbackServer) {
    throw new Error('Callback listener already running on port ' + callbackPort);
  }

  port = port || 9999;
  callbackSecret = crypto.randomBytes(8).toString('hex');

  const server = http.createServer((req, res) => {
    // Check hosted payloads first (fluffy-barnacle cs-serve)
    if (_servePayload(req, res)) {
      // Also log the hit as a callback entry
      const entry = {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.url,
        path: req.url.split('?')[0],
        query: req.url.includes('?') ? req.url.split('?')[1] : null,
        headers: _sanitizeHeaders(req.headers),
        sourceIP: req.socket.remoteAddress,
        sourcePort: req.socket.remotePort,
        body: null,
        userAgent: req.headers['user-agent'] || null,
        contentType: req.headers['content-type'] || null,
        isTargeted: true,
        isPayload: true,
      };
      const log = readJSON(CALLBACK_LOG_PATH, []);
      log.push(entry);
      if (log.length > 500) log.splice(0, log.length - 500);
      writeJSON(CALLBACK_LOG_PATH, log);
      console.log(`  [CALLBACK] PAYLOAD HIT: ${entry.method} ${entry.url} from ${entry.sourceIP}`);
      return;
    }

    // Capture full request
    let body = '';
    req.on('data', (chunk) => { body += chunk.toString().substring(0, 10000); });
    req.on('end', () => {
      const entry = {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.url,
        path: req.url.split('?')[0],
        query: req.url.includes('?') ? req.url.split('?')[1] : null,
        headers: _sanitizeHeaders(req.headers),
        sourceIP: req.socket.remoteAddress,
        sourcePort: req.socket.remotePort,
        body: body || null,
        userAgent: req.headers['user-agent'] || null,
        contentType: req.headers['content-type'] || null,
        // Check if it matches our secret path (indicates intentional callback)
        isTargeted: req.url.includes(callbackSecret),
      };

      // Log to file
      const log = readJSON(CALLBACK_LOG_PATH, []);
      log.push(entry);
      if (log.length > 500) log.splice(0, log.length - 500);
      writeJSON(CALLBACK_LOG_PATH, log);

      console.log(`  [CALLBACK] ${entry.method} ${entry.url} from ${entry.sourceIP} ${entry.isTargeted ? '(TARGETED)' : ''}`);

      // Respond with a generic 200 (don't reveal we're a callback listener)
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('OK');
    });
  });

  server.listen(port, '0.0.0.0', () => {
    console.log(`  [CALLBACK] Listener started on port ${port} (secret: ${callbackSecret})`);
  });

  server.on('error', (err) => {
    console.error(`  [CALLBACK] Server error:`, err.message);
    callbackServer = null;
    callbackPort = null;
    callbackSecret = null;
  });

  callbackServer = server;
  callbackPort = port;

  return {
    port,
    secret: callbackSecret,
    callbackURL: `http://VIGIL_IP:${port}/${callbackSecret}`,
    status: 'listening',
    startedAt: new Date().toISOString(),
  };
}

/**
 * Stop callback listener
 */
function stopCallbackListener() {
  if (!callbackServer) return { status: 'not_running' };
  callbackServer.close();
  const oldPort = callbackPort;
  callbackServer = null;
  callbackPort = null;
  callbackSecret = null;
  return { status: 'stopped', port: oldPort };
}

/**
 * Get callback listener status
 */
function getCallbackStatus() {
  if (!callbackServer) {
    return { running: false };
  }
  const log = readJSON(CALLBACK_LOG_PATH, []);
  const targeted = log.filter(e => e.isTargeted);
  return {
    running: true,
    port: callbackPort,
    secret: callbackSecret,
    callbackURL: `http://VIGIL_IP:${callbackPort}/${callbackSecret}`,
    totalRequests: log.length,
    targetedRequests: targeted.length,
    lastRequest: log.length > 0 ? log[log.length - 1].timestamp : null,
    startedAt: callbackServer._startedAt || null,
  };
}

/**
 * Get callback log entries
 * @param {object} [options]
 * @param {boolean} [options.targetedOnly] - only show requests matching secret
 * @param {number} [options.limit] - max entries
 */
function getCallbackLog(options = {}) {
  const log = readJSON(CALLBACK_LOG_PATH, []);
  let entries = log;
  if (options.targetedOnly) {
    entries = entries.filter(e => e.isTargeted);
  }
  if (options.limit) {
    entries = entries.slice(-options.limit);
  }
  return entries.reverse(); // newest first
}

/**
 * Clear callback log
 */
function clearCallbackLog() {
  writeJSON(CALLBACK_LOG_PATH, []);
  return { cleared: true };
}

/**
 * Sanitize headers — remove potentially sensitive values but keep names
 */
function _sanitizeHeaders(headers) {
  const safe = {};
  for (const [k, v] of Object.entries(headers)) {
    safe[k] = typeof v === 'string' ? v.substring(0, 500) : String(v);
  }
  return safe;
}

// ═══════════════════════════════════════════════════════════════════════════
// PORT UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

function isPortInUse(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', () => resolve(true));
    server.once('listening', () => { server.close(); resolve(false); });
    server.listen(port, '127.0.0.1');
  });
}

function isPortListening(port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(3000);
    socket.connect(port, '127.0.0.1', () => { socket.destroy(); resolve(true); });
    socket.on('error', () => { socket.destroy(); resolve(false); });
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
  });
}

/**
 * Find next available port starting from base
 */
async function findAvailablePort(base = 8080) {
  for (let p = base; p < base + 100; p++) {
    const inUse = await isPortInUse(p);
    if (!inUse) return p;
  }
  throw new Error('No available port found in range ' + base + '-' + (base + 99));
}

// ═══════════════════════════════════════════════════════════════════════════
// CLEANUP
// ═══════════════════════════════════════════════════════════════════════════

function stopAll() {
  for (const [id] of activeTunnels) {
    try { stopTunnel(id); } catch {}
  }
  try { stopCallbackListener(); } catch {}
}

// Cleanup on process exit
process.on('exit', stopAll);
process.on('SIGTERM', stopAll);

module.exports = {
  // Tunnel management
  createTunnel,
  stopTunnel,
  listTunnels,
  getTunnel,
  checkTunnelHealth,
  // Callback listener
  startCallbackListener,
  stopCallbackListener,
  getCallbackStatus,
  getCallbackLog,
  clearCallbackLog,
  // Payload hosting (fluffy-barnacle cs-serve inspired)
  addPayload,
  removePayload,
  listPayloads,
  getSSRFPresets,
  // Utilities
  findAvailablePort,
  isPortInUse,
  isPortListening,
};
