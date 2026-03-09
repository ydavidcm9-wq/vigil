const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const { getCurrentToken } = require('../lib/totp');

const ROOT = path.join(__dirname, '..');
const DATA_DIR = path.join(ROOT, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const CREDENTIALS_FILE = path.join(DATA_DIR, 'credentials.json');
const SSH_KEY_DIR = path.join(DATA_DIR, 'ssh-keys');

const TEST_USER = `release_admin_${process.pid}`;
const TEST_PASS = 'ReleaseTestPass123!';
const TEST_ENCRYPTION_KEY = randomBytes(32).toString('hex');
const FILES_TO_ISOLATE = [USERS_FILE, SESSIONS_FILE, CREDENTIALS_FILE];

let serverProcess = null;
let baseUrl = '';
let cookieJar = new Map();
let fileBackups = new Map();
let sshKeyDirExisted = false;

function backupFile(filePath) {
  return fs.existsSync(filePath) ? fs.readFileSync(filePath) : null;
}

function restoreFile(filePath, backup) {
  if (backup === null) {
    if (fs.existsSync(filePath)) fs.rmSync(filePath, { force: true });
    return;
  }

  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, backup);
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function getFreePort() {
  return await new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const address = srv.address();
      srv.close((err) => {
        if (err) return reject(err);
        resolve(address.port);
      });
    });
  });
}

async function waitForServer(url) {
  const start = Date.now();
  while (Date.now() - start < 15000) {
    if (serverProcess && serverProcess.exitCode !== null) {
      throw new Error(`server exited early with code ${serverProcess.exitCode}`);
    }

    try {
      const res = await fetch(`${url}/api/health`);
      if (res.ok) return;
    } catch {}

    await new Promise(resolve => setTimeout(resolve, 250));
  }

  throw new Error('timed out waiting for server health check');
}

function updateCookies(res) {
  const getSetCookie = res.headers.getSetCookie;
  const setCookies = typeof getSetCookie === 'function'
    ? getSetCookie.call(res.headers)
    : (res.headers.get('set-cookie') ? [res.headers.get('set-cookie')] : []);

  for (const raw of setCookies) {
    const pair = raw.split(';')[0];
    const idx = pair.indexOf('=');
    if (idx === -1) continue;
    cookieJar.set(pair.slice(0, idx).trim(), pair.slice(idx + 1).trim());
  }
}

function cookieHeader() {
  return Array.from(cookieJar.entries()).map(([key, value]) => `${key}=${value}`).join('; ');
}

async function api(pathname, options = {}) {
  const method = String(options.method || 'GET').toUpperCase();
  const headers = new Headers(options.headers || {});

  if (options.body !== undefined) {
    headers.set('Content-Type', 'application/json');
  }
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    headers.set('X-Requested-With', 'Vigil-Test');
  }

  const cookie = cookieHeader();
  if (cookie) headers.set('Cookie', cookie);

  const res = await fetch(`${baseUrl}${pathname}`, {
    method,
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined
  });
  updateCookies(res);

  const text = await res.text();
  return {
    res,
    body: parseJson(text),
    text
  };
}

test.before(async () => {
  sshKeyDirExisted = fs.existsSync(SSH_KEY_DIR);
  for (const filePath of FILES_TO_ISOLATE) {
    fileBackups.set(filePath, backupFile(filePath));
    if (fs.existsSync(filePath)) fs.rmSync(filePath, { force: true });
  }
  if (!sshKeyDirExisted && fs.existsSync(SSH_KEY_DIR)) {
    fs.rmSync(SSH_KEY_DIR, { recursive: true, force: true });
  }

  const port = await getFreePort();
  baseUrl = `http://127.0.0.1:${port}`;

  serverProcess = spawn(process.execPath, ['server.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      VIGIL_PORT: String(port),
      VIGIL_USER: TEST_USER,
      VIGIL_PASS: TEST_PASS,
      ENCRYPTION_KEY: TEST_ENCRYPTION_KEY,
      NODE_ENV: 'test'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  serverProcess.stdout.on('data', () => {});
  serverProcess.stderr.on('data', () => {});

  await waitForServer(baseUrl);
});

test.after(async () => {
  if (serverProcess && serverProcess.exitCode === null) {
    serverProcess.kill('SIGINT');
    await new Promise(resolve => serverProcess.once('exit', resolve));
  }

  for (const [filePath, backup] of fileBackups.entries()) {
    restoreFile(filePath, backup);
  }

  if (!sshKeyDirExisted && fs.existsSync(SSH_KEY_DIR)) {
    fs.rmSync(SSH_KEY_DIR, { recursive: true, force: true });
  }
});

test('release auth and credential flows work end-to-end', async () => {
  cookieJar = new Map();

  const anonCheck = await api('/api/auth/check');
  assert.equal(anonCheck.res.status, 200);
  assert.deepEqual(anonCheck.body, { authenticated: false });

  const login = await api('/api/auth/login', {
    method: 'POST',
    body: { username: TEST_USER, password: TEST_PASS }
  });
  assert.equal(login.res.status, 200);
  assert.equal(login.body.success, true);
  assert.equal(login.body.user.username, TEST_USER);
  assert.ok(cookieJar.get('vigil_session'));

  const session = await api('/api/auth/session');
  assert.equal(session.res.status, 200);
  assert.equal(session.body.username, TEST_USER);
  assert.equal(session.body.twoFactorEnabled, false);

  const check = await api('/api/auth/check');
  assert.equal(check.body.authenticated, true);
  assert.equal(check.body.user.username, TEST_USER);

  const setup2FA = await api('/api/auth/2fa/setup', { method: 'POST', body: {} });
  assert.equal(setup2FA.res.status, 200);
  assert.ok(setup2FA.body.secret);
  assert.ok(setup2FA.body.qrData.includes(setup2FA.body.secret));

  const verify2FA = await api('/api/auth/2fa/verify', {
    method: 'POST',
    body: { code: getCurrentToken(setup2FA.body.secret) }
  });
  assert.equal(verify2FA.res.status, 200);
  assert.equal(verify2FA.body.success, true);

  const sessionAfter2FA = await api('/api/auth/session');
  assert.equal(sessionAfter2FA.body.twoFactorEnabled, true);

  const logout = await api('/api/auth/logout', { method: 'POST', body: {} });
  assert.equal(logout.res.status, 200);

  cookieJar = new Map();

  const loginNeeds2FA = await api('/api/auth/login', {
    method: 'POST',
    body: { username: TEST_USER, password: TEST_PASS }
  });
  assert.equal(loginNeeds2FA.res.status, 200);
  assert.equal(loginNeeds2FA.body.requires2FA, true);
  assert.ok(loginNeeds2FA.body.challengeToken);

  const login2FA = await api('/api/auth/login/2fa', {
    method: 'POST',
    body: {
      challengeToken: loginNeeds2FA.body.challengeToken,
      code: getCurrentToken(setup2FA.body.secret)
    }
  });
  assert.equal(login2FA.res.status, 200);
  assert.equal(login2FA.body.success, true);
  assert.ok(cookieJar.get('vigil_session'));

  const createCredential = await api('/api/credentials', {
    method: 'POST',
    body: {
      name: 'release-test-key',
      type: 'ssh_key',
      secret: '-----BEGIN TEST KEY-----\nabc123\n-----END TEST KEY-----',
      host: '127.0.0.1',
      port: 2222,
      username: 'root',
      tags: ['release', 'test']
    }
  });
  assert.equal(createCredential.res.status, 200);
  assert.equal(createCredential.body.success, true);
  assert.ok(createCredential.body.id);

  const listCredentials = await api('/api/credentials');
  assert.equal(listCredentials.res.status, 200);
  assert.equal(Array.isArray(listCredentials.body.credentials), true);
  assert.equal(listCredentials.body.credentials.length, 1);
  assert.equal(listCredentials.body.credentials[0].id, createCredential.body.id);
  assert.equal(listCredentials.body.credentials[0].host, '127.0.0.1');

  const getCredential = await api(`/api/credentials/${createCredential.body.id}`);
  assert.equal(getCredential.res.status, 200);
  assert.equal(getCredential.body.secret.includes('BEGIN TEST KEY'), true);
  assert.equal(getCredential.body.username, 'root');

  const injectCredential = await api(`/api/credentials/${createCredential.body.id}/inject`, {
    method: 'POST',
    body: {}
  });
  assert.equal(injectCredential.res.status, 200);
  assert.equal(injectCredential.body.success, true);
  assert.match(injectCredential.body.command, /^ssh -i ".+\.key" -p 2222 root@127\.0\.0\.1$/);

  const deleteCredential = await api(`/api/credentials/${createCredential.body.id}`, {
    method: 'DELETE',
    body: {}
  });
  assert.equal(deleteCredential.res.status, 200);
  assert.equal(deleteCredential.body.success, true);

  const emptyList = await api('/api/credentials');
  assert.equal(emptyList.res.status, 200);
  assert.equal(emptyList.body.credentials.length, 0);
});
