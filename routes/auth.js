/**
 * Auth Routes — Login, logout, session, password, 2FA
 */
const crypto = require('crypto');
const { getUser, verifyPassword, updateUser } = require('../lib/users');
const { createSession, getSession, deleteSession } = require('../lib/sessions');
const { generateSecret, generateQRData, verifyToken } = require('../lib/totp');

function escapeHtml(s) { return String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }

// Rate limiting
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW = 15 * 60 * 1000;
const LOGIN_CHALLENGE_TTL = 5 * 60 * 1000;
const pendingLoginChallenges = new Map();

function checkRateLimit(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry) return true;
  if (Date.now() - entry.firstAttempt > LOGIN_WINDOW) { loginAttempts.delete(ip); return true; }
  return entry.count < MAX_LOGIN_ATTEMPTS;
}

function recordFailedLogin(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry) loginAttempts.set(ip, { count: 1, firstAttempt: Date.now() });
  else entry.count++;
}

function setSessionCookie(req, res, token, maxAge = 86400) {
  const secure = req.secure || req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `vigil_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`);
}

function clearSessionCookie(req, res) {
  const secure = req.secure || req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `vigil_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`);
}

function clearExpiredLoginChallenges() {
  const now = Date.now();
  for (const [token, challenge] of pendingLoginChallenges.entries()) {
    if (challenge.expiresAt <= now) {
      pendingLoginChallenges.delete(token);
    }
  }
}

function createLoginChallenge(user, ip) {
  clearExpiredLoginChallenges();
  const token = crypto.randomBytes(32).toString('hex');
  pendingLoginChallenges.set(token, {
    username: user.username,
    role: user.role,
    ip,
    expiresAt: Date.now() + LOGIN_CHALLENGE_TTL
  });
  return token;
}

function getLoginChallenge(token, ip) {
  clearExpiredLoginChallenges();
  const challenge = pendingLoginChallenges.get(token);
  if (!challenge) return null;
  if (challenge.ip !== ip) return null;
  return challenge;
}

function consumeLoginChallenge(token) {
  pendingLoginChallenges.delete(token);
}

function getCurrentSession(req) {
  const token = req.cookies && req.cookies.vigil_session
    ? req.cookies.vigil_session
    : (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')
      ? req.headers.authorization.slice(7)
      : null);

  if (!token) return null;
  return getSession(token);
}

setInterval(clearExpiredLoginChallenges, 60000).unref();

module.exports = function (app, ctx) {

  // POST /api/auth/login
  app.post('/api/auth/login', (req, res) => {
    try {
      const ip = req.ip || req.socket.remoteAddress;
      if (!checkRateLimit(ip)) {
        return res.status(429).json({ error: 'Too many login attempts. Try again in 15 minutes.' });
      }
      const { username, email, password } = req.body || {};
      const login = String(username || email || '').trim();
      if (!login || !password) return res.status(400).json({ error: 'Username and password required' });

      const user = getUser(login);
      if (!user || !verifyPassword(password, user.password)) {
        recordFailedLogin(ip);
        console.log('[AUTH] Failed login: ' + escapeHtml(login) + ' from ' + ip);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      loginAttempts.delete(ip);

      // If 2FA is enabled, require TOTP
      if (user.twoFactor) {
        return res.json({
          requires2FA: true,
          challengeToken: createLoginChallenge(user, ip),
          username: user.username,
          message: 'Enter your 2FA code'
        });
      }

      const token = createSession(user.username, user.role);
      setSessionCookie(req, res, token);
      console.log('[AUTH] Login: ' + user.username + ' from ' + ip);
      res.json({ success: true, user: { username: user.username, role: user.role } });
    } catch (e) {
      console.error('[AUTH] Login error:', e.message);
      res.status(500).json({ error: 'Login failed' });
    }
  });

  // POST /api/auth/login/2fa
  app.post('/api/auth/login/2fa', (req, res) => {
    try {
      const ip = req.ip || req.socket.remoteAddress;
      const { challengeToken, code } = req.body || {};
      if (!challengeToken || !code) {
        return res.status(400).json({ error: 'challengeToken and code required' });
      }

      const challenge = getLoginChallenge(challengeToken, ip);
      if (!challenge) {
        return res.status(401).json({ error: 'Invalid or expired 2FA challenge' });
      }

      const user = getUser(challenge.username);
      if (!user || !user.twoFactor) {
        consumeLoginChallenge(challengeToken);
        return res.status(401).json({ error: '2FA is not enabled for this user' });
      }

      const result = verifyToken(user.twoFactor, code, user.username);
      if (result === 'rate_limited') {
        return res.status(429).json({ error: 'Too many 2FA attempts. Wait 5 minutes.' });
      }
      if (!result) {
        return res.status(400).json({ error: 'Invalid code' });
      }

      consumeLoginChallenge(challengeToken);
      const token = createSession(user.username, user.role);
      setSessionCookie(req, res, token);
      console.log('[AUTH] Login with 2FA: ' + user.username + ' from ' + ip);
      res.json({ success: true, user: { username: user.username, role: user.role } });
    } catch (e) {
      console.error('[AUTH] 2FA login error:', e.message);
      res.status(500).json({ error: '2FA login failed' });
    }
  });

  // POST /api/auth/logout
  app.post('/api/auth/logout', (req, res) => {
    const token = req.cookies && req.cookies.vigil_session;
    if (token) deleteSession(token);
    clearSessionCookie(req, res);
    res.json({ success: true });
  });

  // GET /api/auth/check
  app.get('/api/auth/check', (req, res) => {
    const session = getCurrentSession(req);
    if (!session) {
      return res.json({ authenticated: false });
    }

    res.json({
      authenticated: true,
      user: {
        username: session.username,
        role: session.role
      }
    });
  });

  // GET /api/auth/session
  app.get('/api/auth/session', ctx.requireAuth, (req, res) => {
    const user = getUser(req.user.username);
    res.json({
      username: req.user.username,
      role: req.user.role,
      twoFactorEnabled: !!(user && user.twoFactor)
    });
  });

  // POST /api/auth/change-password
  app.post('/api/auth/change-password', ctx.requireAuth, (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body || {};
      if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Current and new password required' });
      if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
      // Block common weak passwords
      const weak = ['password', '12345678', 'password1', 'admin123', 'letmein1', 'qwerty12', 'changeme', 'admin', 'vigil123'];
      if (weak.includes(newPassword.toLowerCase())) return res.status(400).json({ error: 'Password is too common. Choose a stronger password.' });

      const user = getUser(req.user.username);
      if (!user) return res.status(404).json({ error: 'User not found' });
      if (!verifyPassword(currentPassword, user.password)) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }

      updateUser(req.user.username, { password: newPassword });
      console.log('[AUTH] Password changed for: ' + req.user.username);
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/auth/2fa/setup
  app.post('/api/auth/2fa/setup', ctx.requireAuth, (req, res) => {
    try {
      const secret = generateSecret();
      updateUser(req.user.username, { pendingTwoFactor: secret });
      const qrData = generateQRData(secret, req.user.username);
      res.json({ secret, qrData });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/auth/2fa/verify
  app.post('/api/auth/2fa/verify', ctx.requireAuth, (req, res) => {
    try {
      const { code } = req.body || {};
      if (!code) return res.status(400).json({ error: 'Code required' });

      const user = getUser(req.user.username);
      if (!user) return res.status(404).json({ error: 'User not found' });

      const secret = user.pendingTwoFactor || user.twoFactor;
      if (!secret) return res.status(400).json({ error: 'Run 2FA setup first' });

      const result = verifyToken(secret, code, req.user.username);
      if (result === 'rate_limited') return res.status(429).json({ error: 'Too many 2FA attempts. Wait 5 minutes.' });
      if (!result) return res.status(400).json({ error: 'Invalid code' });

      if (user.pendingTwoFactor) {
        updateUser(req.user.username, { twoFactor: user.pendingTwoFactor, pendingTwoFactor: null });
        console.log('[AUTH] 2FA enabled for: ' + req.user.username);
        return res.json({ success: true, message: '2FA enabled' });
      }

      console.log('[AUTH] 2FA verified for: ' + req.user.username);
      res.json({ success: true, message: '2FA verified' });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // Health check handled in server.js — removed duplicate here
};
