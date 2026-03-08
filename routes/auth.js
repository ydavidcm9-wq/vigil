/**
 * Auth Routes — Login, logout, session, password, 2FA
 */
const { getUsers, getUser, verifyPassword, updateUser } = require('../lib/users');
const { createSession, deleteSession } = require('../lib/sessions');

function escapeHtml(s) { return String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }

// Rate limiting
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW = 15 * 60 * 1000;

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

module.exports = function (app, ctx) {

  // POST /api/auth/login
  app.post('/api/auth/login', (req, res) => {
    try {
      const ip = req.ip || req.socket.remoteAddress;
      if (!checkRateLimit(ip)) {
        return res.status(429).json({ error: 'Too many login attempts. Try again in 15 minutes.' });
      }
      const { username, password } = req.body || {};
      if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

      const user = getUser(username);
      if (!user || !verifyPassword(password, user.password)) {
        recordFailedLogin(ip);
        console.log('[AUTH] Failed login: ' + escapeHtml(username) + ' from ' + ip);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      loginAttempts.delete(ip);

      // If 2FA is enabled, require TOTP
      if (user.twoFactor) {
        return res.json({ requires2FA: true, message: 'Enter your 2FA code' });
      }

      const token = createSession(user.username, user.role);
      const secure = req.secure || req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
      res.setHeader('Set-Cookie', 'vigil_session=' + token + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400' + secure);
      console.log('[AUTH] Login: ' + user.username + ' from ' + ip);
      res.json({ success: true, user: { username: user.username, role: user.role } });
    } catch (e) {
      console.error('[AUTH] Login error:', e.message);
      res.status(500).json({ error: 'Login failed' });
    }
  });

  // POST /api/auth/logout
  app.post('/api/auth/logout', (req, res) => {
    const token = req.cookies && req.cookies.vigil_session;
    if (token) deleteSession(token);
    res.setHeader('Set-Cookie', 'vigil_session=; Path=/; HttpOnly; Max-Age=0');
    res.json({ success: true });
  });

  // GET /api/auth/session
  app.get('/api/auth/session', ctx.requireAuth, (req, res) => {
    res.json({
      username: req.user.username,
      role: req.user.role
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
      const { generateSecret, generateQRData } = require('../lib/totp');
      const secret = generateSecret();
      updateUser(req.user.username, { twoFactor: secret });
      const qrData = generateQRData(secret, req.user.username);
      res.json({ secret, qrData });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/auth/2fa/verify
  app.post('/api/auth/2fa/verify', ctx.requireAuth, (req, res) => {
    try {
      const { verifyToken } = require('../lib/totp');
      const { code } = req.body || {};
      if (!code) return res.status(400).json({ error: 'Code required' });

      const user = getUser(req.user.username);
      if (!user || !user.twoFactor) return res.status(400).json({ error: 'Run 2FA setup first' });
      const result = verifyToken(user.twoFactor, code, req.user.username);
      if (result === 'rate_limited') return res.status(429).json({ error: 'Too many 2FA attempts. Wait 5 minutes.' });
      if (!result) return res.status(400).json({ error: 'Invalid code' });

      console.log('[AUTH] 2FA verified for: ' + req.user.username);
      res.json({ success: true, message: '2FA enabled' });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // Health check handled in server.js — removed duplicate here
};
