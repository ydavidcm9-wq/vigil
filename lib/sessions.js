// Vigil — Session token management
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SESSIONS_FILE = path.join(__dirname, '..', 'data', 'sessions.json');
const SESSION_TTL = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Load sessions from file
 * @returns {object} - Map of token -> session data
 */
function loadSessions() {
  try {
    if (!fs.existsSync(SESSIONS_FILE)) return {};
    const data = fs.readFileSync(SESSIONS_FILE, 'utf8');
    return JSON.parse(data);
  } catch {
    return {};
  }
}

/**
 * Save sessions to file
 * @param {object} sessions
 */
function saveSessions(sessions) {
  try {
    const dir = path.dirname(SESSIONS_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessions, null, 2));
  } catch (err) {
    console.error('  Sessions: error saving —', err.message);
  }
}

/**
 * Create a new session
 * @param {string} username
 * @param {string} role
 * @returns {string} - Session token
 */
function createSession(username, role) {
  const sessions = loadSessions();
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();

  sessions[token] = {
    username,
    role,
    created: now,
    expires: now + SESSION_TTL,
    lastAccess: now
  };

  saveSessions(sessions);
  return token;
}

/**
 * Look up a session by token
 * @param {string} token
 * @returns {object|null} - Session data or null if invalid/expired
 */
function getSession(token) {
  if (!token) return null;

  const sessions = loadSessions();
  const session = sessions[token];

  if (!session) return null;

  // Check expiry
  if (Date.now() > session.expires) {
    delete sessions[token];
    saveSessions(sessions);
    return null;
  }

  // Update last access — always save to prevent stale data
  session.lastAccess = Date.now();
  sessions[token] = session;
  saveSessions(sessions);

  return {
    username: session.username,
    role: session.role,
    created: session.created,
    expires: session.expires
  };
}

/**
 * Delete a session (logout)
 * @param {string} token
 * @returns {boolean}
 */
function deleteSession(token) {
  if (!token) return false;
  const sessions = loadSessions();
  if (!sessions[token]) return false;
  delete sessions[token];
  saveSessions(sessions);
  return true;
}

/**
 * Remove all expired sessions
 * @returns {number} - Number of sessions cleaned
 */
function cleanExpired() {
  const sessions = loadSessions();
  const now = Date.now();
  let cleaned = 0;

  for (const token in sessions) {
    if (now > sessions[token].expires) {
      delete sessions[token];
      cleaned++;
    }
  }

  if (cleaned > 0) {
    saveSessions(sessions);
    console.log('  Sessions: cleaned ' + cleaned + ' expired');
  }

  return cleaned;
}

/**
 * Get count of active sessions
 * @returns {number}
 */
function getActiveCount() {
  const sessions = loadSessions();
  const now = Date.now();
  return Object.values(sessions).filter(s => now <= s.expires).length;
}

/**
 * Delete all sessions for a user
 * @param {string} username
 * @returns {number} - Number of sessions deleted
 */
function deleteUserSessions(username) {
  const sessions = loadSessions();
  let deleted = 0;
  for (const token in sessions) {
    if (sessions[token].username === username) {
      delete sessions[token];
      deleted++;
    }
  }
  if (deleted > 0) saveSessions(sessions);
  return deleted;
}

module.exports = {
  createSession,
  getSession,
  deleteSession,
  cleanExpired,
  getActiveCount,
  deleteUserSessions
};
