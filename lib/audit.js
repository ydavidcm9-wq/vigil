// Vigil — Structured audit logging
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const AUDIT_FILE = path.join(__dirname, '..', 'data', 'audit-log.json');
const MAX_ENTRIES = 10000;

/**
 * Load audit log from file
 * @returns {Array}
 */
function loadLog() {
  try {
    if (!fs.existsSync(AUDIT_FILE)) return [];
    const data = fs.readFileSync(AUDIT_FILE, 'utf8');
    return JSON.parse(data);
  } catch {
    return [];
  }
}

/**
 * Save audit log to file
 * @param {Array} entries
 */
function saveLog(entries) {
  try {
    const dir = path.dirname(AUDIT_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(AUDIT_FILE, JSON.stringify(entries, null, 2));
  } catch (err) {
    console.error('  Audit: error saving —', err.message);
  }
}

/**
 * Log an action to the audit trail
 * @param {string} user - Username or system identifier
 * @param {string} action - Action performed (e.g., 'login', 'scan.start', 'user.create')
 * @param {string} resource - Resource acted upon (e.g., 'session', 'scan:nmap', 'user:john')
 * @param {object} [details] - Additional context
 * @returns {object} - The created log entry
 */
function logAction(user, action, resource, details = {}) {
  const entries = loadLog();

  const entry = {
    id: crypto.randomBytes(12).toString('hex'),
    timestamp: new Date().toISOString(),
    user: user || 'system',
    action,
    resource: resource || '',
    details,
    ip: details.ip || null
  };

  entries.push(entry);

  // Trim to max entries (keep most recent)
  if (entries.length > MAX_ENTRIES) {
    entries.splice(0, entries.length - MAX_ENTRIES);
  }

  saveLog(entries);
  return entry;
}

/**
 * Query audit log with filters
 * @param {object} filters
 * @param {string} [filters.user] - Filter by username
 * @param {string} [filters.action] - Filter by action (prefix match)
 * @param {string} [filters.resource] - Filter by resource (prefix match)
 * @param {string} [filters.from] - Start date (ISO string)
 * @param {string} [filters.to] - End date (ISO string)
 * @param {number} [filters.limit] - Max results (default: 100)
 * @param {number} [filters.offset] - Offset for pagination
 * @returns {object} - { entries, total }
 */
function getAuditLog(filters = {}) {
  let entries = loadLog();

  // Apply filters
  if (filters.user) {
    entries = entries.filter(e => e.user === filters.user);
  }
  if (filters.action) {
    entries = entries.filter(e => e.action && e.action.startsWith(filters.action));
  }
  if (filters.resource) {
    entries = entries.filter(e => e.resource && e.resource.startsWith(filters.resource));
  }
  if (filters.from) {
    const fromDate = new Date(filters.from).getTime();
    entries = entries.filter(e => new Date(e.timestamp).getTime() >= fromDate);
  }
  if (filters.to) {
    const toDate = new Date(filters.to).getTime();
    entries = entries.filter(e => new Date(e.timestamp).getTime() <= toDate);
  }

  const total = entries.length;

  // Sort by most recent first
  entries.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  // Pagination
  const limit = filters.limit || 100;
  const offset = filters.offset || 0;
  entries = entries.slice(offset, offset + limit);

  return { entries, total };
}

/**
 * Express middleware that auto-logs API requests
 * @param {string} action - Action name for the log
 * @returns {Function}
 */
function autoLog(action) {
  return (req, res, next) => {
    const originalEnd = res.end;
    res.end = function (...args) {
      const user = req.user ? req.user.username : 'anonymous';
      const resource = req.params.id || req.params.name || req.originalUrl;
      logAction(user, action, resource, {
        method: req.method,
        path: req.originalUrl,
        status: res.statusCode,
        ip: req.ip || req.connection.remoteAddress
      });
      originalEnd.apply(res, args);
    };
    next();
  };
}

/**
 * Clear the entire audit log
 * @returns {boolean}
 */
function clearLog() {
  saveLog([]);
  return true;
}

module.exports = {
  logAction,
  getAuditLog,
  autoLog,
  clearLog
};
