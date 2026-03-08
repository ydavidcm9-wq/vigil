// Vigil — Role-Based Access Control
// Roles: admin > analyst > viewer

const ROLES = {
  admin: { level: 3, name: 'Admin', description: 'Full system access' },
  analyst: { level: 2, name: 'Analyst', description: 'Read + write, no admin actions' },
  viewer: { level: 1, name: 'Viewer', description: 'Read-only access' }
};

// Action-to-minimum-role mapping
const ACTION_ROLES = {
  // Read actions — viewer and above
  read: 'viewer',
  'view:dashboard': 'viewer',
  'view:threats': 'viewer',
  'view:posture': 'viewer',
  'view:logs': 'viewer',
  'view:reports': 'viewer',

  // Write actions — analyst and above
  write: 'analyst',
  'scan:run': 'analyst',
  'scan:schedule': 'analyst',
  'threat:acknowledge': 'analyst',
  'threat:investigate': 'analyst',
  'report:create': 'analyst',
  'report:export': 'analyst',
  'credential:view': 'analyst',
  'osint:run': 'analyst',

  // Admin actions — admin only
  admin: 'admin',
  'user:create': 'admin',
  'user:delete': 'admin',
  'user:modify': 'admin',
  'settings:modify': 'admin',
  'credential:create': 'admin',
  'credential:delete': 'admin',
  'system:restart': 'admin',
  'audit:clear': 'admin'
};

/**
 * Check if a role has sufficient level
 * @param {string} userRole - The user's role
 * @param {string} requiredRole - The minimum required role
 * @returns {boolean}
 */
function hasRole(userRole, requiredRole) {
  const user = ROLES[userRole];
  const required = ROLES[requiredRole];
  if (!user || !required) return false;
  return user.level >= required.level;
}

/**
 * Express middleware factory — require minimum role
 * @param {string} role - Minimum required role
 * @returns {Function} Express middleware
 */
function requireRole(role) {
  return (req, res, next) => {
    // If req.user not yet set, run auth first
    if (!req.user) {
      const token = req.cookies && req.cookies.vigil_session ||
        (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')
          ? req.headers.authorization.slice(7) : null);
      if (token) {
        try {
          const { getSession } = require('./sessions');
          const session = getSession(token);
          if (session) req.user = { username: session.username, role: session.role };
        } catch {}
      }
    }
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    if (!hasRole(req.user.role, role)) {
      return res.status(403).json({
        error: 'Insufficient permissions',
        required: role,
        current: req.user.role
      });
    }
    next();
  };
}

/**
 * Express middleware factory — require specific action permission
 * @param {string} action - Action identifier
 * @returns {Function} Express middleware
 */
function requireAction(action) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    const requiredRole = ACTION_ROLES[action];
    if (!requiredRole) {
      // Unknown action — require admin
      if (!hasRole(req.user.role, 'admin')) {
        return res.status(403).json({ error: 'Insufficient permissions for action: ' + action });
      }
      return next();
    }
    if (!hasRole(req.user.role, requiredRole)) {
      return res.status(403).json({
        error: 'Insufficient permissions',
        action,
        required: requiredRole,
        current: req.user.role
      });
    }
    next();
  };
}

/**
 * Check if a role can perform an action (non-middleware)
 * @param {string} userRole
 * @param {string} action
 * @returns {boolean}
 */
function canPerform(userRole, action) {
  const requiredRole = ACTION_ROLES[action] || 'admin';
  return hasRole(userRole, requiredRole);
}

module.exports = {
  ROLES,
  ACTION_ROLES,
  hasRole,
  requireRole,
  requireAction,
  canPerform
};
