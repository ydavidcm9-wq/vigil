// Vigil — User management with PBKDF2 password hashing
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const USERS_FILE = path.join(__dirname, '..', 'data', 'users.json');
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN = 64;
const PBKDF2_DIGEST = 'sha512';
const SALT_LENGTH = 32;

/**
 * Hash a password using PBKDF2
 * @param {string} password
 * @returns {string} - Format: salt:hash (both hex)
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(SALT_LENGTH).toString('hex');
  const hash = crypto.pbkdf2Sync(
    password, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST
  ).toString('hex');
  return salt + ':' + hash;
}

/**
 * Verify a password against a stored hash
 * @param {string} password - Plaintext password
 * @param {string} stored - Stored salt:hash string
 * @returns {boolean}
 */
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const verify = crypto.pbkdf2Sync(
    password, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST
  ).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(verify, 'hex'));
}

/**
 * Load all users from file. Creates default admin if file doesn't exist.
 * @returns {Array}
 */
function getUsers() {
  try {
    if (!fs.existsSync(USERS_FILE)) {
      // Create default admin user
      const defaultUsers = [{
        username: 'admin',
        password: hashPassword('admin'),
        role: 'admin',
        created: new Date().toISOString(),
        twoFactor: null
      }];
      const dir = path.dirname(USERS_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
      console.log('  Users: created default admin (admin/admin)');
      return defaultUsers;
    }
    const data = fs.readFileSync(USERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error('  Users: error loading —', err.message);
    return [];
  }
}

/**
 * Find a user by username
 * @param {string} username
 * @returns {object|null}
 */
function getUser(username) {
  const users = getUsers();
  return users.find(u => u.username === username) || null;
}

/**
 * Create a new user
 * @param {string} username
 * @param {string} password
 * @param {string} role - admin, analyst, or viewer
 * @returns {object} - The created user (without password)
 */
function createUser(username, password, role = 'viewer') {
  const users = getUsers();
  if (users.find(u => u.username === username)) {
    throw new Error('Username already exists');
  }

  const validRoles = ['admin', 'analyst', 'viewer'];
  if (!validRoles.includes(role)) {
    throw new Error('Invalid role: ' + role);
  }

  const user = {
    username,
    password: hashPassword(password),
    role,
    created: new Date().toISOString(),
    twoFactor: null
  };

  users.push(user);
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

  // Return without password
  const { password: _, ...safe } = user;
  return safe;
}

/**
 * Update a user's fields
 * @param {string} username
 * @param {object} updates - Fields to update
 * @returns {object|null} - Updated user (without password) or null
 */
function updateUser(username, updates) {
  const users = getUsers();
  const idx = users.findIndex(u => u.username === username);
  if (idx === -1) return null;

  // Hash password if being updated
  if (updates.password) {
    updates.password = hashPassword(updates.password);
  }

  // Merge updates
  users[idx] = { ...users[idx], ...updates, username }; // prevent username change
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

  const { password: _, ...safe } = users[idx];
  return safe;
}

/**
 * Delete a user
 * @param {string} username
 * @returns {boolean}
 */
function deleteUser(username) {
  const users = getUsers();
  const filtered = users.filter(u => u.username !== username);
  if (filtered.length === users.length) return false;
  fs.writeFileSync(USERS_FILE, JSON.stringify(filtered, null, 2));
  return true;
}

module.exports = {
  hashPassword,
  verifyPassword,
  getUsers,
  getUser,
  createUser,
  updateUser,
  deleteUser
};
