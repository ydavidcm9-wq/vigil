// Vigil — User management with PBKDF2 password hashing
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { writeJSONAtomic } = require('./exec');

const USERS_FILE = path.join(__dirname, '..', 'data', 'users.json');
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN = 64;
const PBKDF2_DIGEST = 'sha512';
const SALT_LENGTH = 32;

function saveUsers(users) {
  writeJSONAtomic(USERS_FILE, users);
}

function buildBootstrapUsers() {
  const username = (process.env.VIGIL_USER || 'admin').trim() || 'admin';
  let password = process.env.VIGIL_PASS;
  let generated = false;

  if (!password) {
    password = crypto.randomBytes(18).toString('base64url');
    generated = true;
  }

  const users = [{
    username,
    password: hashPassword(password),
    role: 'admin',
    created: new Date().toISOString(),
    twoFactor: null,
    pendingTwoFactor: null
  }];

  if (generated) {
    console.log(`  Users: created bootstrap admin (${username}) with generated password`);
    console.log(`  Users: initial password for "${username}" => ${password}`);
  } else {
    console.log(`  Users: created bootstrap admin (${username}) from VIGIL_USER/VIGIL_PASS`);
  }

  return users;
}

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
  if (!salt || !hash) return false;
  const verify = crypto.pbkdf2Sync(
    password, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST
  ).toString('hex');
  const expected = Buffer.from(hash, 'hex');
  const actual = Buffer.from(verify, 'hex');
  if (expected.length === 0 || expected.length !== actual.length) return false;
  return crypto.timingSafeEqual(expected, actual);
}

/**
 * Load all users from file. Creates default admin if file doesn't exist.
 * @returns {Array}
 */
function getUsers() {
  try {
    if (!fs.existsSync(USERS_FILE)) {
      const defaultUsers = buildBootstrapUsers();
      saveUsers(defaultUsers);
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
    twoFactor: null,
    pendingTwoFactor: null
  };

  users.push(user);
  saveUsers(users);

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
  saveUsers(users);

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
  saveUsers(filtered);
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
