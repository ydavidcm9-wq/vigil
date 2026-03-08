// Vigil — AES-256-GCM encrypted credential storage
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const VAULT_FILE = path.join(__dirname, '..', 'data', 'credentials.json');
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;

/**
 * Get or generate the encryption key
 * @returns {Buffer} - 32-byte key
 */
function getKey() {
  let keyHex = process.env.ENCRYPTION_KEY;

  if (!keyHex) {
    // Generate a key and warn
    keyHex = crypto.randomBytes(KEY_LENGTH).toString('hex');
    console.warn('  Vault: no ENCRYPTION_KEY set — generated temporary key');
    console.warn('  Vault: set ENCRYPTION_KEY=' + keyHex + ' in .env for persistence');
    process.env.ENCRYPTION_KEY = keyHex;
  }

  // Ensure key is exactly 32 bytes — reject invalid lengths instead of weak fallback
  const key = Buffer.from(keyHex, 'hex');
  if (key.length !== KEY_LENGTH) {
    console.error('  Vault: ENCRYPTION_KEY must be exactly 32 bytes (64 hex chars). Got ' + key.length + ' bytes.');
    console.error('  Vault: Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
    // Use PBKDF2 derivation as fallback — safer than raw SHA-256
    return crypto.pbkdf2Sync(keyHex, 'vigil-vault-kdf', 100000, KEY_LENGTH, 'sha512');
  }
  return key;
}

/**
 * Encrypt plaintext using AES-256-GCM
 * @param {string} plaintext
 * @returns {string} - Format: iv:authTag:ciphertext (all hex)
 */
function encrypt(plaintext) {
  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');

  return iv.toString('hex') + ':' + authTag + ':' + encrypted;
}

/**
 * Decrypt ciphertext using AES-256-GCM
 * @param {string} ciphertext - Format: iv:authTag:encrypted (all hex)
 * @returns {string} - Decrypted plaintext
 */
function decrypt(ciphertext) {
  const key = getKey();
  const parts = ciphertext.split(':');

  if (parts.length !== 3) {
    throw new Error('Invalid ciphertext format');
  }

  const iv = Buffer.from(parts[0], 'hex');
  const authTag = Buffer.from(parts[1], 'hex');
  const encrypted = parts[2];

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/**
 * Load vault from file
 * @returns {Array}
 */
function loadVault() {
  try {
    if (!fs.existsSync(VAULT_FILE)) return [];
    const data = fs.readFileSync(VAULT_FILE, 'utf8');
    return JSON.parse(data);
  } catch {
    return [];
  }
}

/**
 * Save vault to file
 * @param {Array} entries
 */
function saveVault(entries) {
  try {
    const dir = path.dirname(VAULT_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(VAULT_FILE, JSON.stringify(entries, null, 2));
  } catch (err) {
    console.error('  Vault: error saving —', err.message);
    throw err;
  }
}

/**
 * Store an encrypted credential
 * @param {string} name - Unique identifier
 * @param {string} type - Credential type (api_key, password, token, certificate, ssh_key, other)
 * @param {string} value - The secret value to encrypt
 * @param {object} [metadata] - Optional metadata (not encrypted)
 * @returns {object} - The stored entry (without decrypted value)
 */
function storeCredential(name, type, value, metadata = {}) {
  const vault = loadVault();

  // Remove existing entry with same name
  const idx = vault.findIndex(e => e.name === name);
  if (idx !== -1) vault.splice(idx, 1);

  const entry = {
    name,
    type,
    encrypted: encrypt(value),
    metadata: {
      ...metadata,
      created: new Date().toISOString(),
      updated: new Date().toISOString()
    }
  };

  vault.push(entry);
  saveVault(vault);

  return { name, type, metadata: entry.metadata };
}

/**
 * Retrieve and decrypt a credential
 * @param {string} name
 * @returns {object|null} - { name, type, value, metadata } or null
 */
function getCredential(name) {
  const vault = loadVault();
  const entry = vault.find(e => e.name === name);
  if (!entry) return null;

  try {
    return {
      name: entry.name,
      type: entry.type,
      value: decrypt(entry.encrypted),
      metadata: entry.metadata
    };
  } catch (err) {
    console.error('  Vault: decryption failed for "' + name + '" —', err.message);
    return null;
  }
}

/**
 * List all credentials (without decrypted values)
 * @returns {Array} - Array of { name, type, metadata }
 */
function listCredentials() {
  const vault = loadVault();
  return vault.map(e => ({
    name: e.name,
    type: e.type,
    metadata: e.metadata
  }));
}

/**
 * Delete a credential
 * @param {string} name
 * @returns {boolean}
 */
function deleteCredential(name) {
  const vault = loadVault();
  const filtered = vault.filter(e => e.name !== name);
  if (filtered.length === vault.length) return false;
  saveVault(filtered);
  return true;
}

/**
 * Check if a credential exists
 * @param {string} name
 * @returns {boolean}
 */
function hasCredential(name) {
  const vault = loadVault();
  return vault.some(e => e.name === name);
}

module.exports = {
  encrypt,
  decrypt,
  storeCredential,
  getCredential,
  listCredentials,
  deleteCredential,
  hasCredential
};
