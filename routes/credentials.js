/**
 * Credentials Routes — AES-256-GCM encrypted credential vault
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA = path.join(__dirname, '..', 'data');
const VAULT_PATH = path.join(DATA, 'credential-vault.json');
const ALGORITHM = 'aes-256-gcm';

function escapeHtml(s) { return String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }

function readJSON(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return fallback; }
}
function writeJSON(p, data) {
  // Atomic write: temp file + rename
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + '.tmp.' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, p);
}

function getEncryptionKey() {
  // Use ENCRYPTION_KEY from env or generate a stable one from hostname + path
  const envKey = process.env.ENCRYPTION_KEY;
  if (envKey) {
    return crypto.scryptSync(envKey, 'vigil-vault', 32);
  }
  // Deterministic fallback — NOT secure for production, but functional
  const fallback = 'vigil-default-' + require('os').hostname() + '-vault-key';
  return crypto.scryptSync(fallback, 'vigil-vault', 32);
}

function encrypt(text) {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag();
  return {
    encrypted,
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
  };
}

function decrypt(data) {
  const key = getEncryptionKey();
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(data.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(data.tag, 'hex'));
  let decrypted = decipher.update(data.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

module.exports = function (app, ctx) {
  const { requireAuth, requireAdmin } = ctx;

  // GET /api/credentials — list (names + types, no values)
  app.get('/api/credentials', requireAdmin, (req, res) => {
    const vault = readJSON(VAULT_PATH, []);
    const list = vault.map(c => ({
      name: c.name,
      type: c.type,
      createdAt: c.createdAt,
      updatedAt: c.updatedAt || null,
    }));
    res.json({ credentials: list });
  });

  // POST /api/credentials — store credential
  app.post('/api/credentials', requireAdmin, (req, res) => {
    const { name, type, value } = req.body;
    if (!name || !type || !value) return res.status(400).json({ error: 'name, type, and value required' });

    const vault = readJSON(VAULT_PATH, []);

    // Check for duplicate name
    if (vault.find(c => c.name === name)) {
      return res.status(409).json({ error: 'Credential with this name already exists' });
    }

    const encryptedData = encrypt(value);
    vault.push({
      name: escapeHtml(name),
      type: escapeHtml(type),
      data: encryptedData,
      createdAt: new Date().toISOString(),
    });
    writeJSON(VAULT_PATH, vault);

    console.log(`[VAULT] Credential stored: ${name} (${type})`);
    res.json({ success: true, name });
  });

  // GET /api/credentials/:name — get decrypted value
  app.get('/api/credentials/:name', requireAdmin, (req, res) => {
    const vault = readJSON(VAULT_PATH, []);
    const cred = vault.find(c => c.name === req.params.name);
    if (!cred) return res.status(404).json({ error: 'Credential not found' });

    try {
      const value = decrypt(cred.data);
      res.json({ name: cred.name, type: cred.type, value, createdAt: cred.createdAt });
    } catch (e) {
      res.status(500).json({ error: 'Decryption failed. Encryption key may have changed.' });
    }
  });

  // DELETE /api/credentials/:name — remove
  app.delete('/api/credentials/:name', requireAdmin, (req, res) => {
    let vault = readJSON(VAULT_PATH, []);
    const before = vault.length;
    vault = vault.filter(c => c.name !== req.params.name);
    if (vault.length === before) return res.status(404).json({ error: 'Credential not found' });
    writeJSON(VAULT_PATH, vault);
    console.log(`[VAULT] Credential deleted: ${req.params.name}`);
    res.json({ success: true });
  });
};
