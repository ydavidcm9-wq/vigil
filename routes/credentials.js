/**
 * Credentials Routes — AES-256-GCM encrypted credential vault
 */
const fs = require('fs');
const path = require('path');
const vault = require('../lib/credential-vault');

const SSH_KEY_DIR = path.join(__dirname, '..', 'data', 'ssh-keys');

function escapeHtml(s) { return String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }

function formatCredential(entry) {
  const metadata = entry.metadata || {};
  return {
    id: entry.id,
    name: entry.name,
    type: entry.type,
    host: metadata.host || null,
    port: metadata.port || null,
    username: metadata.username || null,
    tags: Array.isArray(metadata.tags) ? metadata.tags : [],
    created_at: metadata.created || null,
    updated_at: metadata.updated || null,
    createdAt: metadata.created || null,
    updatedAt: metadata.updated || null
  };
}

function buildConnectCommand(entry) {
  const metadata = entry.metadata || {};
  const host = String(metadata.host || '').trim();
  const port = Number.isFinite(Number(metadata.port)) ? Number(metadata.port) : 22;
  const username = String(metadata.username || '').trim();

  if (!host) {
    throw new Error('Credential is missing metadata.host for terminal injection');
  }

  const target = username ? `${username}@${host}` : host;

  if (entry.type === 'ssh_key') {
    fs.mkdirSync(SSH_KEY_DIR, { recursive: true });
    const fileName = (entry.id || entry.name).replace(/[^a-zA-Z0-9_-]/g, '');
    const keyPath = path.join(SSH_KEY_DIR, `${fileName}.key`);
    fs.writeFileSync(keyPath, entry.value, { encoding: 'utf8', mode: 0o600 });
    return `ssh -i "${keyPath}" -p ${port} ${target}`;
  }

  if (entry.type === 'password') {
    return `ssh -p ${port} ${target}`;
  }

  throw new Error(`Credential type "${entry.type}" cannot be injected into the terminal`);
}

module.exports = function (app, ctx) {
  const { requireAdmin } = ctx;

  // GET /api/credentials — list (metadata only, no decrypted values)
  app.get('/api/credentials', requireAdmin, (req, res) => {
    const credentials = vault.listCredentials().map(formatCredential);
    res.json({ credentials });
  });

  // POST /api/credentials — store credential
  app.post('/api/credentials', requireAdmin, (req, res) => {
    try {
      const { name, type, value, secret, host, port, username, tags } = req.body || {};
      const resolvedValue = value || secret;
      if (!name || !type || !resolvedValue) {
        return res.status(400).json({ error: 'name, type, and value required' });
      }

      if (vault.hasCredential(name)) {
        return res.status(409).json({ error: 'Credential with this name already exists' });
      }

      const saved = vault.storeCredential(String(name).trim(), String(type).trim(), String(resolvedValue), {
        host: host ? String(host).trim() : null,
        port: port ? Number(port) : null,
        username: username ? String(username).trim() : null,
        tags: Array.isArray(tags)
          ? tags.map(tag => String(tag).trim()).filter(Boolean)
          : String(tags || '').split(',').map(tag => tag.trim()).filter(Boolean)
      });

      console.log(`[VAULT] Credential stored: ${saved.name} (${saved.type})`);
      res.json({ success: true, credential: formatCredential(saved), id: saved.id, name: saved.name });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/credentials/:identifier — get decrypted value by id or name
  app.get('/api/credentials/:identifier', requireAdmin, (req, res) => {
    const cred = vault.getCredential(req.params.identifier);
    if (!cred) return res.status(404).json({ error: 'Credential not found' });

    res.json({
      ...formatCredential(cred),
      value: cred.value,
      secret: cred.value
    });
  });

  // POST /api/credentials/:identifier/inject — build terminal command for SSH connection
  app.post('/api/credentials/:identifier/inject', requireAdmin, (req, res) => {
    try {
      const cred = vault.getCredential(req.params.identifier);
      if (!cred) return res.status(404).json({ error: 'Credential not found' });

      const command = buildConnectCommand(cred);
      res.json({
        success: true,
        id: cred.id,
        name: cred.name,
        command
      });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  // DELETE /api/credentials/:identifier — remove by id or name
  app.delete('/api/credentials/:identifier', requireAdmin, (req, res) => {
    const cred = vault.getCredential(req.params.identifier);
    if (!cred) return res.status(404).json({ error: 'Credential not found' });
    if (!vault.deleteCredential(req.params.identifier)) {
      return res.status(404).json({ error: 'Credential not found' });
    }
    console.log(`[VAULT] Credential deleted: ${cred.name}`);
    res.json({ success: true });
  });
};
