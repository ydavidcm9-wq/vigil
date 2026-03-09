/**
 * Git Projects Routes — Dynamic repo management (add/edit/remove/switch)
 * Stores repo configs in data/git-projects.json
 * Supports private repos via credential vault (SSH key or HTTPS token)
 */
const fs = require('fs');
const path = require('path');
const vault = require('../lib/credential-vault');

const PROJECTS_FILE = path.join(__dirname, '..', 'data', 'git-projects.json');

function loadProjects() {
  try {
    if (fs.existsSync(PROJECTS_FILE)) return JSON.parse(fs.readFileSync(PROJECTS_FILE, 'utf8'));
  } catch {}
  return { projects: [], activeId: null };
}

function saveProjects(data) {
  const dir = path.dirname(PROJECTS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(PROJECTS_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function getActiveProject() {
  const data = loadProjects();
  if (!data.activeId && data.projects.length) data.activeId = data.projects[0].id;
  return data.projects.find(p => p.id === data.activeId) || null;
}

function getRepoCwd(project) {
  if (!project) return null;
  return project.localPath || null;
}

function isValidRemoteUrl(remoteUrl) {
  if (!remoteUrl || typeof remoteUrl !== 'string' || remoteUrl.length > 2048) return false;
  return /^(https:\/\/|git@)[a-zA-Z0-9._:@/-]+(\.git)?$/.test(remoteUrl.trim());
}

/** Build git env with auth for private repos */
function getGitEnv(project) {
  const env = { ...process.env };
  if (!project || !project.credentialId) return env;
  try {
    const cred = vault.getCredential(project.credentialId);
    if (!cred) return env;
    if (cred.type === 'ssh_key' && cred.value) {
      const tmpKey = path.join(__dirname, '..', 'data', '.git-ssh-key-' + project.id);
      fs.writeFileSync(tmpKey, cred.value, { mode: 0o600 });
      env.GIT_SSH_COMMAND = `ssh -i "${tmpKey}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null`;
    } else if (cred.type === 'api_token' && cred.value) {
      env.GIT_ASKPASS = 'echo';
      env.GIT_TOKEN = cred.value;
    }
  } catch {}
  return env;
}

/** Get authenticated remote URL for HTTPS token repos */
function getAuthRemoteUrl(project) {
  if (!project || !project.credentialId || !project.remoteUrl) return null;
  try {
    const cred = vault.getCredential(project.credentialId);
    if (cred && cred.type === 'api_token' && cred.value) {
      return project.remoteUrl.replace(/^https:\/\//, 'https://' + cred.value + '@');
    }
  } catch {}
  return null;
}

module.exports = function (app, ctx) {
  const { requireAdmin, requireRole, execCommand, execFileSafe } = ctx;

  // Expose getActiveProject and getRepoCwd on ctx for git-enhanced.js
  ctx.getActiveGitProject = getActiveProject;
  ctx.getGitCwd = function () {
    const proj = getActiveProject();
    return getRepoCwd(proj) || ctx.REPO_DIR;
  };
  ctx.getGitEnv = function () {
    const proj = getActiveProject();
    return getGitEnv(proj);
  };

  // ── List projects ──
  app.get('/api/git/projects', requireAdmin, (req, res) => {
    const data = loadProjects();
    const enriched = data.projects.map(p => {
      const cwd = getRepoCwd(p);
      return { ...p, hasLocalPath: !!cwd && fs.existsSync(cwd), active: p.id === data.activeId };
    });
    res.json({ projects: enriched, activeId: data.activeId });
  });

  // ── Add project ──
  app.post('/api/git/projects', requireRole('analyst'), async (req, res) => {
    const { name, localPath, remoteUrl, credentialId, description } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    if (!localPath && !remoteUrl) return res.status(400).json({ error: 'Local path or remote URL required' });
    if (remoteUrl && !isValidRemoteUrl(remoteUrl)) {
      return res.status(400).json({ error: 'Remote URL must be an HTTPS or SSH git URL' });
    }

    const id = require('crypto').randomUUID();
    const project = {
      id,
      name,
      localPath: localPath || '',
      remoteUrl: remoteUrl || '',
      credentialId: credentialId || null,
      description: description || '',
      createdAt: new Date().toISOString(),
    };

    if (remoteUrl && !localPath) {
      const cloneDir = path.join(__dirname, '..', 'data', 'repos', id);
      if (!fs.existsSync(path.dirname(cloneDir))) fs.mkdirSync(path.dirname(cloneDir), { recursive: true });
      try {
        const env = getGitEnv(project);
        const authUrl = getAuthRemoteUrl(project) || remoteUrl;
        const result = await execFileSafe('git', ['clone', authUrl, cloneDir], { cwd: __dirname, timeout: 120000, env });
        if (result.code !== 0) {
          return res.status(500).json({ error: 'Clone failed: ' + (result.stderr || result.stdout || 'Unknown error') });
        }
        project.localPath = cloneDir;
      } catch (e) {
        return res.status(500).json({ error: 'Clone failed: ' + (e.message || e.stderr || 'Unknown error') });
      }
    }

    const data = loadProjects();
    data.projects.push(project);
    if (!data.activeId) data.activeId = id;
    saveProjects(data);
    res.json({ success: true, project });
  });

  // ── Update project ──
  app.put('/api/git/projects/:id', requireRole('analyst'), (req, res) => {
    const data = loadProjects();
    const idx = data.projects.findIndex(p => p.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Project not found' });
    const { name, localPath, remoteUrl, credentialId, description } = req.body;
    if (name !== undefined) data.projects[idx].name = name;
    if (localPath !== undefined) data.projects[idx].localPath = localPath;
    if (remoteUrl !== undefined) data.projects[idx].remoteUrl = remoteUrl;
    if (credentialId !== undefined) data.projects[idx].credentialId = credentialId;
    if (description !== undefined) data.projects[idx].description = description;
    saveProjects(data);
    res.json({ success: true, project: data.projects[idx] });
  });

  // ── Delete project ──
  app.delete('/api/git/projects/:id', requireAdmin, (req, res) => {
    const data = loadProjects();
    const idx = data.projects.findIndex(p => p.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Project not found' });
    const removed = data.projects.splice(idx, 1)[0];
    if (data.activeId === req.params.id) data.activeId = data.projects.length ? data.projects[0].id : null;
    saveProjects(data);
    res.json({ success: true, removed: removed.name });
  });

  // ── Activate project ──
  app.post('/api/git/projects/:id/activate', requireRole('analyst'), (req, res) => {
    const data = loadProjects();
    const project = data.projects.find(p => p.id === req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    data.activeId = req.params.id;
    saveProjects(data);
    res.json({ success: true, activeId: data.activeId, name: project.name });
  });

  // ── Test connection ──
  app.post('/api/git/projects/test', requireRole('analyst'), async (req, res) => {
    const { localPath, remoteUrl, credentialId } = req.body;
    try {
      if (localPath) {
        if (!fs.existsSync(localPath)) return res.json({ success: false, error: 'Path does not exist' });
        const r = await execFileSafe('git', ['rev-parse', '--is-inside-work-tree'], { cwd: localPath, timeout: 5000 });
        if (r.code === 0 && r.stdout.trim() === 'true') {
          const branch = await execFileSafe('git', ['branch', '--show-current'], { cwd: localPath, timeout: 5000 });
          return res.json({ success: true, message: 'Git repo found', branch: branch.stdout.trim() });
        }
        return res.json({ success: false, error: 'Not a git repository' });
      }
      if (remoteUrl) {
        if (!isValidRemoteUrl(remoteUrl)) {
          return res.json({ success: false, error: 'Invalid remote URL' });
        }
        const tmpProject = { credentialId, remoteUrl };
        const env = getGitEnv(tmpProject);
        const authUrl = getAuthRemoteUrl(tmpProject) || remoteUrl;
        const r = await execFileSafe('git', ['ls-remote', '--heads', authUrl], { cwd: __dirname, timeout: 30000, env });
        const refs = r.stdout.trim().split('\n').filter(Boolean);
        if (r.code === 0 && refs.length > 0) {
          return res.json({ success: true, message: 'Remote accessible', refs: refs.length + ' refs' });
        }
        return res.json({ success: false, error: r.stderr || r.stdout || 'Could not access remote' });
      }
      res.json({ success: false, error: 'Provide localPath or remoteUrl' });
    } catch (e) { res.json({ success: false, error: e.message }); }
  });
};
