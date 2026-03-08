/**
 * Notifications Routes — Notification center
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA = path.join(__dirname, '..', 'data');
const NOTIFS_PATH = path.join(DATA, 'notifications.json');

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

module.exports = function (app, ctx) {
  const { requireAuth } = ctx;

  // Expose sendNotification for other routes
  ctx.sendNotification = function (category, message, type, severity) {
    const notifs = readJSON(NOTIFS_PATH, []);
    const notif = {
      id: crypto.randomUUID(),
      category: category || 'system',
      message: message || '',
      type: type || 'info',
      severity: severity || 'info',
      read: false,
      dismissed: false,
      createdAt: new Date().toISOString(),
    };
    notifs.push(notif);
    if (notifs.length > 500) notifs.splice(0, notifs.length - 500);
    writeJSON(NOTIFS_PATH, notifs);

    // Emit via socket
    if (ctx.io) ctx.io.emit('notification', notif);
    return notif;
  };

  // GET /api/notifications
  app.get('/api/notifications', requireAuth, (req, res) => {
    const notifs = readJSON(NOTIFS_PATH, []);
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const filtered = notifs.filter(n => !n.dismissed).slice(-limit).reverse();
    res.json({ notifications: filtered, total: filtered.length });
  });

  // GET /api/notifications/unread
  app.get('/api/notifications/unread', requireAuth, (req, res) => {
    const notifs = readJSON(NOTIFS_PATH, []);
    const unread = notifs.filter(n => !n.read && !n.dismissed);
    res.json({ count: unread.length });
  });

  // POST /api/notifications/:id/read
  app.post('/api/notifications/:id/read', requireAuth, (req, res) => {
    const notifs = readJSON(NOTIFS_PATH, []);
    const notif = notifs.find(n => n.id === req.params.id);
    if (!notif) return res.status(404).json({ error: 'Notification not found' });
    notif.read = true;
    notif.readAt = new Date().toISOString();
    writeJSON(NOTIFS_PATH, notifs);
    res.json({ success: true });
  });

  // POST /api/notifications/:id/dismiss
  app.post('/api/notifications/:id/dismiss', requireAuth, (req, res) => {
    const notifs = readJSON(NOTIFS_PATH, []);
    const notif = notifs.find(n => n.id === req.params.id);
    if (!notif) return res.status(404).json({ error: 'Notification not found' });
    notif.dismissed = true;
    notif.dismissedAt = new Date().toISOString();
    writeJSON(NOTIFS_PATH, notifs);
    res.json({ success: true });
  });

  // POST /api/notifications/read-all
  app.post('/api/notifications/read-all', requireAuth, (req, res) => {
    const notifs = readJSON(NOTIFS_PATH, []);
    const now = new Date().toISOString();
    for (const n of notifs) {
      if (!n.read) {
        n.read = true;
        n.readAt = now;
      }
    }
    writeJSON(NOTIFS_PATH, notifs);
    res.json({ success: true, count: notifs.length });
  });
};
