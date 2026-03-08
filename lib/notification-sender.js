// Vigil — Notification system
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const NOTIF_FILE = path.join(__dirname, '..', 'data', 'notifications.json');
const MAX_NOTIFICATIONS = 500;

/**
 * Load notifications from file
 * @returns {Array}
 */
function loadNotifications() {
  try {
    if (!fs.existsSync(NOTIF_FILE)) return [];
    const data = fs.readFileSync(NOTIF_FILE, 'utf8');
    return JSON.parse(data);
  } catch {
    return [];
  }
}

/**
 * Save notifications to file
 * @param {Array} notifications
 */
function saveNotifications(notifications) {
  try {
    const dir = path.dirname(NOTIF_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(NOTIF_FILE, JSON.stringify(notifications, null, 2));
  } catch (err) {
    console.error('  Notifications: error saving —', err.message);
  }
}

/**
 * Create and store a notification
 * @param {string} type - Notification type (threat, scan, system, auth, posture, intel)
 * @param {string} title - Short title
 * @param {string} message - Detailed message
 * @param {string} [severity] - info, warning, critical (default: info)
 * @returns {object} - The created notification
 */
function send(type, title, message, severity = 'info') {
  const notifications = loadNotifications();

  const notification = {
    id: crypto.randomBytes(8).toString('hex'),
    type,
    title,
    message,
    severity,
    read: false,
    dismissed: false,
    created: new Date().toISOString()
  };

  notifications.push(notification);

  // Trim old notifications
  if (notifications.length > MAX_NOTIFICATIONS) {
    notifications.splice(0, notifications.length - MAX_NOTIFICATIONS);
  }

  saveNotifications(notifications);
  return notification;
}

/**
 * Get unread notifications
 * @param {number} [limit] - Max notifications to return (default: 50)
 * @returns {Array}
 */
function getUnread(limit = 50) {
  const notifications = loadNotifications();
  return notifications
    .filter(n => !n.read && !n.dismissed)
    .sort((a, b) => new Date(b.created) - new Date(a.created))
    .slice(0, limit);
}

/**
 * Get all notifications with optional filters
 * @param {object} [filters]
 * @param {string} [filters.type] - Filter by type
 * @param {string} [filters.severity] - Filter by severity
 * @param {boolean} [filters.unreadOnly] - Only unread
 * @param {number} [filters.limit] - Max results
 * @returns {Array}
 */
function getAll(filters = {}) {
  let notifications = loadNotifications();

  if (filters.type) {
    notifications = notifications.filter(n => n.type === filters.type);
  }
  if (filters.severity) {
    notifications = notifications.filter(n => n.severity === filters.severity);
  }
  if (filters.unreadOnly) {
    notifications = notifications.filter(n => !n.read && !n.dismissed);
  }

  notifications.sort((a, b) => new Date(b.created) - new Date(a.created));

  if (filters.limit) {
    notifications = notifications.slice(0, filters.limit);
  }

  return notifications;
}

/**
 * Mark a notification as read
 * @param {string} id
 * @returns {boolean}
 */
function markRead(id) {
  const notifications = loadNotifications();
  const notif = notifications.find(n => n.id === id);
  if (!notif) return false;
  notif.read = true;
  notif.readAt = new Date().toISOString();
  saveNotifications(notifications);
  return true;
}

/**
 * Mark all notifications as read
 * @returns {number} - Count marked
 */
function markAllRead() {
  const notifications = loadNotifications();
  let count = 0;
  const now = new Date().toISOString();
  notifications.forEach(n => {
    if (!n.read) {
      n.read = true;
      n.readAt = now;
      count++;
    }
  });
  if (count > 0) saveNotifications(notifications);
  return count;
}

/**
 * Dismiss a notification
 * @param {string} id
 * @returns {boolean}
 */
function dismiss(id) {
  const notifications = loadNotifications();
  const notif = notifications.find(n => n.id === id);
  if (!notif) return false;
  notif.dismissed = true;
  notif.dismissedAt = new Date().toISOString();
  saveNotifications(notifications);
  return true;
}

/**
 * Get count of unread notifications
 * @returns {number}
 */
function getUnreadCount() {
  const notifications = loadNotifications();
  return notifications.filter(n => !n.read && !n.dismissed).length;
}

/**
 * Clear all notifications
 * @returns {boolean}
 */
function clearAll() {
  saveNotifications([]);
  return true;
}

module.exports = {
  send,
  getUnread,
  getAll,
  markRead,
  markAllRead,
  dismiss,
  getUnreadCount,
  clearAll
};
