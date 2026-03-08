/* Vigil v1.0 — Notification Center View */
Views.notifications = {
  init: function() {
    var el = document.getElementById('view-notifications');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Notifications</div>' +
        '<div style="display:flex;gap:8px;">' +
          '<button class="btn btn-ghost btn-sm" id="notif-mark-all-read">Mark All Read</button>' +
          '<button class="btn btn-ghost btn-sm" id="notif-refresh">Refresh</button>' +
        '</div>' +
      '</div>' +

      '<div class="filter-bar">' +
        '<select class="form-select" id="notif-filter" style="width:auto;">' +
          '<option value="all">All</option>' +
          '<option value="unread">Unread</option>' +
          '<option value="critical">Critical</option>' +
          '<option value="warning">Warnings</option>' +
          '<option value="info">Info</option>' +
        '</select>' +
      '</div>' +

      '<div id="notif-list">' +
        '<div class="loading-state"><div class="spinner"></div><div>Loading notifications...</div></div>' +
      '</div>' +

      '<div class="glass-card" style="margin-top:20px;">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Notification Preferences</div>' +
        '<div id="notif-prefs">' +
          '<div class="checklist-item"><div class="checklist-check checked" onclick="this.classList.toggle(\'checked\');this.textContent=this.classList.contains(\'checked\')?\'\\u2713\':\'\';">&#10003;</div><div class="checklist-text">Critical findings</div></div>' +
          '<div class="checklist-item"><div class="checklist-check checked" onclick="this.classList.toggle(\'checked\');this.textContent=this.classList.contains(\'checked\')?\'\\u2713\':\'\';">&#10003;</div><div class="checklist-text">Scan completions</div></div>' +
          '<div class="checklist-item"><div class="checklist-check checked" onclick="this.classList.toggle(\'checked\');this.textContent=this.classList.contains(\'checked\')?\'\\u2713\':\'\';">&#10003;</div><div class="checklist-text">SSL certificate expiry warnings</div></div>' +
          '<div class="checklist-item"><div class="checklist-check" onclick="this.classList.toggle(\'checked\');this.textContent=this.classList.contains(\'checked\')?\'\\u2713\':\'\';">&#10003;</div><div class="checklist-text">Daily security digest</div></div>' +
          '<div class="checklist-item"><div class="checklist-check" onclick="this.classList.toggle(\'checked\');this.textContent=this.classList.contains(\'checked\')?\'\\u2713\':\'\';">&#10003;</div><div class="checklist-text">Agent run completions</div></div>' +
        '</div>' +
      '</div>';

    var self = this;
    document.getElementById('notif-refresh').addEventListener('click', function() { self.loadNotifications(); });
    document.getElementById('notif-mark-all-read').addEventListener('click', function() { self.markAllRead(); });
    document.getElementById('notif-filter').addEventListener('change', function() { self.loadNotifications(); });
  },

  show: function() {
    this.loadNotifications();
  },

  hide: function() {},

  loadNotifications: function() {
    var container = document.getElementById('notif-list');
    var filter = document.getElementById('notif-filter').value;
    var url = '/api/notifications';
    if (filter !== 'all') url += '?filter=' + filter;

    fetch(url, { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var notifications = data.notifications || data || [];
        if (!Array.isArray(notifications) || notifications.length === 0) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128276;</div><div class="empty-state-title">No Notifications</div><div class="empty-state-desc">You\'re all caught up</div></div>';
          return;
        }

        var html = '';
        notifications.forEach(function(n) {
          var sevBadge = n.severity === 'critical' ? 'badge-critical' :
                        n.severity === 'warning' || n.severity === 'high' ? 'badge-high' :
                        n.severity === 'info' ? 'badge-info' : 'badge-medium';
          var unreadClass = n.read ? '' : ' style="border-left:3px solid var(--cyan);"';

          html += '<div class="glass-card" style="margin-bottom:8px;padding:12px;' + (n.read ? '' : 'border-left:3px solid var(--cyan);') + '">' +
            '<div style="display:flex;align-items:center;gap:10px;margin-bottom:4px;">' +
              '<span class="badge ' + sevBadge + '">' + escapeHtml(n.severity || 'info') + '</span>' +
              '<span style="color:var(--text-primary);font-weight:500;flex:1;">' + escapeHtml(n.title || n.message || 'Notification') + '</span>' +
              '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + timeAgo(n.created_at || n.timestamp) + '</span>' +
            '</div>' +
            '<div style="color:var(--text-secondary);font-size:var(--font-size-xs);margin-bottom:6px;">' + escapeHtml(n.body || n.details || '') + '</div>' +
            '<div style="display:flex;gap:6px;">' +
              (!n.read ? '<button class="btn btn-ghost btn-sm notif-read-btn" data-id="' + escapeHtml(n.id || '') + '">Mark Read</button>' : '') +
              '<button class="btn btn-ghost btn-sm notif-dismiss-btn" data-id="' + escapeHtml(n.id || '') + '">Dismiss</button>' +
            '</div>' +
          '</div>';
        });
        container.innerHTML = html;

        container.querySelectorAll('.notif-read-btn').forEach(function(btn) {
          btn.addEventListener('click', function() {
            var id = btn.getAttribute('data-id');
            fetch('/api/notifications/' + id + '/read', { method: 'POST', credentials: 'same-origin' })
              .then(function() { Views.notifications.loadNotifications(); })
              .catch(function() {});
          });
        });

        container.querySelectorAll('.notif-dismiss-btn').forEach(function(btn) {
          btn.addEventListener('click', function() {
            var id = btn.getAttribute('data-id');
            fetch('/api/notifications/' + id, { method: 'DELETE', credentials: 'same-origin' })
              .then(function() { Views.notifications.loadNotifications(); })
              .catch(function() {});
          });
        });
      })
      .catch(function() {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128276;</div><div class="empty-state-title">Notifications Unavailable</div></div>';
      });
  },

  markAllRead: function() {
    fetch('/api/notifications/read-all', { method: 'POST', credentials: 'same-origin' })
      .then(function() { Toast.success('All notifications marked as read'); Views.notifications.loadNotifications(); })
      .catch(function() { Toast.error('Failed to mark notifications'); });
  }
};
