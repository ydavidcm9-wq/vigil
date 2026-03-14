/* Vigil v1.1 — Audit Log View */
Views['audit-log'] = {
  init: function() {
    var el = document.getElementById('view-audit-log');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Audit Log</div>' +
        '<div style="display:flex;gap:8px;">' +
          '<button class="btn btn-ghost btn-sm" id="audit-export-btn">Export</button>' +
          '<button class="btn btn-ghost btn-sm" id="audit-refresh-btn">Refresh</button>' +
        '</div>' +
      '</div>' +

      '<div class="filter-bar">' +
        '<input type="date" class="form-input" id="audit-date-start" style="width:auto;">' +
        '<span style="color:var(--text-tertiary);">to</span>' +
        '<input type="date" class="form-input" id="audit-date-end" style="width:auto;">' +
        '<input type="text" class="form-input" id="audit-search" placeholder="Search user or action..." style="max-width:200px;">' +
        '<button class="btn btn-ghost btn-sm" id="audit-filter-btn">Filter</button>' +
      '</div>' +

      '<div class="glass-card">' +
        '<div id="audit-log-table">' +
          '<div class="loading-state"><div class="spinner"></div><div>Loading audit log...</div></div>' +
        '</div>' +
      '</div>';

    var self = this;
    document.getElementById('audit-refresh-btn').addEventListener('click', function() { self.loadLog(); });
    document.getElementById('audit-filter-btn').addEventListener('click', function() { self.loadLog(); });
    document.getElementById('audit-export-btn').addEventListener('click', function() { self.exportLog(); });
  },

  show: function() {
    this.loadLog();
  },

  hide: function() {},

  loadLog: function() {
    var container = document.getElementById('audit-log-table');
    var startDate = document.getElementById('audit-date-start').value;
    var endDate = document.getElementById('audit-date-end').value;
    var search = document.getElementById('audit-search').value.trim();

    var url = '/api/audit-log?limit=100';
    if (startDate) url += '&start=' + startDate;
    if (endDate) url += '&end=' + endDate;
    if (search) url += '&search=' + encodeURIComponent(search);

    fetch(url, { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var entries = data.entries || data.log || data || [];
        if (!Array.isArray(entries) || entries.length === 0) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128220;</div><div class="empty-state-title">No Audit Entries</div><div class="empty-state-desc">No activity recorded in this period</div></div>';
          return;
        }

        var html = '<table class="data-table"><thead><tr><th>Timestamp</th><th>User</th><th>Action</th><th>Resource</th><th>Details</th></tr></thead><tbody>';
        entries.forEach(function(e) {
          html += '<tr>' +
            '<td style="white-space:nowrap;">' + formatDate(e.timestamp || e.created_at) + '</td>' +
            '<td style="color:var(--text-primary);">' + escapeHtml(e.user || e.username || '--') + '</td>' +
            '<td><span class="tag">' + escapeHtml(e.action || '--') + '</span></td>' +
            '<td>' + escapeHtml(e.resource || e.target || '--') + '</td>' +
            '<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + escapeHtml(e.details || e.message || '--') + '</td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      })
      .catch(function() {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128220;</div><div class="empty-state-title">Audit Log Unavailable</div></div>';
      });
  },

  exportLog: function() {
    fetch('/api/audit-log/export', { credentials: 'same-origin' })
      .then(function(r) { return r.blob(); })
      .then(function(blob) {
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'audit-log-' + new Date().toISOString().split('T')[0] + '.json';
        a.click();
        URL.revokeObjectURL(url);
        Toast.success('Audit log exported');
      })
      .catch(function() { Toast.error('Export failed'); });
  }
};
