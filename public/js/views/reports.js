/* Vigil v1.1 — Reports View */
Views.reports = {
  init: function() {
    var el = document.getElementById('view-reports');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Reports</div>' +
        '<button class="btn btn-primary btn-sm" id="report-generate-btn">Generate Report</button>' +
      '</div>' +

      '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Generated Reports</div>' +
        '<div id="reports-list">' +
          '<div class="loading-state"><div class="spinner"></div><div>Loading reports...</div></div>' +
        '</div>' +
      '</div>';

    document.getElementById('report-generate-btn').addEventListener('click', this.showGenerateModal.bind(this));
  },

  show: function() {
    this.loadReports();
  },

  hide: function() {},

  loadReports: function() {
    var container = document.getElementById('reports-list');
    fetch('/api/reports', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var reports = data.reports || data || [];
        if (!Array.isArray(reports) || reports.length === 0) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128202;</div><div class="empty-state-title">No Reports</div><div class="empty-state-desc">Generate a report to get started</div></div>';
          return;
        }

        var html = '<table class="data-table"><thead><tr><th>Date</th><th>Type</th><th>Scope</th><th>Status</th><th>Actions</th></tr></thead><tbody>';
        reports.forEach(function(r) {
          html += '<tr>' +
            '<td>' + formatDate(r.created_at || r.date) + '</td>' +
            '<td style="color:var(--text-primary);">' + escapeHtml(r.type || r.report_type || '--') + '</td>' +
            '<td>' + escapeHtml(r.scope || '--') + '</td>' +
            '<td><span class="tag">' + escapeHtml(r.status || 'complete') + '</span></td>' +
            '<td>' +
              '<button class="btn btn-ghost btn-sm report-view-btn" data-id="' + escapeHtml(r.id || '') + '">View</button> ' +
              '<button class="btn btn-ghost btn-sm report-delete-btn" data-id="' + escapeHtml(r.id || '') + '" style="color:var(--orange);">Delete</button>' +
            '</td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;

        container.querySelectorAll('.report-view-btn').forEach(function(btn) {
          btn.addEventListener('click', function() {
            Views.reports.viewReport(btn.getAttribute('data-id'));
          });
        });

        container.querySelectorAll('.report-delete-btn').forEach(function(btn) {
          btn.addEventListener('click', function() {
            Views.reports.deleteReport(btn.getAttribute('data-id'));
          });
        });
      })
      .catch(function() {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128202;</div><div class="empty-state-title">No Reports</div></div>';
      });
  },

  showGenerateModal: function() {
    Modal.open({
      title: 'Generate Report',
      body:
        '<div class="form-group"><label class="form-label">Report Type</label><select class="form-select" id="report-type"><option value="security-assessment">Security Assessment</option><option value="vulnerability">Vulnerability Report</option><option value="compliance">Compliance Report</option><option value="pentest">Pentest Report</option><option value="executive">Executive Summary</option></select></div>' +
        '<div class="form-group"><label class="form-label">Scope</label><input type="text" class="form-input" id="report-scope" placeholder="e.g., All infrastructure, Production servers, etc."></div>',
      footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="report-gen-confirm">Generate</button>'
    });

    document.getElementById('report-gen-confirm').addEventListener('click', function() {
      var type = document.getElementById('report-type').value;
      var scope = document.getElementById('report-scope').value.trim() || 'All';

      Modal.loading('Generating report — this may take a moment...');
      fetch('/api/reports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ type: type, scope: scope })
      })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        Modal.close();
        if (data.error) {
          Toast.error(data.error);
          return;
        }
        Toast.success('Report generated');
        Views.reports.loadReports();
      })
      .catch(function() { Modal.close(); Toast.error('Report generation failed'); });
    });
  },

  viewReport: function(id) {
    Modal.loading('Loading report...');
    fetch('/api/reports/' + id, { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        Modal.close();
        var content = data.content || data.html || data.body || '';
        if (!content && data.summary) content = data.summary;
        Modal.open({
          title: data.type || 'Report',
          body: '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;">' + (content.startsWith('<') ? content : escapeHtml(content).replace(/\n/g, '<br>')) + '</div>',
          size: 'lg'
        });
      })
      .catch(function() { Modal.close(); Toast.error('Failed to load report'); });
  },

  deleteReport: function(id) {
    Modal.confirm({
      title: 'Delete Report',
      message: 'Are you sure you want to delete this report?',
      confirmText: 'Delete',
      dangerous: true
    }).then(function(confirmed) {
      if (!confirmed) return;
      fetch('/api/reports/' + id, { method: 'DELETE', credentials: 'same-origin' })
        .then(function() { Toast.success('Report deleted'); Views.reports.loadReports(); })
        .catch(function() { Toast.error('Delete failed'); });
    });
  }
};
