/* Vigil v1.1 — Alert Triage View */
Views.triage = {
  init: function() {
    var el = document.getElementById('view-triage');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">AI Alert Triage</div>' +
        '<button class="btn btn-ghost btn-sm" id="triage-refresh">Refresh</button>' +
      '</div>' +

      '<div class="grid-2">' +
        '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Pending Alerts</div>' +
          '<div id="triage-pending-list">' +
            '<div class="loading-state"><div class="spinner"></div><div>Loading alerts...</div></div>' +
          '</div>' +
        '</div>' +

        '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Triage Result</div>' +
          '<div id="triage-result">' +
            '<div class="empty-state"><div class="empty-state-icon">&#9783;</div><div class="empty-state-title">Select an Alert</div><div class="empty-state-desc">Choose an alert from the left to run AI triage</div></div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card" style="margin-top:20px;">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Triage History</div>' +
        '<div id="triage-history">' +
          '<div class="empty-state"><div class="empty-state-icon">&#128220;</div><div class="empty-state-title">No History</div><div class="empty-state-desc">Triaged alerts will appear here</div></div>' +
        '</div>' +
      '</div>';

    document.getElementById('triage-refresh').addEventListener('click', this.show.bind(this));
  },

  show: function() {
    this.loadPending();
    this.loadHistory();
  },

  hide: function() {},

  loadPending: function() {
    var container = document.getElementById('triage-pending-list');
    fetch('/api/alerts?status=pending', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var alerts = data.alerts || data || [];
        if (!Array.isArray(alerts)) alerts = [];

        if (alerts.length === 0) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10003;</div><div class="empty-state-title">All Clear</div><div class="empty-state-desc">No pending alerts to triage</div></div>';
          return;
        }

        var html = '';
        alerts.forEach(function(a) {
          html += '<div class="kanban-card triage-alert-card" data-id="' + escapeHtml(a.id || '') + '">' +
            '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">' +
              '<span class="badge ' + severityBadge(a.severity) + '">' + escapeHtml(a.severity || 'info') + '</span>' +
              '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + timeAgo(a.timestamp || a.created_at) + '</span>' +
            '</div>' +
            '<div class="kanban-card-title">' + escapeHtml(a.title || a.description || 'Unnamed Alert') + '</div>' +
            '<div class="kanban-card-meta">' + escapeHtml(a.source || '--') + '</div>' +
          '</div>';
        });
        container.innerHTML = html;

        container.querySelectorAll('.triage-alert-card').forEach(function(card) {
          card.addEventListener('click', function() {
            var id = card.getAttribute('data-id');
            Views.triage.runTriage(id);
          });
        });
      })
      .catch(function() {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10003;</div><div class="empty-state-title">All Clear</div><div class="empty-state-desc">No pending alerts</div></div>';
      });
  },

  runTriage: function(id) {
    var result = document.getElementById('triage-result');
    result.innerHTML = '<div class="loading-state"><div class="spinner"></div><div>AI analyzing alert...</div></div>';

    fetch('/api/alerts/' + id + '/triage', {
      method: 'POST',
      credentials: 'same-origin'
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.error) {
        result.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Triage Error</div><div class="empty-state-desc">' + escapeHtml(data.error) + '</div></div>';
        Toast.error(data.error);
        return;
      }

      var verdict = data.verdict || 'needs_investigation';
      var confidence = data.confidence || 0;
      var reasoning = data.reasoning || 'No analysis available.';
      var techniques = data.mitre_techniques || [];
      var action = data.recommended_action || '';

      var verdictColor = verdict === 'true_positive' ? 'var(--orange)' :
                        verdict === 'false_positive' ? 'var(--cyan)' : 'var(--text-secondary)';
      var verdictLabel = verdict.replace(/_/g, ' ').toUpperCase();

      var html =
        '<div style="text-align:center;margin-bottom:20px;">' +
          '<div style="font-size:var(--font-size-2xl);font-weight:700;color:' + verdictColor + ';">' + escapeHtml(verdictLabel) + '</div>' +
          '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);margin-top:4px;">Confidence: ' + confidence + '%</div>' +
          '<div class="progress-bar" style="max-width:200px;margin:8px auto 0;">' +
            '<div class="progress-bar-fill" style="width:' + confidence + '%;"></div>' +
          '</div>' +
        '</div>' +
        '<div style="margin-bottom:16px;">' +
          '<div class="form-label">Analysis</div>' +
          '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;">' + escapeHtml(reasoning) + '</div>' +
        '</div>';

      if (action) {
        html += '<div style="margin-bottom:16px;">' +
          '<div class="form-label">Recommended Action</div>' +
          '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);">' + escapeHtml(action) + '</div>' +
          '</div>';
      }

      if (techniques.length > 0) {
        html += '<div>' +
          '<div class="form-label">MITRE ATT&CK Techniques</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
        techniques.forEach(function(t) {
          html += '<span class="tag tag-purple">' + escapeHtml(t) + '</span>';
        });
        html += '</div></div>';
      }

      result.innerHTML = html;
      Toast.success('Triage complete');
      Views.triage.loadHistory();
      Views.triage.loadPending();
    })
    .catch(function() {
      result.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Triage Failed</div><div class="empty-state-desc">Could not reach server. Check your connection.</div></div>';
      Toast.error('AI triage failed');
    });
  },

  loadHistory: function() {
    var container = document.getElementById('triage-history');
    fetch('/api/alerts/triage-history', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var history = data.history || data || [];
        if (!Array.isArray(history) || history.length === 0) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128220;</div><div class="empty-state-title">No History</div><div class="empty-state-desc">Triaged alerts will appear here</div></div>';
          return;
        }

        var html = '<table class="data-table"><thead><tr><th>Alert</th><th>Verdict</th><th>Confidence</th><th>Time</th></tr></thead><tbody>';
        history.slice(0, 20).forEach(function(h) {
          var verdictColor = h.verdict === 'true_positive' ? 'var(--orange)' :
                            h.verdict === 'false_positive' ? 'var(--cyan)' : 'var(--purple)';
          html += '<tr>' +
            '<td style="color:var(--text-primary);">' + escapeHtml(h.alert_title || h.title || '--') + '</td>' +
            '<td><span style="color:' + verdictColor + ';font-weight:600;text-transform:uppercase;font-size:var(--font-size-xs);">' + escapeHtml((h.verdict || '').replace(/_/g, ' ')) + '</span></td>' +
            '<td>' + (h.confidence || 0) + '%</td>' +
            '<td>' + timeAgo(h.triaged_at || h.created_at) + '</td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      })
      .catch(function() {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128220;</div><div class="empty-state-title">No History</div></div>';
      });
  }
};
