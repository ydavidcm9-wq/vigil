/* Vigil v1.0 — Threat Feed View */
Views.threats = {
  _refreshTimer: null,

  init: function() {
    var el = document.getElementById('view-threats');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Threat Feed</div>' +
        '<button class="btn btn-ghost btn-sm" id="threats-refresh">Refresh</button>' +
      '</div>' +

      '<div class="glass-card" style="margin-bottom:20px;display:flex;align-items:center;gap:20px;">' +
        '<div>' +
          '<div style="font-size:var(--font-size-xs);color:var(--text-tertiary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;">Current Threat Level</div>' +
          '<div id="threats-level-badge" style="font-size:var(--font-size-xl);font-weight:700;color:var(--cyan);">LOW</div>' +
        '</div>' +
        '<div style="flex:1;"></div>' +
        '<div id="threats-sources-summary" style="font-size:var(--font-size-sm);color:var(--text-secondary);"></div>' +
      '</div>' +

      '<div class="glass-card" style="margin-bottom:20px;">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Threat Sources Breakdown</div>' +
        '<div style="height:180px;"><canvas id="threats-sources-chart"></canvas></div>' +
      '</div>' +

      '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Recent Threats</div>' +
        '<div id="threats-list">' +
          '<div class="loading-state"><div class="spinner"></div><div>Loading threats...</div></div>' +
        '</div>' +
      '</div>';

    document.getElementById('threats-refresh').addEventListener('click', this.show.bind(this));
  },

  show: function() {
    this.loadThreats();
    this._refreshTimer = setInterval(this.loadThreats.bind(this), 30000);
  },

  hide: function() {
    if (this._refreshTimer) { clearInterval(this._refreshTimer); this._refreshTimer = null; }
  },

  loadThreats: function() {
    var container = document.getElementById('threats-list');
    var levelEl = document.getElementById('threats-level-badge');
    var sourcesEl = document.getElementById('threats-sources-summary');

    fetch('/api/threats', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var threats = data.threats || data || [];
        if (!Array.isArray(threats)) threats = [];

        // Update threat level
        var level = data.level || 'LOW';
        if (levelEl) {
          levelEl.textContent = level;
          if (level === 'CRITICAL' || level === 'HIGH') {
            levelEl.style.color = 'var(--orange)';
          } else if (level === 'MEDIUM') {
            levelEl.style.color = 'var(--purple)';
          } else {
            levelEl.style.color = 'var(--cyan)';
          }
        }

        // Sources breakdown
        var sources = {};
        threats.forEach(function(t) {
          var src = t.source || 'Unknown';
          sources[src] = (sources[src] || 0) + 1;
        });
        var srcLabels = Object.keys(sources);
        var srcValues = srcLabels.map(function(k) { return sources[k]; });
        if (sourcesEl) {
          sourcesEl.textContent = threats.length + ' threats from ' + srcLabels.length + ' sources';
        }
        if (srcLabels.length > 0) {
          createBarChart('threats-sources-chart', srcLabels, srcValues);
        }

        // Threats list
        if (threats.length === 0) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#9888;</div><div class="empty-state-title">No Active Threats</div><div class="empty-state-desc">The threat landscape is clear</div></div>';
          return;
        }

        var html = '<table class="data-table"><thead><tr><th>Severity</th><th>Threat</th><th>Source</th><th>Time</th><th>Action</th></tr></thead><tbody>';
        threats.forEach(function(t) {
          html += '<tr>' +
            '<td><span class="badge ' + severityBadge(t.severity) + '">' + escapeHtml(t.severity || 'info') + '</span></td>' +
            '<td style="color:var(--text-primary);">' + escapeHtml(t.title || t.description || '--') + '</td>' +
            '<td>' + escapeHtml(t.source || '--') + '</td>' +
            '<td>' + timeAgo(t.timestamp || t.created_at) + '</td>' +
            '<td><button class="btn btn-ghost btn-sm threat-triage-btn" data-id="' + escapeHtml(t.id || '') + '">Triage</button></td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;

        // Triage buttons
        container.querySelectorAll('.threat-triage-btn').forEach(function(btn) {
          btn.addEventListener('click', function() {
            var id = btn.getAttribute('data-id');
            Views.threats.triageThreat(id);
          });
        });
      })
      .catch(function() {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#9888;</div><div class="empty-state-title">No Active Threats</div><div class="empty-state-desc">Unable to fetch threat data</div></div>';
      });
  },

  triageThreat: function(id) {
    if (!id) return;
    Modal.loading('AI is analyzing threat...');
    fetch('/api/threats/' + id + '/triage', { method: 'POST', credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        Modal.close();
        var verdict = data.verdict || 'unknown';
        var confidence = data.confidence || 0;
        var reasoning = data.reasoning || 'No analysis available.';
        var verdictColor = verdict === 'true_positive' ? 'var(--orange)' :
                          verdict === 'false_positive' ? 'var(--cyan)' : 'var(--purple)';

        Modal.open({
          title: 'AI Triage Result',
          body:
            '<div style="margin-bottom:16px;">' +
              '<span style="color:' + verdictColor + ';font-weight:700;font-size:var(--font-size-lg);text-transform:uppercase;">' + escapeHtml(verdict.replace(/_/g, ' ')) + '</span>' +
              '<span style="margin-left:12px;color:var(--text-tertiary);">Confidence: ' + confidence + '%</span>' +
            '</div>' +
            '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;">' + escapeHtml(reasoning) + '</div>'
        });
      })
      .catch(function() {
        Modal.close();
        Toast.error('AI triage failed');
      });
  },

  update: function(data) {
    if (data && data.threats) {
      this.loadThreats();
    }
  }
};
