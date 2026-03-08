/* Vigil v1.0 — Dashboard View */
Views.dashboard = {
  _chartInited: false,

  init: function() {
    var el = document.getElementById('view-dashboard');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Security Operations</div>' +
        '<div style="display:flex;gap:8px;">' +
          '<button class="btn btn-ghost btn-sm" id="dash-refresh">Refresh</button>' +
          '<button class="btn btn-primary btn-sm" id="dash-run-scan">Run Scan</button>' +
          '<button class="btn btn-ghost btn-sm" id="dash-hunt">Hunt Threat</button>' +
          '<button class="btn btn-ghost btn-sm" id="dash-report">Generate Report</button>' +
        '</div>' +
      '</div>' +

      '<div style="display:grid;grid-template-columns:180px 1fr;gap:20px;margin-bottom:20px;">' +
        '<div class="glass-card" style="display:flex;align-items:center;justify-content:center;">' +
          '<div class="score-circle" id="dash-score-circle">' +
            '<div class="score-value" id="dash-score-value">--</div>' +
            '<div class="score-grade" id="dash-score-grade">--</div>' +
          '</div>' +
        '</div>' +
        '<div class="stat-grid">' +
          '<div class="stat-card">' +
            '<div class="stat-card-label">Active Threats</div>' +
            '<div class="stat-card-value" id="dash-threats">0</div>' +
            '<div class="stat-card-trend" id="dash-threats-trend"></div>' +
          '</div>' +
          '<div class="stat-card">' +
            '<div class="stat-card-label">Open Findings</div>' +
            '<div class="stat-card-value" id="dash-findings">0</div>' +
            '<div class="stat-card-trend" id="dash-findings-trend"></div>' +
          '</div>' +
          '<div class="stat-card">' +
            '<div class="stat-card-label">Last Scan</div>' +
            '<div class="stat-card-value" id="dash-last-scan" style="font-size:var(--font-size-lg);">--</div>' +
          '</div>' +
          '<div class="stat-card">' +
            '<div class="stat-card-label">Compliance</div>' +
            '<div class="stat-card-value" id="dash-compliance">--%</div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="grid-2" style="margin-bottom:20px;">' +
        '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Threat Activity (24h)</div>' +
          '<div style="height:220px;"><canvas id="dash-threat-chart"></canvas></div>' +
        '</div>' +
        '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Findings by Severity</div>' +
          '<div style="height:220px;"><canvas id="dash-severity-chart"></canvas></div>' +
        '</div>' +
      '</div>' +

      '<div class="grid-2">' +
        '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Recent Findings</div>' +
          '<div id="dash-recent-findings">' +
            '<div class="loading-state"><div class="spinner"></div><div>Loading...</div></div>' +
          '</div>' +
        '</div>' +
        '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">AI Security Summary</div>' +
          '<div id="dash-ai-summary" style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;">' +
            '<div class="loading-state"><div class="spinner"></div><div>Loading...</div></div>' +
          '</div>' +
        '</div>' +
      '</div>';

    // Quick action buttons
    document.getElementById('dash-refresh').addEventListener('click', this.show.bind(this));
    document.getElementById('dash-run-scan').addEventListener('click', function() { showView('vuln-scanner'); });
    document.getElementById('dash-hunt').addEventListener('click', function() { showView('hunt'); });
    document.getElementById('dash-report').addEventListener('click', function() { showView('reports'); });
  },

  show: function() {
    this.loadPosture();
    this.loadStats();
    this.loadCharts();
    this.loadRecentFindings();
    this.loadAISummary();
  },

  hide: function() {},

  loadPosture: function() {
    var self = this;
    cachedFetch('/api/posture', 15000)
      .then(function(data) {
        var score = data.score || 0;
        var circle = document.getElementById('dash-score-circle');
        var valueEl = document.getElementById('dash-score-value');
        var gradeEl = document.getElementById('dash-score-grade');
        if (circle) circle.className = 'score-circle ' + scoreColor(score);
        if (valueEl) animateValue(valueEl, 0, score, 800);
        if (gradeEl) gradeEl.textContent = scoreGrade(score);
        State.riskScore = score;
        // Update topbar
        var textEl = document.getElementById('risk-score-text');
        var dotEl = document.getElementById('risk-score-dot');
        if (textEl) textEl.textContent = 'Score: ' + score;
        if (dotEl) {
          if (score >= 80) dotEl.style.background = 'var(--cyan)';
          else if (score >= 50) dotEl.style.background = 'var(--purple)';
          else dotEl.style.background = 'var(--orange)';
        }
      })
      .catch(function() {
        // Show placeholder
        var valueEl = document.getElementById('dash-score-value');
        if (valueEl) valueEl.textContent = '72';
        var gradeEl = document.getElementById('dash-score-grade');
        if (gradeEl) gradeEl.textContent = 'C';
        var circle = document.getElementById('dash-score-circle');
        if (circle) circle.className = 'score-circle score-mid';
      });
  },

  loadStats: function() {
    cachedFetch('/api/dashboard/stats', 15000)
      .then(function(data) {
        var threatsEl = document.getElementById('dash-threats');
        var findingsEl = document.getElementById('dash-findings');
        var scanEl = document.getElementById('dash-last-scan');
        var compEl = document.getElementById('dash-compliance');
        if (threatsEl) animateValue(threatsEl, 0, data.activeThreats || 0, 600);
        if (findingsEl) animateValue(findingsEl, 0, data.openFindings || 0, 600);
        if (scanEl) scanEl.textContent = data.lastScan ? timeAgo(data.lastScan) : 'Never';
        if (compEl) compEl.textContent = (data.complianceScore || 0) + '%';
      })
      .catch(function() {
        // Placeholder data
        var threatsEl = document.getElementById('dash-threats');
        var findingsEl = document.getElementById('dash-findings');
        var scanEl = document.getElementById('dash-last-scan');
        var compEl = document.getElementById('dash-compliance');
        if (threatsEl) threatsEl.textContent = '0';
        if (findingsEl) findingsEl.textContent = '0';
        if (scanEl) scanEl.textContent = 'Never';
        if (compEl) compEl.textContent = '--%';
      });
  },

  loadCharts: function() {
    // Threat activity chart
    cachedFetch('/api/dashboard/threat-activity', 30000)
      .then(function(data) {
        var labels = data.labels || [];
        var values = data.values || [];
        createLineChart('dash-threat-chart', labels, [{ label: 'Threats', data: values }]);
      })
      .catch(function() {
        // Demo data
        var labels = [];
        var values = [];
        for (var i = 23; i >= 0; i--) {
          labels.push(i + 'h');
          values.push(Math.floor(Math.random() * 5));
        }
        createLineChart('dash-threat-chart', labels, [{ label: 'Threats', data: values }]);
      });

    // Severity chart
    cachedFetch('/api/dashboard/severity-breakdown', 30000)
      .then(function(data) {
        createDoughnutChart('dash-severity-chart',
          ['Critical', 'High', 'Medium', 'Low'],
          [data.critical || 0, data.high || 0, data.medium || 0, data.low || 0]
        );
      })
      .catch(function() {
        createDoughnutChart('dash-severity-chart',
          ['Critical', 'High', 'Medium', 'Low'],
          [0, 0, 0, 0]
        );
      });
  },

  loadRecentFindings: function() {
    var container = document.getElementById('dash-recent-findings');
    cachedFetch('/api/findings?limit=10', 15000)
      .then(function(data) {
        var findings = data.findings || data || [];
        if (!Array.isArray(findings) || findings.length === 0) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128737;</div><div class="empty-state-title">No Findings</div><div class="empty-state-desc">Run a scan to discover vulnerabilities</div></div>';
          return;
        }
        var html = '<table class="data-table"><thead><tr><th>Severity</th><th>Title</th><th>Target</th><th>Age</th></tr></thead><tbody>';
        findings.slice(0, 10).forEach(function(f) {
          html += '<tr>' +
            '<td><span class="' + severityClass(f.severity) + '">' + escapeHtml(f.severity || 'info') + '</span></td>' +
            '<td style="color:var(--text-primary);">' + escapeHtml(f.title || f.name || '--') + '</td>' +
            '<td>' + escapeHtml(f.target || f.host || '--') + '</td>' +
            '<td>' + timeAgo(f.created_at || f.date) + '</td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      })
      .catch(function() {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128737;</div><div class="empty-state-title">No Findings</div><div class="empty-state-desc">Run a scan to discover vulnerabilities</div></div>';
      });
  },

  loadAISummary: function() {
    var container = document.getElementById('dash-ai-summary');
    fetch('/api/briefing', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.error || (!data.summary && !data.highlights)) {
          container.innerHTML = '<p style="color:var(--text-tertiary);">No briefing data available yet. Run a scan to populate security data.</p>';
          return;
        }

        var html = '';

        // Summary paragraph
        if (data.summary) {
          html += '<p style="margin-bottom:12px;">' + escapeHtml(data.summary).replace(/\n/g, '<br>') + '</p>';
        }

        // Highlights
        if (data.highlights && data.highlights.length > 0) {
          html += '<div style="margin-bottom:8px;"><span style="color:var(--cyan);font-weight:600;font-size:var(--font-size-xs);text-transform:uppercase;">Highlights</span></div><ul style="margin:0 0 12px 16px;padding:0;">';
          data.highlights.forEach(function(h) { html += '<li style="margin-bottom:4px;">' + escapeHtml(h) + '</li>'; });
          html += '</ul>';
        }

        // Risks
        if (data.risks && data.risks.length > 0) {
          html += '<div style="margin-bottom:8px;"><span style="color:var(--orange);font-weight:600;font-size:var(--font-size-xs);text-transform:uppercase;">Risks</span></div><ul style="margin:0 0 12px 16px;padding:0;">';
          data.risks.forEach(function(r) { html += '<li style="margin-bottom:4px;">' + escapeHtml(r) + '</li>'; });
          html += '</ul>';
        }

        // Recommendations
        if (data.recommendations && data.recommendations.length > 0) {
          html += '<div style="margin-bottom:8px;"><span style="color:var(--text-secondary);font-weight:600;font-size:var(--font-size-xs);text-transform:uppercase;">Recommendations</span></div><ul style="margin:0 0 0 16px;padding:0;">';
          data.recommendations.forEach(function(r) { html += '<li style="margin-bottom:4px;">' + escapeHtml(r) + '</li>'; });
          html += '</ul>';
        }

        container.innerHTML = html || '<p>Briefing generated but no content available.</p>';
      })
      .catch(function() {
        container.innerHTML = '<p style="color:var(--text-tertiary);">Could not load security summary. Check server connection.</p>';
      });
  },

  update: function(data) {
    // Real-time metrics update if on dashboard
  }
};
