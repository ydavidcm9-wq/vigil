/* Vigil v1.0 — Web Application Scanner View */
Views['web-scanner'] = {
  init: function() {
    var el = document.getElementById('view-web-scanner');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Web Application Scanner</div>' +
      '</div>' +

      '<div class="glass-card" style="margin-bottom:20px;">' +
        '<div class="form-inline" style="flex-wrap:wrap;gap:10px;">' +
          '<div class="form-group" style="flex:2;">' +
            '<label class="form-label">Target URL</label>' +
            '<input type="text" class="form-input" id="web-target" placeholder="https://example.com">' +
          '</div>' +
          '<div class="form-group" style="flex:1;">' +
            '<label class="form-label">Scan Type</label>' +
            '<select class="form-select" id="web-scan-type">' +
              '<option value="passive">Passive Scan</option>' +
              '<option value="active">Active Scan</option>' +
              '<option value="spider">Spider / Crawl</option>' +
            '</select>' +
          '</div>' +
          '<div class="form-group" style="align-self:flex-end;">' +
            '<button class="btn btn-primary" id="web-scan-btn">Scan</button>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card" id="web-scanning" style="display:none;margin-bottom:20px;">' +
        '<div style="display:flex;align-items:center;gap:12px;">' +
          '<div class="spinner"></div>' +
          '<div style="color:var(--text-primary);">Running web application scan...</div>' +
        '</div>' +
      '</div>' +

      '<div id="web-summary" style="display:none;margin-bottom:20px;">' +
        '<div class="stat-grid">' +
          '<div class="stat-card"><div class="stat-card-label">High Risk</div><div class="stat-card-value" id="web-high" style="color:var(--orange);">0</div></div>' +
          '<div class="stat-card"><div class="stat-card-label">Medium Risk</div><div class="stat-card-value" id="web-medium" style="color:var(--purple);">0</div></div>' +
          '<div class="stat-card"><div class="stat-card-label">Low Risk</div><div class="stat-card-value" id="web-low" style="color:var(--cyan);">0</div></div>' +
          '<div class="stat-card"><div class="stat-card-label">Info</div><div class="stat-card-value" id="web-info">0</div></div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Findings</div>' +
        '<div id="web-results">' +
          '<div class="empty-state"><div class="empty-state-icon">&#127760;</div><div class="empty-state-title">No Results</div><div class="empty-state-desc">Enter a target URL and run a scan</div></div>' +
        '</div>' +
      '</div>';

    var self = this;
    document.getElementById('web-scan-btn').addEventListener('click', function() { self.runScan(); });
  },

  show: function() {},
  hide: function() {},

  runScan: function() {
    var target = document.getElementById('web-target').value.trim();
    if (!target) { Toast.warning('Enter a target URL'); return; }

    var scanType = document.getElementById('web-scan-type').value;
    var scanBtn = document.getElementById('web-scan-btn');
    var scanning = document.getElementById('web-scanning');
    var results = document.getElementById('web-results');
    var summary = document.getElementById('web-summary');

    scanBtn.disabled = true;
    scanning.style.display = 'block';

    fetch('/api/scan/web', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ target: target, scan_type: scanType })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      scanning.style.display = 'none';
      scanBtn.disabled = false;

      var alerts = data.alerts || data.findings || [];
      if (!Array.isArray(alerts)) alerts = [];

      // Count by risk
      var counts = { high: 0, medium: 0, low: 0, info: 0 };
      alerts.forEach(function(a) {
        var r = (a.risk || a.severity || 'info').toLowerCase();
        if (r === 'high' || r === 'critical') counts.high++;
        else if (r === 'medium') counts.medium++;
        else if (r === 'low') counts.low++;
        else counts.info++;
      });

      summary.style.display = 'block';
      document.getElementById('web-high').textContent = counts.high;
      document.getElementById('web-medium').textContent = counts.medium;
      document.getElementById('web-low').textContent = counts.low;
      document.getElementById('web-info').textContent = counts.info;

      if (alerts.length === 0) {
        results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10003;</div><div class="empty-state-title">No Issues Found</div></div>';
        return;
      }

      var html = '';
      alerts.forEach(function(a) {
        var risk = (a.risk || a.severity || 'info');
        html += '<div class="glass-card" style="margin-bottom:8px;padding:12px;cursor:pointer;" onclick="var d=this.querySelector(\'.web-detail\');d.style.display=d.style.display===\'none\'?\'block\':\'none\';">' +
          '<div style="display:flex;align-items:center;gap:10px;">' +
            '<span class="badge ' + severityBadge(risk) + '">' + escapeHtml(risk) + '</span>' +
            '<span style="color:var(--text-primary);font-weight:500;flex:1;">' + escapeHtml(a.name || a.title || '--') + '</span>' +
            '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + escapeHtml(a.url || a.target || '') + '</span>' +
          '</div>' +
          '<div class="web-detail" style="display:none;margin-top:12px;padding-top:12px;border-top:1px solid var(--border);">' +
            '<div class="detail-row"><div class="detail-label">Description</div><div class="detail-value">' + escapeHtml(a.description || '--') + '</div></div>' +
            '<div class="detail-row"><div class="detail-label">Solution</div><div class="detail-value">' + escapeHtml(a.solution || '--') + '</div></div>' +
            '<div class="detail-row"><div class="detail-label">URL</div><div class="detail-value">' + escapeHtml(a.url || '--') + '</div></div>' +
            (a.reference ? '<div class="detail-row"><div class="detail-label">Reference</div><div class="detail-value"><a href="' + escapeHtml(a.reference) + '" target="_blank" rel="noopener">' + escapeHtml(a.reference) + '</a></div></div>' : '') +
          '</div>' +
        '</div>';
      });
      results.innerHTML = html;
    })
    .catch(function() {
      scanning.style.display = 'none';
      scanBtn.disabled = false;
      results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Scan Failed</div><div class="empty-state-desc">Web scan could not complete. Ensure ZAP is available.</div></div>';
      Toast.error('Web scan failed');
    });
  }
};
