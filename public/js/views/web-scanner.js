/* Vigil v1.0 — Web Application Scanner View (with WAF Detection) */
Views['web-scanner'] = {
  _lastWafResult: null,
  _activeTab: 'findings',

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
          '<div class="form-group" style="align-self:flex-end;display:flex;gap:8px;">' +
            '<button class="btn btn-ghost btn-sm" id="web-waf-only-btn" title="WAF detection only">WAF Scan</button>' +
            '<button class="btn btn-primary" id="web-scan-btn">Full Scan</button>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card" id="web-scanning" style="display:none;margin-bottom:20px;">' +
        '<div style="display:flex;align-items:center;gap:12px;">' +
          '<div class="spinner"></div>' +
          '<div style="color:var(--text-primary);" id="web-scanning-text">Running web application scan...</div>' +
        '</div>' +
      '</div>' +

      '<div id="web-summary" style="display:none;margin-bottom:20px;">' +
        '<div class="stat-grid">' +
          '<div class="stat-card"><div class="stat-card-label">High Risk</div><div class="stat-card-value" id="web-high" style="color:var(--orange);">0</div></div>' +
          '<div class="stat-card"><div class="stat-card-label">Medium Risk</div><div class="stat-card-value" id="web-medium" style="color:var(--purple);">0</div></div>' +
          '<div class="stat-card"><div class="stat-card-label">Low Risk</div><div class="stat-card-value" id="web-low" style="color:var(--cyan);">0</div></div>' +
          '<div class="stat-card"><div class="stat-card-label">WAF</div><div class="stat-card-value" id="web-waf-badge" style="font-size:var(--font-size-sm);">--</div></div>' +
        '</div>' +
      '</div>' +

      // Tab bar
      '<div id="web-tabs" style="display:none;margin-bottom:0;">' +
        '<div style="display:flex;border-bottom:1px solid var(--border);margin-bottom:0;">' +
          '<button class="btn btn-ghost btn-sm web-tab active" data-tab="findings" style="border-radius:6px 6px 0 0;border-bottom:2px solid var(--cyan);margin-bottom:-1px;">Findings</button>' +
          '<button class="btn btn-ghost btn-sm web-tab" data-tab="waf" style="border-radius:6px 6px 0 0;margin-bottom:-1px;">WAF Detection</button>' +
        '</div>' +
      '</div>' +

      // Findings tab content
      '<div class="glass-card" id="web-tab-findings" style="border-radius:0 6px 6px 6px;">' +
        '<div id="web-results">' +
          '<div class="empty-state"><div class="empty-state-icon">&#127760;</div><div class="empty-state-title">No Results</div><div class="empty-state-desc">Enter a target URL and run a scan</div></div>' +
        '</div>' +
      '</div>' +

      // WAF tab content (hidden by default)
      '<div class="glass-card" id="web-tab-waf" style="display:none;border-radius:0 6px 6px 6px;">' +
        '<div id="web-waf-results">' +
          '<div class="empty-state"><div class="empty-state-icon">&#128737;</div><div class="empty-state-title">No WAF Scan</div><div class="empty-state-desc">Run a scan to detect WAF presence</div></div>' +
        '</div>' +
      '</div>';

    var self = this;
    document.getElementById('web-scan-btn').addEventListener('click', function() { self.runScan(); });
    document.getElementById('web-waf-only-btn').addEventListener('click', function() { self.runWAFScan(); });

    // Tab switching
    el.querySelectorAll('.web-tab').forEach(function(tab) {
      tab.addEventListener('click', function() {
        self.switchTab(tab.getAttribute('data-tab'));
      });
    });
  },

  show: function() {},
  hide: function() {},

  switchTab: function(tab) {
    this._activeTab = tab;
    document.querySelectorAll('.web-tab').forEach(function(t) {
      var isActive = t.getAttribute('data-tab') === tab;
      t.classList.toggle('active', isActive);
      t.style.borderBottom = isActive ? '2px solid var(--cyan)' : 'none';
    });
    document.getElementById('web-tab-findings').style.display = tab === 'findings' ? 'block' : 'none';
    document.getElementById('web-tab-waf').style.display = tab === 'waf' ? 'block' : 'none';
  },

  runWAFScan: function() {
    var target = document.getElementById('web-target').value.trim();
    if (!target) { Toast.warning('Enter a target URL'); return; }

    var scanBtn = document.getElementById('web-waf-only-btn');
    var scanning = document.getElementById('web-scanning');
    var scanningText = document.getElementById('web-scanning-text');
    var summary = document.getElementById('web-summary');
    var tabs = document.getElementById('web-tabs');

    scanBtn.disabled = true;
    document.getElementById('web-scan-btn').disabled = true;
    scanning.style.display = 'block';
    scanningText.textContent = 'Detecting WAF/CDN...';

    var scanType = document.getElementById('web-scan-type').value;
    var probeMode = scanType === 'active' ? 'active' : 'passive';
    var self = this;

    fetch('/api/scan/waf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ target: target, probe_mode: probeMode })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      scanning.style.display = 'none';
      scanBtn.disabled = false;
      document.getElementById('web-scan-btn').disabled = false;

      if (data.error) { Toast.error(data.error); return; }

      summary.style.display = 'block';
      tabs.style.display = 'block';

      // Reset finding counts
      document.getElementById('web-high').textContent = '0';
      document.getElementById('web-medium').textContent = '0';
      document.getElementById('web-low').textContent = '0';

      self._lastWafResult = data;
      self.renderWAFBadge(data);
      self.renderWAFResults(data);
      self.switchTab('waf');

      Toast.success(data.detected ? 'WAF detected: ' + data.waf.name : 'No WAF detected');
    })
    .catch(function() {
      scanning.style.display = 'none';
      scanBtn.disabled = false;
      document.getElementById('web-scan-btn').disabled = false;
      Toast.error('WAF scan failed');
    });
  },

  runScan: function() {
    var target = document.getElementById('web-target').value.trim();
    if (!target) { Toast.warning('Enter a target URL'); return; }

    var scanType = document.getElementById('web-scan-type').value;
    var scanBtn = document.getElementById('web-scan-btn');
    var scanning = document.getElementById('web-scanning');
    var scanningText = document.getElementById('web-scanning-text');
    var results = document.getElementById('web-results');
    var summary = document.getElementById('web-summary');
    var tabs = document.getElementById('web-tabs');

    scanBtn.disabled = true;
    document.getElementById('web-waf-only-btn').disabled = true;
    scanning.style.display = 'block';
    scanningText.textContent = 'Running web application scan...';

    var self = this;

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
      document.getElementById('web-waf-only-btn').disabled = false;

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
      tabs.style.display = 'block';
      document.getElementById('web-high').textContent = counts.high;
      document.getElementById('web-medium').textContent = counts.medium;
      document.getElementById('web-low').textContent = counts.low;

      // Handle WAF detection results
      if (data.wafDetection) {
        self._lastWafResult = data.wafDetection;
        self.renderWAFBadge(data.wafDetection);
        self.renderWAFResults(data.wafDetection);
      }

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
      document.getElementById('web-waf-only-btn').disabled = false;
      results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Scan Failed</div><div class="empty-state-desc">Web scan could not complete.</div></div>';
      Toast.error('Web scan failed');
    });
  },

  renderWAFBadge: function(wafData) {
    var badge = document.getElementById('web-waf-badge');
    if (!badge) return;
    if (wafData.detected && wafData.waf) {
      badge.textContent = wafData.waf.name;
      badge.style.color = 'var(--cyan)';
    } else {
      badge.textContent = 'None';
      badge.style.color = 'var(--orange)';
    }
  },

  renderWAFResults: function(wafData) {
    var container = document.getElementById('web-waf-results');
    if (!container) return;

    var html = '';

    // Main detection card
    if (wafData.detected && wafData.waf) {
      var confColor = wafData.waf.confidence >= 70 ? 'var(--cyan)' : wafData.waf.confidence >= 40 ? 'var(--purple, #a78bfa)' : 'var(--text-tertiary)';
      html += '<div class="glass-card" style="margin-bottom:12px;padding:16px;border-left:3px solid var(--cyan);">' +
        '<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">' +
          '<div style="font-size:28px;">&#128737;</div>' +
          '<div style="flex:1;">' +
            '<div style="font-size:var(--font-size-lg);font-weight:600;color:var(--text-primary);">' + escapeHtml(wafData.waf.name) + '</div>' +
            '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">Vendor: ' + escapeHtml(wafData.waf.vendor) + '</div>' +
          '</div>' +
          '<div style="text-align:center;">' +
            '<div style="font-size:var(--font-size-xl);font-weight:700;color:' + confColor + ';">' + wafData.waf.confidence + '%</div>' +
            '<div style="font-size:var(--font-size-xs);color:var(--text-tertiary);">confidence</div>' +
          '</div>' +
        '</div>' +
        '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);">Probe mode: ' + escapeHtml(wafData.probeMode) + ' | HTTP ' + wafData.statusCode + '</div>' +
      '</div>';

      // Additional WAFs
      if (wafData.allWAFs && wafData.allWAFs.length > 1) {
        html += '<div style="margin-bottom:12px;color:var(--text-secondary);font-size:var(--font-size-sm);font-weight:500;">Additional WAF/CDN layers detected:</div>';
        wafData.allWAFs.slice(1).forEach(function(w) {
          html += '<div class="glass-card" style="margin-bottom:6px;padding:10px;display:flex;align-items:center;gap:10px;">' +
            '<span style="color:var(--cyan);font-weight:500;">' + escapeHtml(w.name) + '</span>' +
            '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">(' + escapeHtml(w.vendor) + ')</span>' +
            '<span style="margin-left:auto;color:var(--text-tertiary);font-size:var(--font-size-xs);">' + w.score + '% conf</span>' +
          '</div>';
        });
      }
    } else {
      html += '<div class="glass-card" style="margin-bottom:12px;padding:16px;border-left:3px solid var(--orange);">' +
        '<div style="display:flex;align-items:center;gap:12px;">' +
          '<div style="font-size:28px;">&#9888;</div>' +
          '<div>' +
            '<div style="font-size:var(--font-size-lg);font-weight:600;color:var(--orange);">No WAF Detected</div>' +
            '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">Application may be directly exposed without WAF protection</div>' +
          '</div>' +
        '</div>' +
      '</div>';
    }

    // Evidence section
    if (wafData.evidence && wafData.evidence.length > 0) {
      html += '<div class="glass-card" style="padding:14px;">' +
        '<div style="font-weight:500;color:var(--text-primary);margin-bottom:10px;">Detection Evidence (' + wafData.evidence.length + ')</div>';
      wafData.evidence.forEach(function(e) {
        var methodIcon = { header: '&#128203;', cookie: '&#127850;', body: '&#128196;', certificate: '&#128274;', probe: '&#9889;', probe_body: '&#9889;', error: '&#10060;' }[e.method] || '&#128270;';
        var methodColor = { header: 'var(--cyan)', cookie: 'var(--purple, #a78bfa)', probe: 'var(--orange)', probe_body: 'var(--orange)', certificate: 'var(--cyan)' }[e.method] || 'var(--text-tertiary)';

        html += '<div style="display:flex;align-items:flex-start;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);">' +
          '<span style="font-size:14px;">' + methodIcon + '</span>' +
          '<div style="flex:1;">' +
            '<span style="color:' + methodColor + ';font-size:var(--font-size-xs);font-weight:600;text-transform:uppercase;">' + escapeHtml(e.method) + '</span>' +
            (e.waf ? '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-left:6px;">(' + escapeHtml(e.waf) + ')</span>' : '') +
            '<div style="color:var(--text-secondary);font-size:var(--font-size-xs);font-family:var(--font-mono);margin-top:2px;">' + escapeHtml(e.detail) + '</div>' +
          '</div>' +
        '</div>';
      });
      html += '</div>';
    }

    // Findings from WAF analysis
    if (wafData.findings && wafData.findings.length > 0) {
      html += '<div style="margin-top:12px;">';
      wafData.findings.forEach(function(f) {
        html += '<div class="glass-card" style="margin-bottom:6px;padding:10px;cursor:pointer;" onclick="var d=this.querySelector(\'.waf-detail\');d.style.display=d.style.display===\'none\'?\'block\':\'none\';">' +
          '<div style="display:flex;align-items:center;gap:8px;">' +
            '<span class="badge ' + severityBadge(f.severity) + '">' + escapeHtml(f.severity) + '</span>' +
            '<span style="color:var(--text-primary);font-weight:500;flex:1;">' + escapeHtml(f.name || f.title) + '</span>' +
          '</div>' +
          '<div class="waf-detail" style="display:none;margin-top:10px;padding-top:10px;border-top:1px solid var(--border);">' +
            '<div class="detail-row"><div class="detail-label">Description</div><div class="detail-value">' + escapeHtml(f.description || '--') + '</div></div>' +
            '<div class="detail-row"><div class="detail-label">Recommendation</div><div class="detail-value" style="color:var(--cyan);">' + escapeHtml(f.solution || '--') + '</div></div>' +
          '</div>' +
        '</div>';
      });
      html += '</div>';
    }

    // TLS info
    if (wafData.tlsInfo) {
      html += '<div style="margin-top:8px;padding:8px 12px;border-radius:6px;background:rgba(34,211,238,0.06);border:1px solid rgba(34,211,238,0.12);color:var(--text-tertiary);font-size:var(--font-size-xs);">' +
        'TLS Cert Issuer: <span style="color:var(--text-secondary);">' + escapeHtml(wafData.tlsInfo.issuer) + '</span>' +
        ' | Subject: <span style="color:var(--text-secondary);">' + escapeHtml(wafData.tlsInfo.subject) + '</span>' +
      '</div>';
    }

    container.innerHTML = html;
  }
};
