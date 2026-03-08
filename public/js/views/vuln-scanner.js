/* Vigil v1.0 — Vulnerability Scanner View */
Views['vuln-scanner'] = {
  init: function() {
    var el = document.getElementById('view-vuln-scanner');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Vulnerability Scanner</div>' +
      '</div>' +

      '<div class="glass-card" style="margin-bottom:20px;">' +
        '<div class="form-inline" style="flex-wrap:wrap;gap:10px;">' +
          '<div class="form-group" style="flex:2;">' +
            '<label class="form-label">Target URL</label>' +
            '<input type="text" class="form-input" id="vuln-target" placeholder="https://example.com">' +
          '</div>' +
          '<div class="form-group" style="flex:1;">' +
            '<label class="form-label">Template Category</label>' +
            '<select class="form-select" id="vuln-category">' +
              '<option value="all">All Templates</option>' +
              '<option value="cves">CVEs</option>' +
              '<option value="vulnerabilities">Vulnerabilities</option>' +
              '<option value="misconfiguration">Misconfigurations</option>' +
              '<option value="exposed-panels">Exposed Panels</option>' +
            '</select>' +
          '</div>' +
          '<div class="form-group" style="flex:1;">' +
            '<label class="form-label">Min Severity</label>' +
            '<select class="form-select" id="vuln-severity">' +
              '<option value="info">Info+</option>' +
              '<option value="low">Low+</option>' +
              '<option value="medium" selected>Medium+</option>' +
              '<option value="high">High+</option>' +
              '<option value="critical">Critical</option>' +
            '</select>' +
          '</div>' +
          '<div class="form-group" style="align-self:flex-end;">' +
            '<button class="btn btn-primary" id="vuln-scan-btn">Scan</button>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card" id="vuln-scanning-card" style="display:none;margin-bottom:20px;">' +
        '<div style="display:flex;align-items:center;gap:12px;">' +
          '<div class="spinner"></div>' +
          '<div style="color:var(--text-primary);">Running vulnerability scan...</div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card">' +
        '<div class="glass-card-header">' +
          '<div class="glass-card-title">Scan Results</div>' +
          '<div id="vuln-result-count" style="color:var(--text-tertiary);font-size:var(--font-size-sm);"></div>' +
        '</div>' +
        '<div id="vuln-results">' +
          '<div class="empty-state"><div class="empty-state-icon">&#128737;</div><div class="empty-state-title">No Results</div><div class="empty-state-desc">Enter a target URL and click Scan</div></div>' +
        '</div>' +
      '</div>';

    var self = this;
    document.getElementById('vuln-scan-btn').addEventListener('click', function() { self.runScan(); });
  },

  show: function() {},
  hide: function() {},

  runScan: function() {
    var target = document.getElementById('vuln-target').value.trim();
    if (!target) {
      Toast.warning('Enter a target URL');
      return;
    }

    var category = document.getElementById('vuln-category').value;
    var severity = document.getElementById('vuln-severity').value;
    var scanBtn = document.getElementById('vuln-scan-btn');
    var scanningCard = document.getElementById('vuln-scanning-card');
    var results = document.getElementById('vuln-results');
    var countEl = document.getElementById('vuln-result-count');

    scanBtn.disabled = true;
    scanningCard.style.display = 'block';

    fetch('/api/scan/nuclei', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ target: target, category: category, severity: severity })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      scanningCard.style.display = 'none';
      scanBtn.disabled = false;

      var findings = data.findings || data.results || [];
      if (!Array.isArray(findings)) findings = [];

      var scannerLabel = data.scanner === 'native' ? ' (built-in checks)' : data.scanner === 'nuclei' ? ' (nuclei)' : '';
      countEl.textContent = findings.length + ' finding(s)' + scannerLabel;

      if (findings.length === 0) {
        var desc = 'Target appears clean against selected templates';
        if (data.error) desc = escapeHtml(data.error);
        if (data.note) desc += '<br><span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + escapeHtml(data.note) + '</span>';
        results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10003;</div><div class="empty-state-title">No Vulnerabilities Found</div><div class="empty-state-desc">' + desc + '</div></div>';
        return;
      }

      // Show scanner note banner if using fallback
      var bannerHtml = '';
      if (data.note) {
        bannerHtml = '<div style="padding:8px 12px;margin-bottom:12px;border-radius:6px;background:rgba(34,211,238,0.08);border:1px solid rgba(34,211,238,0.15);color:var(--text-secondary);font-size:var(--font-size-sm);">' + escapeHtml(data.note) + '</div>';
      }

      var html = bannerHtml;
      findings.forEach(function(f, idx) {
        html += '<div class="glass-card" style="margin-bottom:8px;padding:12px;cursor:pointer;" onclick="this.querySelector(\'.vuln-detail\').style.display=this.querySelector(\'.vuln-detail\').style.display===\'none\'?\'block\':\'none\';">' +
          '<div style="display:flex;align-items:center;gap:10px;">' +
            '<span class="badge ' + severityBadge(f.severity) + '">' + escapeHtml(f.severity || 'info') + '</span>' +
            '<span style="color:var(--text-primary);font-weight:500;flex:1;">' + escapeHtml(f.title || f.name || f.template_id || 'Finding #' + (idx + 1)) + '</span>' +
            '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + escapeHtml(f.matched_at || f.target || target) + '</span>' +
          '</div>' +
          '<div class="vuln-detail" style="display:none;margin-top:12px;padding-top:12px;border-top:1px solid var(--border);">' +
            '<div class="detail-row"><div class="detail-label">Template</div><div class="detail-value">' + escapeHtml(f.template_id || '--') + '</div></div>' +
            '<div class="detail-row"><div class="detail-label">Matched At</div><div class="detail-value">' + escapeHtml(f.matched_at || '--') + '</div></div>' +
            '<div class="detail-row"><div class="detail-label">Description</div><div class="detail-value">' + escapeHtml(f.description || 'No description available') + '</div></div>' +
            (f.reference ? '<div class="detail-row"><div class="detail-label">Reference</div><div class="detail-value"><a href="' + escapeHtml(f.reference) + '" target="_blank" rel="noopener">' + escapeHtml(f.reference) + '</a></div></div>' : '') +
            (f.cve ? '<div class="detail-row"><div class="detail-label">CVE</div><div class="detail-value">' + escapeHtml(f.cve) + '</div></div>' : '') +
          '</div>' +
        '</div>';
      });
      results.innerHTML = html;
    })
    .catch(function() {
      scanningCard.style.display = 'none';
      scanBtn.disabled = false;
      results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Scan Failed</div><div class="empty-state-desc">Could not complete vulnerability scan. Ensure nuclei is installed.</div></div>';
      Toast.error('Vulnerability scan failed');
    });
  }
};
