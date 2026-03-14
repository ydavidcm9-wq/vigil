/* Vigil v1.1 — Port Scanner View */
Views['port-scanner'] = {
  init: function() {
    var el = document.getElementById('view-port-scanner');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Port Scanner</div>' +
      '</div>' +

      '<div class="glass-card" style="margin-bottom:20px;">' +
        '<div class="form-inline" style="flex-wrap:wrap;gap:10px;">' +
          '<div class="form-group" style="flex:2;">' +
            '<label class="form-label">Target (IP / Hostname / CIDR)</label>' +
            '<input type="text" class="form-input" id="port-target" placeholder="192.168.1.1 or example.com">' +
          '</div>' +
          '<div class="form-group" style="flex:1;">' +
            '<label class="form-label">Scan Type</label>' +
            '<select class="form-select" id="port-scan-type">' +
              '<option value="quick">Quick (Top 100)</option>' +
              '<option value="full">Full (All 65535)</option>' +
              '<option value="stealth">Stealth (SYN)</option>' +
              '<option value="custom">Custom Range</option>' +
            '</select>' +
          '</div>' +
          '<div class="form-group" style="flex:1;" id="port-range-group" style="display:none;">' +
            '<label class="form-label">Port Range</label>' +
            '<input type="text" class="form-input" id="port-range" placeholder="1-1024">' +
          '</div>' +
          '<div class="form-group" style="align-self:flex-end;">' +
            '<button class="btn btn-primary" id="port-scan-btn">Scan</button>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card" style="margin-bottom:20px;" id="port-progress-card" style="display:none;">' +
        '<div style="display:flex;align-items:center;gap:12px;">' +
          '<div class="spinner"></div>' +
          '<div>' +
            '<div style="color:var(--text-primary);font-weight:500;">Scanning...</div>' +
            '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);" id="port-progress-text">Initializing scan</div>' +
          '</div>' +
        '</div>' +
        '<div class="progress-bar" style="margin-top:12px;">' +
          '<div class="progress-bar-fill" id="port-progress-bar" style="width:0%;"></div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card">' +
        '<div class="glass-card-header">' +
          '<div class="glass-card-title">Scan Results</div>' +
          '<button class="btn btn-ghost btn-sm" id="port-save-btn" style="display:none;">Save Results</button>' +
        '</div>' +
        '<div id="port-results">' +
          '<div class="empty-state"><div class="empty-state-icon">&#128225;</div><div class="empty-state-title">No Scan Results</div><div class="empty-state-desc">Enter a target and click Scan to begin</div></div>' +
        '</div>' +
      '</div>';

    var self = this;
    document.getElementById('port-scan-btn').addEventListener('click', function() { self.runScan(); });
    document.getElementById('port-scan-type').addEventListener('change', function() {
      var group = document.getElementById('port-range-group');
      if (this.value === 'custom') {
        group.style.display = 'block';
      } else {
        group.style.display = 'none';
      }
    });
    document.getElementById('port-save-btn').addEventListener('click', function() { self.saveResults(); });
  },

  show: function() {},
  hide: function() {},

  _lastResults: null,

  runScan: function() {
    var target = document.getElementById('port-target').value.trim();
    if (!target) {
      Toast.warning('Enter a target IP or hostname');
      return;
    }

    var scanType = document.getElementById('port-scan-type').value;
    var portRange = document.getElementById('port-range').value.trim();
    var progressCard = document.getElementById('port-progress-card');
    var scanBtn = document.getElementById('port-scan-btn');
    var results = document.getElementById('port-results');

    scanBtn.disabled = true;
    progressCard.style.display = 'block';
    results.innerHTML = '';

    var body = { target: target, scan_type: scanType };
    if (scanType === 'custom' && portRange) body.port_range = portRange;

    fetch('/api/scan/ports', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(body)
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      progressCard.style.display = 'none';
      scanBtn.disabled = false;

      var ports = data.ports || data.results || [];
      Views['port-scanner']._lastResults = data;

      if (!Array.isArray(ports) || ports.length === 0) {
        results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10003;</div><div class="empty-state-title">No Open Ports Found</div><div class="empty-state-desc">Target appears secure or unreachable</div></div>';
        return;
      }

      document.getElementById('port-save-btn').style.display = 'inline-flex';

      var html = '<div style="margin-bottom:12px;color:var(--text-secondary);font-size:var(--font-size-sm);">Found ' + ports.length + ' open port(s) on ' + escapeHtml(target) + '</div>';
      html += '<table class="data-table"><thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th></tr></thead><tbody>';
      ports.forEach(function(p) {
        var stateColor = p.state === 'open' ? 'var(--cyan)' : 'var(--text-tertiary)';
        html += '<tr>' +
          '<td style="color:var(--text-primary);font-weight:600;">' + escapeHtml(String(p.port || '')) + '</td>' +
          '<td>' + escapeHtml(p.protocol || 'tcp') + '</td>' +
          '<td><span style="color:' + stateColor + ';">' + escapeHtml(p.state || 'unknown') + '</span></td>' +
          '<td>' + escapeHtml(p.service || '--') + '</td>' +
          '<td>' + escapeHtml(p.version || '--') + '</td>' +
          '</tr>';
      });
      html += '</tbody></table>';
      results.innerHTML = html;
    })
    .catch(function() {
      progressCard.style.display = 'none';
      scanBtn.disabled = false;
      results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Scan Failed</div><div class="empty-state-desc">Could not complete port scan. Ensure nmap is installed.</div></div>';
      Toast.error('Port scan failed');
    });
  },

  saveResults: function() {
    if (!this._lastResults) return;
    fetch('/api/scan/ports/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(this._lastResults)
    })
    .then(function() { Toast.success('Scan results saved'); })
    .catch(function() { Toast.error('Failed to save results'); });
  }
};
