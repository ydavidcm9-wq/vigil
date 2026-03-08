/* Vigil v1.0 — OSINT Reconnaissance View */
Views.osint = {
  _lastDomainData: null,

  init: function() {
    var el = document.getElementById('view-osint');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">OSINT Reconnaissance</div>' +
      '</div>' +

      '<div class="tab-bar" id="osint-tabs">' +
        '<div class="tab-item active" data-tab="osint-domain">Domain Intel</div>' +
        '<div class="tab-item" data-tab="osint-ip">IP Lookup</div>' +
        '<div class="tab-item" data-tab="osint-history">History</div>' +
      '</div>' +

      // ── Domain Tab ──────────────────────────────────────────────────
      '<div class="tab-content active" id="osint-domain">' +
        '<div class="glass-card" style="margin-bottom:20px;">' +
          '<div class="form-inline">' +
            '<div class="form-group" style="flex:1;">' +
              '<label class="form-label">Domain</label>' +
              '<input type="text" class="form-input" id="osint-domain-input" placeholder="example.com">' +
            '</div>' +
            '<div class="form-group" style="align-self:flex-end;">' +
              '<button class="btn btn-primary" id="osint-domain-btn">Investigate</button>' +
            '</div>' +
          '</div>' +
        '</div>' +
        '<div id="osint-domain-results">' +
          '<div class="empty-state"><div class="empty-state-icon">&#128065;</div><div class="empty-state-title">Domain Intelligence</div><div class="empty-state-desc">Enter a domain to gather WHOIS, DNS, SSL, subdomains, certificates, and AI security assessment</div></div>' +
        '</div>' +
      '</div>' +

      // ── IP Tab ──────────────────────────────────────────────────────
      '<div class="tab-content" id="osint-ip">' +
        '<div class="glass-card" style="margin-bottom:20px;">' +
          '<div class="form-inline">' +
            '<div class="form-group" style="flex:1;">' +
              '<label class="form-label">IP Address</label>' +
              '<input type="text" class="form-input" id="osint-ip-input" placeholder="8.8.8.8">' +
            '</div>' +
            '<div class="form-group" style="align-self:flex-end;">' +
              '<button class="btn btn-primary" id="osint-ip-btn">Investigate</button>' +
            '</div>' +
          '</div>' +
        '</div>' +
        '<div id="osint-ip-results">' +
          '<div class="empty-state"><div class="empty-state-icon">&#128065;</div><div class="empty-state-title">IP Intelligence</div><div class="empty-state-desc">Enter an IP address for geolocation, reverse DNS, port scan, and AI assessment</div></div>' +
        '</div>' +
      '</div>' +

      // ── History Tab ─────────────────────────────────────────────────
      '<div class="tab-content" id="osint-history">' +
        '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Past Lookups</div>' +
          '<div id="osint-history-list">' +
            '<div class="empty-state"><div class="empty-state-icon">&#128339;</div><div class="empty-state-title">No History</div><div class="empty-state-desc">Investigations will appear here</div></div>' +
          '</div>' +
        '</div>' +
      '</div>';

    var self = this;

    // Tabs
    document.querySelectorAll('#osint-tabs .tab-item').forEach(function(tab) {
      tab.addEventListener('click', function() {
        document.querySelectorAll('#osint-tabs .tab-item').forEach(function(t) { t.classList.remove('active'); });
        tab.classList.add('active');
        document.querySelectorAll('#view-osint > .tab-content').forEach(function(c) { c.classList.remove('active'); });
        document.getElementById(tab.getAttribute('data-tab')).classList.add('active');
      });
    });

    document.getElementById('osint-domain-btn').addEventListener('click', function() { self.lookupDomain(); });
    document.getElementById('osint-domain-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') self.lookupDomain();
    });
    document.getElementById('osint-ip-btn').addEventListener('click', function() { self.lookupIP(); });
    document.getElementById('osint-ip-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') self.lookupIP();
    });
  },

  show: function() {
    this.loadHistory();
  },

  hide: function() {},

  // ── Domain Investigation ────────────────────────────────────────────
  lookupDomain: function() {
    var domain = document.getElementById('osint-domain-input').value.trim();
    if (!domain) { Toast.warning('Enter a domain'); return; }

    var btn = document.getElementById('osint-domain-btn');
    var results = document.getElementById('osint-domain-results');
    btn.disabled = true;
    btn.textContent = 'Investigating...';
    results.innerHTML = '<div class="loading-state"><div class="spinner spinner-lg"></div><div>Gathering intelligence on ' + escapeHtml(domain) + '...<br><span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">DNS, WHOIS, SSL, subdomains, cert transparency, HTTP headers, AI analysis</span></div></div>';

    fetch('/api/osint/domain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ domain: domain })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      btn.disabled = false;
      btn.textContent = 'Investigate';

      if (data.error) { results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Error</div><div class="empty-state-desc">' + escapeHtml(data.error) + '</div></div>'; Toast.error(data.error); return; }

      Views.osint._lastDomainData = data;
      var html = '';

      // ── AI Analysis (top, most valuable) ──────────────────────────
      if (data.analysis) {
        html += '<div class="glass-card" style="margin-bottom:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:8px;color:var(--cyan);">AI Security Assessment</div>' +
          '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;white-space:pre-wrap;">' + escapeHtml(data.analysis) + '</div>' +
          '</div>';
      }

      // ── Stat cards ────────────────────────────────────────────────
      html += '<div class="stat-grid" style="margin-bottom:16px;">' +
        '<div class="stat-card">' +
          '<div class="stat-card-label">Subdomains</div>' +
          '<div class="stat-card-value" style="color:var(--cyan);">' + (data.subdomains || []).length + '</div>' +
        '</div>' +
        '<div class="stat-card">' +
          '<div class="stat-card-label">Certificates</div>' +
          '<div class="stat-card-value">' + (data.certificates || []).length + '</div>' +
        '</div>' +
        '<div class="stat-card">' +
          '<div class="stat-card-label">Technologies</div>' +
          '<div class="stat-card-value">' + (data.technologies || []).length + '</div>' +
        '</div>' +
        '<div class="stat-card">' +
          '<div class="stat-card-label">Missing Headers</div>' +
          '<div class="stat-card-value" style="color:' + ((data.httpInfo && data.httpInfo.missingHeaders && data.httpInfo.missingHeaders.length > 0) ? 'var(--orange)' : 'var(--cyan)') + ';">' + (data.httpInfo && data.httpInfo.missingHeaders ? data.httpInfo.missingHeaders.length : '--') + '</div>' +
        '</div>' +
      '</div>';

      // ── WHOIS + SSL side by side ──────────────────────────────────
      html += '<div class="grid-2" style="margin-bottom:16px;">';

      // WHOIS
      var whois = data.whois || {};
      html += '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:8px;">WHOIS</div>';
      if (whois.registrar || whois.created) {
        html += Views.osint.detailRow('Registrar', whois.registrar) +
          Views.osint.detailRow('Created', whois.created) +
          Views.osint.detailRow('Expires', whois.expires) +
          Views.osint.detailRow('Registrant', whois.registrant) +
          Views.osint.detailRow('Nameservers', (whois.nameservers || []).join(', '));
        if (whois.status && whois.status.length > 0) {
          html += '<div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:4px;">';
          whois.status.forEach(function(s) { html += '<span class="tag" style="font-size:10px;">' + escapeHtml(s.split(' ')[0]) + '</span>'; });
          html += '</div>';
        }
      } else {
        html += '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">WHOIS data unavailable — install whois for full data</div>';
      }
      html += '</div>';

      // SSL
      var ssl = data.ssl;
      html += '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:8px;">SSL Certificate</div>';
      if (ssl) {
        html += Views.osint.detailRow('Common Name', ssl.cn) +
          Views.osint.detailRow('Issuer', ssl.issuer) +
          Views.osint.detailRow('Valid From', ssl.valid_from) +
          Views.osint.detailRow('Valid To', ssl.valid_to) +
          Views.osint.detailRow('Protocol', ssl.protocol) +
          Views.osint.detailRow('SAN Count', ssl.san_count);
      } else {
        html += '<div style="color:var(--orange);font-size:var(--font-size-sm);">No SSL certificate — site may not support HTTPS</div>';
      }
      html += '</div></div>';

      // ── Technologies ──────────────────────────────────────────────
      var tech = data.technologies || [];
      if (tech.length > 0) {
        html += '<div class="glass-card" style="margin-bottom:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:8px;">Technologies Detected</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
        tech.forEach(function(t) { html += '<span class="tag tag-cyan">' + escapeHtml(t) + '</span>'; });
        html += '</div></div>';
      }

      // ── Security Headers ──────────────────────────────────────────
      var httpInfo = data.httpInfo;
      if (httpInfo) {
        html += '<div class="glass-card" style="margin-bottom:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:8px;">HTTP Security Headers</div>';
        var sh = httpInfo.securityHeaders || {};
        var headerNames = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'x-xss-protection', 'referrer-policy', 'permissions-policy'];
        html += '<table class="data-table"><thead><tr><th>Header</th><th>Status</th><th>Value</th></tr></thead><tbody>';
        headerNames.forEach(function(h) {
          var val = sh[h];
          var present = val ? true : false;
          html += '<tr>' +
            '<td style="color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-xs);">' + escapeHtml(h) + '</td>' +
            '<td><span style="color:' + (present ? 'var(--cyan)' : 'var(--orange)') + ';font-weight:600;">' + (present ? 'Present' : 'Missing') + '</span></td>' +
            '<td style="font-size:var(--font-size-xs);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + escapeHtml(val || '--') + '</td>' +
            '</tr>';
        });
        html += '</tbody></table></div>';
      }

      // ── Subdomains ────────────────────────────────────────────────
      var subs = data.subdomains || [];
      if (subs.length > 0) {
        html += '<div class="glass-card" style="margin-bottom:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:8px;">Subdomains (' + subs.length + ')</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
        subs.forEach(function(s) { html += '<span class="tag">' + escapeHtml(s) + '</span>'; });
        html += '</div></div>';
      }

      // ── Certificates ──────────────────────────────────────────────
      var certs = data.certificates || [];
      if (certs.length > 0) {
        html += '<div class="glass-card" style="margin-bottom:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:8px;">Certificates (' + certs.length + ')</div>' +
          '<table class="data-table"><thead><tr><th>Common Name</th><th>Issuer</th><th>Valid Until</th></tr></thead><tbody>';
        certs.slice(0, 25).forEach(function(c) {
          html += '<tr>' +
            '<td style="color:var(--text-primary);">' + escapeHtml(c.cn || '--') + '</td>' +
            '<td>' + escapeHtml(c.issuer || '--') + '</td>' +
            '<td>' + escapeHtml(c.valid_to || '--') + '</td>' +
            '</tr>';
        });
        html += '</tbody></table></div>';
      }

      // ── DNS Records (collapsed) ───────────────────────────────────
      var dnsData = data.dns || {};
      var dnsTypes = Object.keys(dnsData);
      if (dnsTypes.length > 0) {
        html += '<div class="glass-card" style="margin-bottom:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:8px;">DNS Records</div>';
        dnsTypes.forEach(function(type) {
          var records = dnsData[type];
          if (!records) return;
          var recordStr = '';
          if (Array.isArray(records)) {
            recordStr = records.map(function(r) {
              if (typeof r === 'string') return r;
              if (r.exchange) return r.priority + ' ' + r.exchange;
              if (r.value) return r.value;
              return JSON.stringify(r);
            }).join(', ');
          } else if (typeof records === 'object') {
            recordStr = records.nsname ? records.nsname + ' (serial: ' + records.serial + ')' : JSON.stringify(records);
          }
          if (recordStr) {
            html += '<div style="margin-bottom:6px;">' +
              '<span class="tag tag-cyan" style="min-width:40px;text-align:center;display:inline-block;">' + escapeHtml(type) + '</span> ' +
              '<span style="color:var(--text-secondary);font-size:var(--font-size-sm);font-family:var(--font-mono);">' + escapeHtml(recordStr) + '</span>' +
              '</div>';
          }
        });
        html += '</div>';
      }

      // ── Re-analyze button ─────────────────────────────────────────
      if (!data.analysis) {
        html += '<div style="text-align:center;margin-top:16px;">' +
          '<button class="btn btn-ghost" id="osint-ai-domain">Run AI Analysis</button>' +
          '</div>';
      }

      results.innerHTML = html;
      Toast.success('OSINT investigation complete');

      // AI Analysis button handler (only if no analysis was returned)
      var aiBtn = document.getElementById('osint-ai-domain');
      if (aiBtn) {
        aiBtn.addEventListener('click', function() {
          aiBtn.disabled = true;
          aiBtn.textContent = 'Analyzing...';
          fetch('/api/osint/domain/' + encodeURIComponent(domain) + '/analyze', { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(d) {
              if (d.analysis) {
                Modal.open({ title: 'AI OSINT Analysis: ' + domain, body: '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;white-space:pre-wrap;">' + escapeHtml(d.analysis) + '</div>', size: 'lg' });
              } else {
                Toast.warning('No analysis available — configure AI provider in Settings');
              }
              aiBtn.disabled = false;
              aiBtn.textContent = 'Run AI Analysis';
            })
            .catch(function() { aiBtn.disabled = false; aiBtn.textContent = 'Run AI Analysis'; Toast.error('AI analysis failed'); });
        });
      }

      Views.osint.loadHistory();
    })
    .catch(function() {
      btn.disabled = false;
      btn.textContent = 'Investigate';
      results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Investigation Failed</div><div class="empty-state-desc">Check server connection and try again</div></div>';
      Toast.error('OSINT lookup failed');
    });
  },

  // ── IP Investigation ────────────────────────────────────────────────
  lookupIP: function() {
    var ip = document.getElementById('osint-ip-input').value.trim();
    if (!ip) { Toast.warning('Enter an IP address'); return; }

    var btn = document.getElementById('osint-ip-btn');
    var results = document.getElementById('osint-ip-results');
    btn.disabled = true;
    btn.textContent = 'Investigating...';
    results.innerHTML = '<div class="loading-state"><div class="spinner spinner-lg"></div><div>Gathering intelligence on ' + escapeHtml(ip) + '...<br><span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">Reverse DNS, geolocation, port scan, AI analysis</span></div></div>';

    fetch('/api/osint/ip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ ip: ip })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      btn.disabled = false;
      btn.textContent = 'Investigate';

      if (data.error) { results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Error</div><div class="empty-state-desc">' + escapeHtml(data.error) + '</div></div>'; Toast.error(data.error); return; }

      var html = '';

      // ── AI Analysis ───────────────────────────────────────────────
      if (data.analysis) {
        html += '<div class="glass-card" style="margin-bottom:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:8px;color:var(--cyan);">AI Security Assessment</div>' +
          '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;white-space:pre-wrap;">' + escapeHtml(data.analysis) + '</div>' +
          '</div>';
      }

      // ── Geolocation + Network ─────────────────────────────────────
      html += '<div class="grid-2" style="margin-bottom:16px;">';

      html += '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:8px;">Geolocation</div>' +
        Views.osint.detailRow('IP Address', data.ip) +
        Views.osint.detailRow('Country', (data.country || '--') + (data.countryCode ? ' (' + data.countryCode + ')' : '')) +
        Views.osint.detailRow('Region', data.region) +
        Views.osint.detailRow('City', data.city) +
        Views.osint.detailRow('Timezone', data.timezone) +
        (data.lat && data.lon ? Views.osint.detailRow('Coordinates', data.lat + ', ' + data.lon) : '') +
        '</div>';

      html += '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:8px;">Network</div>' +
        Views.osint.detailRow('ISP', data.isp) +
        Views.osint.detailRow('Organization', data.org) +
        Views.osint.detailRow('ASN', data.asn) +
        Views.osint.detailRow('AS Name', data.asName) +
        Views.osint.detailRow('Reverse DNS', data.reverse_dns || data.hostname) +
        '</div>';

      html += '</div>';

      // ── Open Ports ────────────────────────────────────────────────
      var ports = data.openPorts || [];
      html += '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:8px;">Port Scan</div>';
      if (ports.length > 0) {
        html += '<div style="display:flex;flex-wrap:wrap;gap:8px;">';
        ports.forEach(function(p) {
          var portNum = p.port || p;
          var svcName = '';
          if (portNum === 22) svcName = 'SSH';
          else if (portNum === 80) svcName = 'HTTP';
          else if (portNum === 443) svcName = 'HTTPS';
          else if (portNum === 8080) svcName = 'HTTP-Alt';
          else if (portNum === 8443) svcName = 'HTTPS-Alt';
          else if (portNum === 3389) svcName = 'RDP';
          else if (portNum === 3306) svcName = 'MySQL';
          else if (portNum === 5432) svcName = 'PostgreSQL';
          else if (portNum === 6379) svcName = 'Redis';
          else if (portNum === 27017) svcName = 'MongoDB';
          html += '<div style="background:rgba(34,211,238,0.08);border:1px solid rgba(34,211,238,0.2);border-radius:6px;padding:8px 12px;text-align:center;">' +
            '<div style="color:var(--cyan);font-weight:600;font-size:var(--font-size-lg);">' + portNum + '</div>' +
            (svcName ? '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + svcName + '</div>' : '') +
            '</div>';
        });
        html += '</div>';
      } else {
        html += '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">No open ports detected on common ports (22, 80, 443, 8080, 8443, 3389, 3306, 5432, 6379, 27017)</div>';
      }
      html += '</div>';

      results.innerHTML = html;
      Toast.success('IP investigation complete');
      Views.osint.loadHistory();
    })
    .catch(function() {
      btn.disabled = false;
      btn.textContent = 'Investigate';
      results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Investigation Failed</div><div class="empty-state-desc">Check server connection and try again</div></div>';
      Toast.error('IP lookup failed');
    });
  },

  // ── History ─────────────────────────────────────────────────────────
  loadHistory: function() {
    var container = document.getElementById('osint-history-list');
    fetch('/api/osint/history', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var history = data.history || data || [];
        if (!Array.isArray(history) || history.length === 0) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128339;</div><div class="empty-state-title">No History</div><div class="empty-state-desc">Investigations will appear here</div></div>';
          return;
        }
        var html = '<table class="data-table"><thead><tr><th>Type</th><th>Target</th><th>Summary</th><th>Time</th></tr></thead><tbody>';
        history.slice(0, 30).forEach(function(h) {
          html += '<tr>' +
            '<td><span class="tag tag-cyan">' + escapeHtml(h.type || '--') + '</span></td>' +
            '<td style="color:var(--text-primary);font-weight:500;">' + escapeHtml(h.target || h.query || '--') + '</td>' +
            '<td style="color:var(--text-tertiary);font-size:var(--font-size-xs);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + escapeHtml(h.summary || '--') + '</td>' +
            '<td>' + timeAgo(h.created_at || h.timestamp) + '</td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      })
      .catch(function() {});
  },

  // ── Helper: detail row ──────────────────────────────────────────────
  detailRow: function(label, value) {
    return '<div class="detail-row">' +
      '<div class="detail-label">' + escapeHtml(label) + '</div>' +
      '<div class="detail-value">' + escapeHtml(value || '--') + '</div>' +
      '</div>';
  }
};
