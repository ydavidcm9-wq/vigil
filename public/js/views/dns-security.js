/* Vigil v1.0 — DNS Security View */
Views['dns-security'] = {
  init: function() {
    var el = document.getElementById('view-dns-security');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">DNS Security</div>' +
      '</div>' +

      '<div class="glass-card" style="margin-bottom:20px;">' +
        '<div class="form-inline">' +
          '<div class="form-group" style="flex:1;">' +
            '<label class="form-label">Domain</label>' +
            '<input type="text" class="form-input" id="dns-domain-input" placeholder="example.com">' +
          '</div>' +
          '<div class="form-group" style="align-self:flex-end;">' +
            '<button class="btn btn-primary" id="dns-lookup-btn">Lookup</button>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div id="dns-results-container" style="display:none;">' +
        '<div class="stat-grid" style="margin-bottom:20px;">' +
          '<div class="stat-card">' +
            '<div class="stat-card-label">Security Score</div>' +
            '<div class="stat-card-value" id="dns-score">--</div>' +
          '</div>' +
          '<div class="stat-card">' +
            '<div class="stat-card-label">DNSSEC</div>' +
            '<div class="stat-card-value" id="dns-dnssec" style="font-size:var(--font-size-lg);">--</div>' +
            '<div class="stat-card-trend" id="dns-dnssec-detail" style="font-size:var(--font-size-xs);margin-top:4px;"></div>' +
          '</div>' +
          '<div class="stat-card">' +
            '<div class="stat-card-label">Records Found</div>' +
            '<div class="stat-card-value" id="dns-record-count">0</div>' +
          '</div>' +
          '<div class="stat-card">' +
            '<div class="stat-card-label">CAA Records</div>' +
            '<div class="stat-card-value" id="dns-caa-count">0</div>' +
          '</div>' +
        '</div>' +

        // Strengths / Issues summary bar
        '<div class="grid-2" style="margin-bottom:20px;" id="dns-summary-bar">' +
          '<div class="glass-card" id="dns-strengths-card" style="display:none;">' +
            '<div style="color:var(--cyan);font-weight:600;font-size:var(--font-size-xs);text-transform:uppercase;margin-bottom:8px;">Strengths</div>' +
            '<div id="dns-strengths-list"></div>' +
          '</div>' +
          '<div class="glass-card" id="dns-issues-card" style="display:none;">' +
            '<div style="color:var(--orange);font-weight:600;font-size:var(--font-size-xs);text-transform:uppercase;margin-bottom:8px;">Issues</div>' +
            '<div id="dns-issues-list"></div>' +
          '</div>' +
        '</div>' +

        '<div class="glass-card" style="margin-bottom:20px;">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">DNS Records</div>' +
          '<div class="tab-bar" id="dns-tab-bar">' +
            '<div class="tab-item active" data-tab="dns-a">A / AAAA</div>' +
            '<div class="tab-item" data-tab="dns-mx">MX</div>' +
            '<div class="tab-item" data-tab="dns-ns">NS</div>' +
            '<div class="tab-item" data-tab="dns-txt">TXT</div>' +
            '<div class="tab-item" data-tab="dns-caa">CAA</div>' +
            '<div class="tab-item" data-tab="dns-cname">CNAME</div>' +
            '<div class="tab-item" data-tab="dns-soa">SOA</div>' +
          '</div>' +
          '<div class="tab-content active" id="dns-a"></div>' +
          '<div class="tab-content" id="dns-mx"></div>' +
          '<div class="tab-content" id="dns-ns"></div>' +
          '<div class="tab-content" id="dns-txt"></div>' +
          '<div class="tab-content" id="dns-caa"></div>' +
          '<div class="tab-content" id="dns-cname"></div>' +
          '<div class="tab-content" id="dns-soa"></div>' +
        '</div>' +

        '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">AI Security Assessment</div>' +
          '<div id="dns-assessment">' +
            '<div class="empty-state"><div class="empty-state-icon">&#128421;</div><div class="empty-state-title">No Assessment</div></div>' +
          '</div>' +
        '</div>' +
      '</div>';

    var self = this;
    document.getElementById('dns-lookup-btn').addEventListener('click', function() { self.lookup(); });
    document.getElementById('dns-domain-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') self.lookup();
    });

    // Tab handling
    document.querySelectorAll('#dns-tab-bar .tab-item').forEach(function(tab) {
      tab.addEventListener('click', function() {
        document.querySelectorAll('#dns-tab-bar .tab-item').forEach(function(t) { t.classList.remove('active'); });
        tab.classList.add('active');
        var tabId = tab.getAttribute('data-tab');
        document.querySelectorAll('#dns-results-container .tab-content').forEach(function(c) { c.classList.remove('active'); });
        document.getElementById(tabId).classList.add('active');
      });
    });
  },

  show: function() {},
  hide: function() {},

  lookup: function() {
    var domain = document.getElementById('dns-domain-input').value.trim();
    if (!domain) { Toast.warning('Enter a domain name'); return; }

    var btn = document.getElementById('dns-lookup-btn');
    btn.disabled = true;
    btn.textContent = 'Analyzing...';

    fetch('/api/dns/lookup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ domain: domain })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      btn.disabled = false;
      btn.textContent = 'Lookup';

      if (data.error) { Toast.error(data.error); return; }

      document.getElementById('dns-results-container').style.display = 'block';

      var records = data.records || {};
      var totalRecords = 0;

      // A / AAAA
      var aRecords = (records.A || []).concat(records.AAAA || []);
      totalRecords += aRecords.length;
      document.getElementById('dns-a').innerHTML = aRecords.length > 0 ?
        Views['dns-security'].renderRecordTable(['Type', 'Value', 'TTL'], aRecords.map(function(r) {
          return [r.type || 'A', r.value || r.address || r, r.ttl || '--'];
        })) : '<div style="color:var(--text-tertiary);padding:8px;">No A/AAAA records found</div>';

      // MX
      var mxRecords = records.MX || [];
      totalRecords += mxRecords.length;
      document.getElementById('dns-mx').innerHTML = mxRecords.length > 0 ?
        Views['dns-security'].renderRecordTable(['Priority', 'Exchange', 'TTL'], mxRecords.map(function(r) {
          return [r.priority || '--', r.exchange || r.value || r, r.ttl || '--'];
        })) : '<div style="color:var(--text-tertiary);padding:8px;">No MX records found</div>';

      // NS
      var nsRecords = records.NS || [];
      totalRecords += nsRecords.length;
      document.getElementById('dns-ns').innerHTML = nsRecords.length > 0 ?
        Views['dns-security'].renderRecordTable(['Nameserver', 'TTL'], nsRecords.map(function(r) {
          return [r.value || r, r.ttl || '--'];
        })) : '<div style="color:var(--text-tertiary);padding:8px;">No NS records found</div>';

      // TXT
      var txtRecords = records.TXT || [];
      totalRecords += txtRecords.length;
      document.getElementById('dns-txt').innerHTML = txtRecords.length > 0 ?
        '<div>' + txtRecords.map(function(r) {
          var val = r.value || (Array.isArray(r) ? r.join('') : String(r));
          var highlight = '';
          if (val.indexOf('v=spf1') === 0) highlight = ' style="margin-bottom:8px;word-break:break-all;border-left:3px solid var(--cyan);padding-left:8px;"';
          else if (val.indexOf('v=DMARC1') === 0) highlight = ' style="margin-bottom:8px;word-break:break-all;border-left:3px solid var(--cyan);padding-left:8px;"';
          else if (val.indexOf('v=DKIM1') === 0) highlight = ' style="margin-bottom:8px;word-break:break-all;border-left:3px solid var(--cyan);padding-left:8px;"';
          else highlight = ' style="margin-bottom:8px;word-break:break-all;"';
          return '<div class="code-block"' + highlight + '>' + escapeHtml(val) + '</div>';
        }).join('') + '</div>' :
        '<div style="color:var(--text-tertiary);padding:8px;">No TXT records found</div>';

      // CAA
      var caaRecords = data.caa || records.CAA || [];
      totalRecords += caaRecords.length;
      document.getElementById('dns-caa-count').textContent = caaRecords.length;
      document.getElementById('dns-caa').innerHTML = caaRecords.length > 0 ?
        Views['dns-security'].renderRecordTable(['Tag', 'Value', 'Critical'], caaRecords.map(function(r) {
          return [r.tag || '--', r.value || '--', r.critical ? 'Yes' : 'No'];
        })) : '<div style="color:var(--text-tertiary);padding:8px;">No CAA records — any Certificate Authority can issue certs for this domain</div>';

      // CNAME
      var cnameRecords = records.CNAME || [];
      totalRecords += cnameRecords.length;
      document.getElementById('dns-cname').innerHTML = cnameRecords.length > 0 ?
        Views['dns-security'].renderRecordTable(['Alias', 'Target', 'TTL'], cnameRecords.map(function(r) {
          return [r.name || domain, r.value || r, r.ttl || '--'];
        })) : '<div style="color:var(--text-tertiary);padding:8px;">No CNAME records found</div>';

      // SOA
      var soaRecords = records.SOA || [];
      document.getElementById('dns-soa').innerHTML = soaRecords.length > 0 ?
        Views['dns-security'].renderRecordTable(['Primary NS', 'Admin', 'Serial'], soaRecords.map(function(r) {
          return [r.nsname || r.primary || '--', r.hostmaster || r.admin || '--', r.serial || '--'];
        })) : '<div style="color:var(--text-tertiary);padding:8px;">No SOA records found</div>';

      document.getElementById('dns-record-count').textContent = totalRecords;

      // DNSSEC
      var dnssec = data.dnssec;
      var dnssecEl = document.getElementById('dns-dnssec');
      var dnssecDetail = document.getElementById('dns-dnssec-detail');
      if (dnssec === true || dnssec === 'valid') {
        dnssecEl.textContent = 'Enabled';
        dnssecEl.style.color = 'var(--cyan)';
      } else if (dnssec === 'unknown') {
        dnssecEl.textContent = 'Unknown';
        dnssecEl.style.color = 'var(--text-tertiary)';
      } else if (dnssec === false || dnssec === 'not_configured') {
        dnssecEl.textContent = 'Not Configured';
        dnssecEl.style.color = 'var(--orange)';
      } else {
        dnssecEl.textContent = String(dnssec || 'Unknown');
        dnssecEl.style.color = 'var(--text-tertiary)';
      }
      if (data.dnssecDetail) {
        dnssecDetail.textContent = data.dnssecDetail;
        dnssecDetail.style.color = 'var(--text-tertiary)';
      }

      // Score
      var scoreEl = document.getElementById('dns-score');
      var score = data.security_score || data.score;
      if (score !== undefined) {
        if (typeof animateValue === 'function') {
          animateValue(scoreEl, 0, score, 600);
        } else {
          scoreEl.textContent = score;
        }
        scoreEl.style.color = score >= 80 ? 'var(--cyan)' : score >= 50 ? 'var(--purple)' : 'var(--orange)';
      }

      // Strengths / Issues summary
      var strengths = data.strengths || [];
      var issues = data.issues || [];
      var strengthsCard = document.getElementById('dns-strengths-card');
      var issuesCard = document.getElementById('dns-issues-card');

      if (strengths.length > 0) {
        strengthsCard.style.display = 'block';
        document.getElementById('dns-strengths-list').innerHTML = strengths.map(function(s) {
          return '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);margin-bottom:4px;padding-left:12px;position:relative;">' +
            '<span style="position:absolute;left:0;color:var(--cyan);">+</span>' + escapeHtml(s) + '</div>';
        }).join('');
      } else { strengthsCard.style.display = 'none'; }

      if (issues.length > 0) {
        issuesCard.style.display = 'block';
        document.getElementById('dns-issues-list').innerHTML = issues.map(function(i) {
          return '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);margin-bottom:4px;padding-left:12px;position:relative;">' +
            '<span style="position:absolute;left:0;color:var(--orange);">-</span>' + escapeHtml(i) + '</div>';
        }).join('');
      } else { issuesCard.style.display = 'none'; }

      // Assessment
      var assessment = data.assessment || '';
      var assessEl = document.getElementById('dns-assessment');
      if (assessment) {
        assessEl.innerHTML = '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;white-space:pre-wrap;">' + escapeHtml(assessment) + '</div>';
      } else {
        assessEl.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">Configure an AI provider in Settings for detailed security assessment.</div>';
      }

      Toast.success('DNS analysis complete — score: ' + score + '/100');
    })
    .catch(function() {
      btn.disabled = false;
      btn.textContent = 'Lookup';
      Toast.error('DNS lookup failed');
    });
  },

  renderRecordTable: function(headers, rows) {
    var html = '<table class="data-table"><thead><tr>';
    headers.forEach(function(h) { html += '<th>' + escapeHtml(h) + '</th>'; });
    html += '</tr></thead><tbody>';
    rows.forEach(function(row) {
      html += '<tr>';
      row.forEach(function(cell, i) {
        var style = i === 0 ? ' style="color:var(--text-primary);"' : '';
        html += '<td' + style + '>' + escapeHtml(String(cell)) + '</td>';
      });
      html += '</tr>';
    });
    html += '</tbody></table>';
    return html;
  }
};
