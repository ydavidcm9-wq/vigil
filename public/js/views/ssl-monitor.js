/* Vigil v1.0 — SSL Monitor View */
Views['ssl-monitor'] = {
  init: function() {
    var el = document.getElementById('view-ssl-monitor');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">SSL/TLS Certificate Monitor</div>' +
        '<button class="btn btn-ghost btn-sm" id="ssl-refresh">Refresh All</button>' +
      '</div>' +

      '<div class="glass-card" style="margin-bottom:20px;">' +
        '<div class="form-inline">' +
          '<div class="form-group" style="flex:1;">' +
            '<label class="form-label">Add Domain</label>' +
            '<input type="text" class="form-input" id="ssl-domain-input" placeholder="example.com">' +
          '</div>' +
          '<div class="form-group" style="align-self:flex-end;">' +
            '<button class="btn btn-primary" id="ssl-add-btn">Add & Check</button>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Monitored Domains</div>' +
        '<div id="ssl-domains">' +
          '<div class="loading-state"><div class="spinner"></div><div>Loading...</div></div>' +
        '</div>' +
      '</div>';

    var self = this;
    document.getElementById('ssl-add-btn').addEventListener('click', function() { self.addDomain(); });
    document.getElementById('ssl-refresh').addEventListener('click', function() { self.loadDomains(); });
    document.getElementById('ssl-domain-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') self.addDomain();
    });
  },

  show: function() {
    this.loadDomains();
  },

  hide: function() {},

  addDomain: function() {
    var input = document.getElementById('ssl-domain-input');
    var domain = input.value.trim();
    if (!domain) { Toast.warning('Enter a domain name'); return; }

    var btn = document.getElementById('ssl-add-btn');
    btn.disabled = true;

    fetch('/api/ssl/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ domain: domain })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      btn.disabled = false;
      input.value = '';
      Toast.success('Domain added: ' + domain);
      Views['ssl-monitor'].loadDomains();
    })
    .catch(function() {
      btn.disabled = false;
      Toast.error('Failed to check domain');
    });
  },

  loadDomains: function() {
    var container = document.getElementById('ssl-domains');
    fetch('/api/ssl/monitors', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var domains = data.domains || data || [];
        if (!Array.isArray(domains) || domains.length === 0) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128274;</div><div class="empty-state-title">No Domains</div><div class="empty-state-desc">Add a domain to start monitoring SSL certificates</div></div>';
          return;
        }

        var html = '<table class="data-table"><thead><tr><th>Domain</th><th>Grade</th><th>Issuer</th><th>Expires</th><th>Days Left</th><th>Actions</th></tr></thead><tbody>';
        domains.forEach(function(d) {
          var daysLeft = d.days_until_expiry || d.daysLeft || 0;
          var daysColor = daysLeft < 15 ? 'var(--orange)' : daysLeft < 30 ? 'var(--purple)' : 'var(--cyan)';
          var grade = d.grade || '--';
          var gradeColor = grade === 'A' || grade === 'A+' ? 'var(--cyan)' :
                          grade === 'B' ? 'var(--purple)' : 'var(--orange)';

          html += '<tr>' +
            '<td style="color:var(--text-primary);font-weight:500;">' + escapeHtml(d.domain || d.name || '--') + '</td>' +
            '<td><span style="color:' + gradeColor + ';font-weight:700;">' + escapeHtml(grade) + '</span></td>' +
            '<td>' + escapeHtml(d.issuer || '--') + '</td>' +
            '<td>' + (d.expiry ? formatDate(d.expiry) : '--') + '</td>' +
            '<td><span style="color:' + daysColor + ';font-weight:600;">' + daysLeft + '</span></td>' +
            '<td>' +
              '<button class="btn btn-ghost btn-sm ssl-check-btn" data-domain="' + escapeHtml(d.domain || d.name) + '">Check</button> ' +
              '<button class="btn btn-ghost btn-sm ssl-ai-btn" data-domain="' + escapeHtml(d.domain || d.name) + '">AI Analysis</button>' +
            '</td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;

        container.querySelectorAll('.ssl-check-btn').forEach(function(btn) {
          btn.addEventListener('click', function() {
            var domain = btn.getAttribute('data-domain');
            btn.disabled = true;
            btn.textContent = '...';
            fetch('/api/ssl/check', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'same-origin',
              body: JSON.stringify({ domain: domain })
            }).then(function() {
              Toast.success('Certificate checked');
              Views['ssl-monitor'].loadDomains();
            }).catch(function() {
              btn.disabled = false;
              btn.textContent = 'Check';
              Toast.error('Check failed');
            });
          });
        });

        container.querySelectorAll('.ssl-ai-btn').forEach(function(btn) {
          btn.addEventListener('click', function() {
            var domain = btn.getAttribute('data-domain');
            Modal.loading('AI analyzing SSL configuration...');
            fetch('/api/ssl/' + encodeURIComponent(domain) + '/analyze', { credentials: 'same-origin' })
              .then(function(r) { return r.json(); })
              .then(function(data) {
                Modal.close();
                Modal.open({
                  title: 'SSL Analysis: ' + domain,
                  body: '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;">' + escapeHtml(data.analysis || data.summary || 'No analysis available').replace(/\n/g, '<br>') + '</div>',
                  size: 'lg'
                });
              })
              .catch(function() {
                Modal.close();
                Toast.error('AI analysis failed');
              });
          });
        });
      })
      .catch(function() {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128274;</div><div class="empty-state-title">No Domains</div><div class="empty-state-desc">Add a domain to start monitoring</div></div>';
      });
  }
};
