/* Vigil v1.0 — Network Overview View */
Views.network = {
  init: function() {
    var el = document.getElementById('view-network');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Network Overview</div>' +
        '<div style="display:flex;gap:8px;">' +
          '<button class="btn btn-primary btn-sm" id="network-quick-scan">Quick Scan</button>' +
          '<button class="btn btn-ghost btn-sm" id="network-refresh">Refresh</button>' +
        '</div>' +
      '</div>' +

      '<div class="grid-2" style="margin-bottom:20px;">' +
        '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Network Interfaces</div>' +
          '<div id="network-interfaces">' +
            '<div class="loading-state"><div class="spinner"></div><div>Loading...</div></div>' +
          '</div>' +
        '</div>' +

        '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Listening Ports</div>' +
          '<div id="network-ports">' +
            '<div class="loading-state"><div class="spinner"></div><div>Loading...</div></div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Firewall Rules</div>' +
        '<div id="network-firewall">' +
          '<div class="loading-state"><div class="spinner"></div><div>Loading...</div></div>' +
        '</div>' +
      '</div>';

    var self = this;
    document.getElementById('network-refresh').addEventListener('click', function() { self.show(); });
    document.getElementById('network-quick-scan').addEventListener('click', function() {
      showView('port-scanner');
    });
  },

  show: function() {
    this.loadInterfaces();
    this.loadPorts();
    this.loadFirewall();
  },

  hide: function() {},

  loadInterfaces: function() {
    var container = document.getElementById('network-interfaces');
    fetch('/api/network/interfaces', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var ifaces = data.interfaces || data || [];
        if (!Array.isArray(ifaces) || ifaces.length === 0) {
          container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">No interfaces found</div>';
          return;
        }

        var html = '<table class="data-table"><thead><tr><th>Interface</th><th>IP Address</th><th>MAC</th><th>Status</th></tr></thead><tbody>';
        ifaces.forEach(function(i) {
          var statusColor = i.status === 'up' ? 'var(--cyan)' : 'var(--text-tertiary)';
          html += '<tr>' +
            '<td style="color:var(--text-primary);font-weight:500;">' + escapeHtml(i.name || i.iface || '--') + '</td>' +
            '<td>' + escapeHtml(i.ip || i.address || '--') + '</td>' +
            '<td>' + escapeHtml(i.mac || '--') + '</td>' +
            '<td><span style="color:' + statusColor + ';">' + escapeHtml(i.status || 'unknown') + '</span></td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      })
      .catch(function() {
        container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">Could not load interfaces</div>';
      });
  },

  loadPorts: function() {
    var container = document.getElementById('network-ports');
    fetch('/api/network/connections', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var conns = data.connections || [];
        // Filter to LISTENING only and deduplicate
        var listening = conns.filter(function(c) { return (c.state || '').toUpperCase() === 'LISTENING'; });
        if (listening.length === 0) {
          container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">No listening ports detected</div>';
          return;
        }

        var html = '<table class="data-table"><thead><tr><th>Local Address</th><th>Protocol</th><th>State</th><th>Process</th></tr></thead><tbody>';
        listening.forEach(function(c) {
          html += '<tr>' +
            '<td style="color:var(--text-primary);font-weight:500;">' + escapeHtml(c.local || '') + '</td>' +
            '<td>' + escapeHtml(c.proto || 'tcp') + '</td>' +
            '<td><span style="color:var(--cyan);">' + escapeHtml(c.state || '') + '</span></td>' +
            '<td>' + escapeHtml(c.process || '--') + '</td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      })
      .catch(function() {
        container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">Could not load ports</div>';
      });
  },

  loadFirewall: function() {
    var container = document.getElementById('network-firewall');
    fetch('/api/network/firewall', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var rules = data.rules || data || [];
        if (!Array.isArray(rules) || rules.length === 0) {
          container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">No firewall rules detected or firewall not configured</div>';
          return;
        }

        var html = '<table class="data-table"><thead><tr><th>Chain</th><th>Action</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Port</th></tr></thead><tbody>';
        rules.forEach(function(r) {
          var actionColor = r.action === 'ACCEPT' || r.action === 'allow' ? 'var(--cyan)' : 'var(--orange)';
          html += '<tr>' +
            '<td>' + escapeHtml(r.chain || '--') + '</td>' +
            '<td><span style="color:' + actionColor + ';font-weight:600;">' + escapeHtml(r.action || '--') + '</span></td>' +
            '<td>' + escapeHtml(r.protocol || 'any') + '</td>' +
            '<td>' + escapeHtml(r.source || 'any') + '</td>' +
            '<td>' + escapeHtml(r.destination || 'any') + '</td>' +
            '<td>' + escapeHtml(String(r.port || 'any')) + '</td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      })
      .catch(function() {
        container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">Could not load firewall rules</div>';
      });
  }
};
