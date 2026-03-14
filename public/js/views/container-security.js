/* Vigil v1.1 — Container Security View */
Views['container-security'] = {
  init: function() {
    var el = document.getElementById('view-container-security');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Container Security</div>' +
        '<div style="display:flex;gap:8px;">' +
          '<button class="btn btn-primary btn-sm" id="container-add-btn">Add Image</button>' +
          '<button class="btn btn-ghost btn-sm" id="container-refresh">Refresh</button>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card" style="margin-bottom:20px;">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Container Images</div>' +
        '<div id="container-images">' +
          '<div class="loading-state"><div class="spinner"></div><div>Loading images...</div></div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card" id="container-scan-card" style="display:none;margin-bottom:20px;">' +
        '<div style="display:flex;align-items:center;gap:12px;">' +
          '<div class="spinner"></div>' +
          '<div style="color:var(--text-primary);" id="container-scan-status">Scanning image...</div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card">' +
        '<div class="glass-card-header">' +
          '<div class="glass-card-title">Scan Results</div>' +
          '<div style="display:flex;gap:8px;">' +
            '<select class="form-select" id="container-sev-filter" style="width:auto;min-width:100px;">' +
              '<option value="all">All Severities</option>' +
              '<option value="critical">Critical</option>' +
              '<option value="high">High</option>' +
              '<option value="medium">Medium</option>' +
              '<option value="low">Low</option>' +
            '</select>' +
          '</div>' +
        '</div>' +
        '<div id="container-results">' +
          '<div class="empty-state"><div class="empty-state-icon">&#128230;</div><div class="empty-state-title">No Scan Results</div><div class="empty-state-desc">Add a container image and click Scan to analyze it for vulnerabilities</div></div>' +
        '</div>' +
      '</div>';

    var self = this;
    document.getElementById('container-add-btn').addEventListener('click', function() { self.showAddModal(); });
    document.getElementById('container-refresh').addEventListener('click', function() { self.loadImages(); });
    document.getElementById('container-sev-filter').addEventListener('change', function() { self.filterResults(); });
  },

  show: function() {
    this.loadImages();
  },

  hide: function() {},

  _lastScanData: null,
  _lastScanImage: null,

  showAddModal: function() {
    Modal.open({
      title: 'Add Container Image',
      body:
        '<div class="form-group">' +
          '<label class="form-label">Image Name</label>' +
          '<input type="text" class="form-input" id="container-image-name" placeholder="e.g., nginx:latest, node:22-alpine, python:3.12">' +
          '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-top:6px;">Enter any Docker Hub or registry image name with tag</div>' +
        '</div>' +
        '<div style="margin-top:12px;">' +
          '<div class="form-label">Popular Images</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:6px;">' +
            '<button class="btn btn-ghost btn-sm container-quick-img" data-img="nginx:latest">nginx</button>' +
            '<button class="btn btn-ghost btn-sm container-quick-img" data-img="node:22-alpine">node:22</button>' +
            '<button class="btn btn-ghost btn-sm container-quick-img" data-img="python:3.12-slim">python:3.12</button>' +
            '<button class="btn btn-ghost btn-sm container-quick-img" data-img="postgres:17">postgres:17</button>' +
            '<button class="btn btn-ghost btn-sm container-quick-img" data-img="redis:7-alpine">redis:7</button>' +
            '<button class="btn btn-ghost btn-sm container-quick-img" data-img="ubuntu:24.04">ubuntu:24.04</button>' +
            '<button class="btn btn-ghost btn-sm container-quick-img" data-img="alpine:3.20">alpine:3.20</button>' +
            '<button class="btn btn-ghost btn-sm container-quick-img" data-img="mongo:7">mongo:7</button>' +
          '</div>' +
        '</div>',
      footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="container-add-confirm">Add Image</button>'
    });

    document.querySelectorAll('.container-quick-img').forEach(function(btn) {
      btn.addEventListener('click', function() {
        document.getElementById('container-image-name').value = btn.getAttribute('data-img');
      });
    });

    document.getElementById('container-add-confirm').addEventListener('click', function() {
      var name = document.getElementById('container-image-name').value.trim();
      if (!name) { Toast.warning('Enter an image name'); return; }
      Modal.loading('Adding image...');

      fetch('/api/docker/images', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ image: name })
      })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        Modal.close();
        if (data.error) { Toast.error(data.error); return; }
        Toast.success('Image added: ' + name);
        Views['container-security'].loadImages();
      })
      .catch(function() { Modal.close(); Toast.error('Failed to add image'); });
    });
  },

  loadImages: function() {
    var container = document.getElementById('container-images');
    fetch('/api/docker/images', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var images = data.images || [];
        if (!Array.isArray(images) || images.length === 0) {
          container.innerHTML =
            '<div class="empty-state">' +
              '<div class="empty-state-icon">&#128230;</div>' +
              '<div class="empty-state-title">No Container Images</div>' +
              '<div class="empty-state-desc">Click "Add Image" to add a Docker image for security scanning</div>' +
            '</div>';
          return;
        }

        var html = '<table class="data-table"><thead><tr><th>Image</th><th>Tag</th><th>Source</th><th>Last Scan</th><th>Findings</th><th>Actions</th></tr></thead><tbody>';
        images.forEach(function(img) {
          var name = img.name || img.repository || '--';
          var tag = img.tag || 'latest';
          var source = img.source || 'manual';
          var lastScan = img.lastScanAt ? timeAgo(img.lastScanAt) : 'Never';
          var findings = img.findingsCount != null ? img.findingsCount : '--';
          var findingsColor = img.findingsCount > 0 ? 'var(--orange)' : 'var(--cyan)';
          var fullImage = name + ':' + tag;

          html += '<tr>' +
            '<td style="color:var(--text-primary);font-weight:500;">' + escapeHtml(name) + '</td>' +
            '<td><span class="tag">' + escapeHtml(tag) + '</span></td>' +
            '<td style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + escapeHtml(source) + '</td>' +
            '<td>' + lastScan + '</td>' +
            '<td style="color:' + findingsColor + ';font-weight:600;">' + findings + '</td>' +
            '<td style="display:flex;gap:6px;">' +
              '<button class="btn btn-primary btn-sm container-scan-btn" data-image="' + escapeHtml(fullImage) + '">Scan</button>' +
              (source === 'manual' ? '<button class="btn btn-ghost btn-sm container-remove-btn" data-image="' + escapeHtml(fullImage) + '" style="color:var(--orange);">Remove</button>' : '') +
            '</td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;

        container.querySelectorAll('.container-scan-btn').forEach(function(btn) {
          btn.addEventListener('click', function() {
            Views['container-security'].scanImage(btn.getAttribute('data-image'));
          });
        });

        container.querySelectorAll('.container-remove-btn').forEach(function(btn) {
          btn.addEventListener('click', function() {
            Views['container-security'].removeImage(btn.getAttribute('data-image'));
          });
        });
      })
      .catch(function() {
        container.innerHTML =
          '<div class="empty-state">' +
            '<div class="empty-state-icon">&#128230;</div>' +
            '<div class="empty-state-title">No Container Images</div>' +
            '<div class="empty-state-desc">Click "Add Image" to add a Docker image for security scanning</div>' +
          '</div>';
      });
  },

  removeImage: function(image) {
    Modal.confirm({
      title: 'Remove Image',
      message: 'Remove ' + image + ' from the watchlist?',
      confirmText: 'Remove',
      dangerous: true
    }).then(function(confirmed) {
      if (!confirmed) return;
      fetch('/api/docker/images/' + encodeURIComponent(image), {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin'
      })
      .then(function() { Toast.success('Image removed'); Views['container-security'].loadImages(); })
      .catch(function() { Toast.error('Remove failed'); });
    });
  },

  scanImage: function(image) {
    var scanCard = document.getElementById('container-scan-card');
    var statusEl = document.getElementById('container-scan-status');
    var results = document.getElementById('container-results');

    scanCard.style.display = 'block';
    statusEl.textContent = 'Scanning ' + image + ' for vulnerabilities...';
    this._lastScanImage = image;

    fetch('/api/scan/container', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ image: image })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      scanCard.style.display = 'none';

      if (data.error && (!data.vulnerabilities || data.vulnerabilities.length === 0)) {
        results.innerHTML =
          '<div class="empty-state">' +
            '<div class="empty-state-icon">&#10007;</div>' +
            '<div class="empty-state-title">Scan Error</div>' +
            '<div class="empty-state-desc">' + escapeHtml(data.error) + '</div>' +
            (data.note ? '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-top:8px;">' + escapeHtml(data.note) + '</div>' : '') +
          '</div>';
        return;
      }

      var vulns = data.vulnerabilities || data.results || [];
      if (!Array.isArray(vulns)) vulns = [];
      Views['container-security']._lastScanData = vulns;

      // Show scanner info banner
      var scannerNote = data.scanner === 'trivy' ? 'Scanned with Trivy' :
                       data.scanner === 'native' ? 'Scanned with built-in analysis (install Trivy for deeper scanning)' : '';
      var bannerHtml = '';
      if (scannerNote || data.analysis) {
        bannerHtml += '<div style="padding:12px;margin-bottom:16px;border-radius:8px;background:rgba(34,211,238,0.05);border:1px solid rgba(34,211,238,0.15);">';
        if (scannerNote) bannerHtml += '<div style="color:var(--cyan);font-size:var(--font-size-xs);margin-bottom:' + (data.analysis ? '8' : '0') + 'px;">' + escapeHtml(scannerNote) + ' — ' + vulns.length + ' findings for ' + escapeHtml(image) + '</div>';
        if (data.analysis) {
          bannerHtml += '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.6;white-space:pre-wrap;">' + escapeHtml(data.analysis) + '</div>';
        }
        bannerHtml += '</div>';
      }

      Views['container-security'].renderResults(vulns, bannerHtml);
      Toast.success('Scan complete: ' + vulns.length + ' findings');
      Views['container-security'].loadImages();
    })
    .catch(function() {
      scanCard.style.display = 'none';
      results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Scan Failed</div><div class="empty-state-desc">Could not complete the container scan. Check server logs.</div></div>';
      Toast.error('Container scan failed');
    });
  },

  renderResults: function(vulns, prefixHtml) {
    var results = document.getElementById('container-results');
    var html = prefixHtml || '';

    if (!vulns || vulns.length === 0) {
      html += '<div class="empty-state"><div class="empty-state-icon">&#10003;</div><div class="empty-state-title">No Vulnerabilities Found</div><div class="empty-state-desc">Image appears clean</div></div>';
      results.innerHTML = html;
      return;
    }

    html += '<table class="data-table"><thead><tr><th>Severity</th><th>CVE / Issue</th><th>Package</th><th>Installed</th><th>Fix Version</th></tr></thead><tbody>';
    vulns.forEach(function(v) {
      html += '<tr>' +
        '<td><span class="' + severityClass(v.severity) + '">' + escapeHtml(v.severity || 'unknown') + '</span></td>' +
        '<td style="color:var(--text-primary);">' + escapeHtml(v.cve_id || v.vulnerability_id || v.title || '--') + '</td>' +
        '<td>' + escapeHtml(v.pkg_name || v.package || '--') + '</td>' +
        '<td>' + escapeHtml(v.installed_version || '--') + '</td>' +
        '<td>' + escapeHtml(v.fixed_version || 'N/A') + '</td>' +
        '</tr>';
    });
    html += '</tbody></table>';
    results.innerHTML = html;
  },

  filterResults: function() {
    var sev = document.getElementById('container-sev-filter').value;
    var data = this._lastScanData || [];
    if (sev === 'all') {
      this.renderResults(data);
    } else {
      var filtered = data.filter(function(v) {
        return (v.severity || '').toLowerCase() === sev;
      });
      this.renderResults(filtered);
    }
  }
};
