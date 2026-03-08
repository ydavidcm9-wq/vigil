/* Vigil v1.0 — Credential Vault View */
Views.credentials = {
  init: function() {
    var el = document.getElementById('view-credentials');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Credential Vault</div>' +
        '<button class="btn btn-primary btn-sm" id="cred-add-btn">Add Credential</button>' +
      '</div>' +

      '<div class="glass-card">' +
        '<div style="margin-bottom:12px;color:var(--text-tertiary);font-size:var(--font-size-xs);">Credentials are encrypted at rest using AES-256-GCM. Values are only decrypted on reveal.</div>' +
        '<div id="cred-table">' +
          '<div class="loading-state"><div class="spinner"></div><div>Loading credentials...</div></div>' +
        '</div>' +
      '</div>';

    document.getElementById('cred-add-btn').addEventListener('click', this.showAddModal.bind(this));
  },

  show: function() {
    this.loadCredentials();
  },

  hide: function() {},

  loadCredentials: function() {
    var container = document.getElementById('cred-table');
    fetch('/api/credentials', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var creds = data.credentials || data || [];
        if (!Array.isArray(creds) || creds.length === 0) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128273;</div><div class="empty-state-title">No Credentials</div><div class="empty-state-desc">Add credentials to the vault for secure storage</div></div>';
          return;
        }

        var html = '<table class="data-table"><thead><tr><th>Name</th><th>Type</th><th>Last Updated</th><th>Actions</th></tr></thead><tbody>';
        creds.forEach(function(c) {
          html += '<tr>' +
            '<td style="color:var(--text-primary);font-weight:500;">' + escapeHtml(c.name || '--') + '</td>' +
            '<td><span class="tag">' + escapeHtml(c.type || 'generic') + '</span></td>' +
            '<td>' + timeAgo(c.updated_at || c.created_at) + '</td>' +
            '<td>' +
              '<button class="btn btn-ghost btn-sm cred-reveal-btn" data-name="' + escapeHtml(c.name || '') + '">Reveal</button> ' +
              '<button class="btn btn-ghost btn-sm cred-delete-btn" data-name="' + escapeHtml(c.name || '') + '" style="color:var(--orange);">Delete</button>' +
            '</td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;

        container.querySelectorAll('.cred-reveal-btn').forEach(function(btn) {
          btn.addEventListener('click', function() {
            var name = btn.getAttribute('data-name');
            Views.credentials.revealCredential(name, btn);
          });
        });

        container.querySelectorAll('.cred-delete-btn').forEach(function(btn) {
          btn.addEventListener('click', function() {
            var name = btn.getAttribute('data-name');
            Views.credentials.deleteCredential(name);
          });
        });
      })
      .catch(function() {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128273;</div><div class="empty-state-title">Vault Unavailable</div></div>';
      });
  },

  revealCredential: function(name, btn) {
    fetch('/api/credentials/' + encodeURIComponent(name), { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var value = data.value || data.secret || '***';
        var td = btn.parentElement;
        var origHTML = td.innerHTML;

        td.innerHTML = '<div class="code-block" style="display:inline-block;max-width:300px;overflow:hidden;text-overflow:ellipsis;">' + escapeHtml(value) + '</div>';

        // Hide after 5 seconds
        setTimeout(function() {
          td.innerHTML = origHTML;
          // Re-attach listeners
          var newRevealBtn = td.querySelector('.cred-reveal-btn');
          var newDeleteBtn = td.querySelector('.cred-delete-btn');
          if (newRevealBtn) newRevealBtn.addEventListener('click', function() { Views.credentials.revealCredential(name, newRevealBtn); });
          if (newDeleteBtn) newDeleteBtn.addEventListener('click', function() { Views.credentials.deleteCredential(name); });
        }, 5000);
      })
      .catch(function() { Toast.error('Failed to reveal credential'); });
  },

  deleteCredential: function(name) {
    Modal.confirm({
      title: 'Delete Credential',
      message: 'Are you sure you want to delete "' + name + '"? This cannot be undone.',
      confirmText: 'Delete',
      dangerous: true
    }).then(function(confirmed) {
      if (!confirmed) return;
      fetch('/api/credentials/' + encodeURIComponent(name), {
        method: 'DELETE',
        credentials: 'same-origin'
      })
      .then(function() { Toast.success('Credential deleted'); Views.credentials.loadCredentials(); })
      .catch(function() { Toast.error('Delete failed'); });
    });
  },

  showAddModal: function() {
    Modal.open({
      title: 'Add Credential',
      body:
        '<div class="form-group"><label class="form-label">Name</label><input type="text" class="form-input" id="cred-new-name" placeholder="e.g., api_key_production"></div>' +
        '<div class="form-group"><label class="form-label">Type</label><select class="form-select" id="cred-new-type"><option value="api_token">API Token</option><option value="api_key">API Key</option><option value="password">Password</option><option value="token">Token</option><option value="ssh_key">SSH Key</option><option value="certificate">Certificate</option><option value="generic">Generic</option></select></div>' +
        '<div class="form-group"><label class="form-label">Value</label><textarea class="form-textarea" id="cred-new-value" rows="4" placeholder="Enter the secret value..." style="font-family:var(--font-mono);"></textarea></div>',
      footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="cred-save-btn">Save</button>'
    });

    document.getElementById('cred-save-btn').addEventListener('click', function() {
      var name = document.getElementById('cred-new-name').value.trim();
      var type = document.getElementById('cred-new-type').value;
      var value = document.getElementById('cred-new-value').value;
      if (!name || !value) { Toast.warning('Name and value are required'); return; }

      fetch('/api/credentials', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ name: name, type: type, value: value })
      })
      .then(function() { Modal.close(); Toast.success('Credential saved'); Views.credentials.loadCredentials(); })
      .catch(function() { Toast.error('Failed to save credential'); });
    });
  }
};
