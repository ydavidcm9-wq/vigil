/* Vigil v1.0 — Incident Response Playbooks View */
Views.playbooks = {
  init: function() {
    var el = document.getElementById('view-playbooks');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Incident Response Playbooks</div>' +
        '<button class="btn btn-primary btn-sm" id="playbook-create-btn">Create from Natural Language</button>' +
      '</div>' +

      '<div class="glass-card" style="margin-bottom:20px;">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Playbook Templates</div>' +
        '<div id="playbook-list" class="grid-2">' +
          '<div class="loading-state"><div class="spinner"></div><div>Loading playbooks...</div></div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card" id="playbook-detail-card" style="display:none;">' +
        '<div class="glass-card-header">' +
          '<div class="glass-card-title" id="playbook-detail-title">--</div>' +
          '<button class="btn btn-ghost btn-sm" id="playbook-detail-close">Close</button>' +
        '</div>' +
        '<div id="playbook-steps"></div>' +
      '</div>';

    var self = this;
    document.getElementById('playbook-create-btn').addEventListener('click', function() { self.showCreateModal(); });
    document.getElementById('playbook-detail-close').addEventListener('click', function() {
      document.getElementById('playbook-detail-card').style.display = 'none';
    });
  },

  show: function() {
    this.loadPlaybooks();
  },

  hide: function() {},

  _defaultPlaybooks: [
    { id: 'ddos', name: 'DDoS Response', description: 'Respond to distributed denial-of-service attacks', severity: 'critical', steps: ['Identify attack vector and affected services', 'Enable DDoS mitigation (Cloudflare/WAF)', 'Rate-limit incoming traffic', 'Monitor bandwidth and service availability', 'Analyze attack patterns for IOCs', 'Document timeline and impact', 'Post-incident review and hardening'] },
    { id: 'ransomware', name: 'Ransomware Response', description: 'Respond to ransomware infection', severity: 'critical', steps: ['Isolate affected systems from network', 'Identify ransomware variant', 'Preserve evidence (memory + disk)', 'Activate backup restoration plan', 'Scan all systems for lateral spread', 'Report to law enforcement if required', 'Restore from clean backups', 'Harden entry points'] },
    { id: 'data-breach', name: 'Data Breach Response', description: 'Respond to confirmed data breach', severity: 'high', steps: ['Confirm scope of breach', 'Contain data exfiltration', 'Preserve forensic evidence', 'Identify compromised data types', 'Notify legal and compliance team', 'Prepare breach notification', 'Reset affected credentials', 'Implement additional monitoring'] },
    { id: 'account-compromise', name: 'Account Compromise', description: 'Respond to compromised user account', severity: 'high', steps: ['Disable compromised account', 'Review account activity logs', 'Identify unauthorized access/changes', 'Reset password and revoke sessions', 'Check for persistence mechanisms', 'Enable MFA if not already active', 'Notify account owner', 'Review access policies'] }
  ],

  loadPlaybooks: function() {
    var container = document.getElementById('playbook-list');
    var self = this;

    fetch('/api/playbooks', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var playbooks = data.playbooks || data || [];
        if (!Array.isArray(playbooks) || playbooks.length === 0) playbooks = self._defaultPlaybooks;
        self.renderPlaybooks(playbooks);
      })
      .catch(function() {
        self.renderPlaybooks(self._defaultPlaybooks);
      });
  },

  renderPlaybooks: function(playbooks) {
    var container = document.getElementById('playbook-list');
    var html = '';
    playbooks.forEach(function(p) {
      html += '<div class="glass-card playbook-card" data-id="' + escapeHtml(p.id || '') + '" style="cursor:pointer;">' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">' +
          '<span style="font-size:16px;">&#128214;</span>' +
          '<span style="color:var(--text-primary);font-weight:600;flex:1;">' + escapeHtml(p.name || 'Playbook') + '</span>' +
          '<span class="badge ' + severityBadge(p.severity) + '">' + escapeHtml(p.severity || 'info') + '</span>' +
        '</div>' +
        '<div style="color:var(--text-secondary);font-size:var(--font-size-xs);line-height:1.5;">' + escapeHtml(p.description || '') + '</div>' +
        '<div style="margin-top:8px;color:var(--text-tertiary);font-size:var(--font-size-xs);">' + (p.steps ? p.steps.length : 0) + ' steps</div>' +
      '</div>';
    });
    container.innerHTML = html;

    container.querySelectorAll('.playbook-card').forEach(function(card) {
      card.addEventListener('click', function() {
        var id = card.getAttribute('data-id');
        var playbook = playbooks.find(function(p) { return p.id == id; });
        if (playbook) Views.playbooks.showDetail(playbook);
      });
    });
  },

  showDetail: function(playbook) {
    var card = document.getElementById('playbook-detail-card');
    card.style.display = 'block';
    document.getElementById('playbook-detail-title').textContent = playbook.name || 'Playbook';

    var steps = playbook.steps || [];
    var html = '';
    steps.forEach(function(step, idx) {
      html += '<div class="checklist-item" id="playbook-step-' + idx + '">' +
        '<div class="checklist-check" onclick="this.classList.toggle(\'checked\');this.textContent=this.classList.contains(\'checked\')?\'\\u2713\':\'\';">' + '</div>' +
        '<div style="flex:1;">' +
          '<div class="checklist-text">' + escapeHtml(typeof step === 'string' ? step : step.title || step.description || '') + '</div>' +
        '</div>' +
        '<button class="btn btn-ghost btn-sm playbook-exec-step" data-step="' + idx + '">Execute</button>' +
      '</div>';
    });
    document.getElementById('playbook-steps').innerHTML = html;

    document.querySelectorAll('.playbook-exec-step').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var stepIdx = btn.getAttribute('data-step');
        btn.disabled = true;
        btn.textContent = 'Running...';
        fetch('/api/playbooks/' + (playbook.id || 'custom') + '/execute', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ step: parseInt(stepIdx) })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          btn.textContent = 'Done';
          var check = document.querySelector('#playbook-step-' + stepIdx + ' .checklist-check');
          if (check) { check.classList.add('checked'); check.textContent = '\u2713'; }
          Toast.success('Step executed');
        })
        .catch(function() {
          btn.disabled = false;
          btn.textContent = 'Execute';
          Toast.error('Step execution failed');
        });
      });
    });
  },

  showCreateModal: function() {
    Modal.open({
      title: 'Create Playbook from Natural Language',
      body:
        '<div class="form-group"><label class="form-label">Describe the incident scenario</label><textarea class="form-textarea" id="playbook-nl-input" rows="4" placeholder="e.g., \'Our web application is under a SQL injection attack and customer data may be exposed\'"></textarea></div>',
      footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="playbook-generate-btn">Generate Playbook</button>'
    });

    document.getElementById('playbook-generate-btn').addEventListener('click', function() {
      var description = document.getElementById('playbook-nl-input').value.trim();
      if (!description) { Toast.warning('Describe the scenario'); return; }

      Modal.loading('AI generating playbook...');
      fetch('/api/playbooks/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ description: description })
      })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        Modal.close();
        var playbook = data.playbook || data;
        if (playbook && playbook.steps) {
          Views.playbooks.showDetail(playbook);
          Toast.success('Playbook generated');
        } else {
          Toast.error('AI did not return a valid playbook');
        }
      })
      .catch(function() { Modal.close(); Toast.error('Playbook generation failed'); });
    });
  }
};
