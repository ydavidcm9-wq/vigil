/* Vigil v1.0 — Campaigns View */
Views.campaigns = {
  init: function() {
    var el = document.getElementById('view-campaigns');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Multi-Agent Campaigns</div>' +
        '<button class="btn btn-primary btn-sm" id="campaign-launch-btn">Launch Campaign</button>' +
      '</div>' +

      '<div class="glass-card" style="margin-bottom:20px;">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Active Campaigns</div>' +
        '<div id="campaigns-active">' +
          '<div class="loading-state"><div class="spinner"></div><div>Loading...</div></div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Past Campaigns</div>' +
        '<div id="campaigns-past">' +
          '<div class="empty-state"><div class="empty-state-icon">&#127919;</div><div class="empty-state-title">No Past Campaigns</div></div>' +
        '</div>' +
      '</div>';

    document.getElementById('campaign-launch-btn').addEventListener('click', this.showLaunchModal.bind(this));
  },

  show: function() {
    this.loadCampaigns();
  },

  hide: function() {},

  loadCampaigns: function() {
    var activeContainer = document.getElementById('campaigns-active');
    var pastContainer = document.getElementById('campaigns-past');

    fetch('/api/campaigns', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var campaigns = data.campaigns || data || [];
        if (!Array.isArray(campaigns)) campaigns = [];

        var active = campaigns.filter(function(c) { return c.status === 'running' || c.status === 'active'; });
        var past = campaigns.filter(function(c) { return c.status !== 'running' && c.status !== 'active'; });

        // Active
        if (active.length === 0) {
          activeContainer.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#127919;</div><div class="empty-state-title">No Active Campaigns</div><div class="empty-state-desc">Launch a campaign to begin multi-agent security operations</div></div>';
        } else {
          var html = '';
          active.forEach(function(c) {
            var progress = c.progress || 0;
            html += '<div class="glass-card" style="margin-bottom:8px;">' +
              '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">' +
                '<span style="color:var(--text-primary);font-weight:600;flex:1;">' + escapeHtml(c.goal || c.name || 'Campaign') + '</span>' +
                '<span class="badge badge-success">Running</span>' +
              '</div>' +
              '<div class="progress-bar"><div class="progress-bar-fill" style="width:' + progress + '%;"></div></div>' +
              '<div style="display:flex;justify-content:space-between;margin-top:6px;font-size:var(--font-size-xs);color:var(--text-tertiary);">' +
                '<span>' + (c.agents_complete || 0) + '/' + (c.agents_total || 0) + ' agents complete</span>' +
                '<span>' + progress + '%</span>' +
              '</div>' +
              '<div style="margin-top:8px;"><button class="btn btn-ghost btn-sm campaign-detail-btn" data-id="' + escapeHtml(c.id || '') + '">View Details</button></div>' +
            '</div>';
          });
          activeContainer.innerHTML = html;
        }

        // Past
        if (past.length === 0) {
          pastContainer.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#127919;</div><div class="empty-state-title">No Past Campaigns</div></div>';
        } else {
          var html2 = '<table class="data-table"><thead><tr><th>Goal</th><th>Status</th><th>Agents</th><th>Findings</th><th>Time</th></tr></thead><tbody>';
          past.forEach(function(c) {
            html2 += '<tr class="clickable campaign-detail-btn" data-id="' + escapeHtml(c.id || '') + '">' +
              '<td style="color:var(--text-primary);">' + escapeHtml((c.goal || c.name || '--').substring(0, 60)) + '</td>' +
              '<td><span class="tag">' + escapeHtml(c.status || 'complete') + '</span></td>' +
              '<td>' + (c.agents_total || 0) + '</td>' +
              '<td>' + (c.findings_count || 0) + '</td>' +
              '<td>' + timeAgo(c.created_at || c.timestamp) + '</td>' +
              '</tr>';
          });
          html2 += '</tbody></table>';
          pastContainer.innerHTML = html2;
        }

        // Detail buttons
        document.querySelectorAll('.campaign-detail-btn').forEach(function(btn) {
          btn.addEventListener('click', function() {
            Views.campaigns.showDetail(btn.getAttribute('data-id'));
          });
        });
      })
      .catch(function() {
        activeContainer.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#127919;</div><div class="empty-state-title">No Campaigns</div></div>';
      });
  },

  showLaunchModal: function() {
    Modal.open({
      title: 'Launch Campaign',
      body:
        '<div class="form-group"><label class="form-label">Campaign Goal</label><textarea class="form-textarea" id="campaign-goal" rows="3" placeholder="Describe the campaign goal... e.g., \'Full security audit of production infrastructure\'"></textarea></div>' +
        '<div class="form-group"><label class="form-label">Max Agents</label><input type="range" id="campaign-agents" min="1" max="10" value="3" style="width:100%;accent-color:var(--cyan);"><div style="display:flex;justify-content:space-between;font-size:var(--font-size-xs);color:var(--text-tertiary);"><span>1</span><span id="campaign-agents-val">3</span><span>10</span></div></div>',
      footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="campaign-launch-confirm">Launch</button>'
    });

    var slider = document.getElementById('campaign-agents');
    var valEl = document.getElementById('campaign-agents-val');
    slider.addEventListener('input', function() { valEl.textContent = slider.value; });

    document.getElementById('campaign-launch-confirm').addEventListener('click', function() {
      var goal = document.getElementById('campaign-goal').value.trim();
      if (!goal) { Toast.warning('Enter a campaign goal'); return; }
      var maxAgents = parseInt(document.getElementById('campaign-agents').value);

      Modal.loading('Launching campaign...');
      fetch('/api/campaigns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ goal: goal, max_agents: maxAgents })
      })
      .then(function() { Modal.close(); Toast.success('Campaign launched'); Views.campaigns.loadCampaigns(); })
      .catch(function() { Modal.close(); Toast.error('Failed to launch campaign'); });
    });
  },

  showDetail: function(id) {
    Modal.loading('Loading campaign details...');
    fetch('/api/campaigns/' + id, { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        Modal.close();
        var runs = data.agent_runs || data.runs || [];
        var runsHtml = '';
        if (Array.isArray(runs) && runs.length > 0) {
          runsHtml = '<table class="data-table"><thead><tr><th>Agent</th><th>Status</th><th>Summary</th></tr></thead><tbody>';
          runs.forEach(function(r) {
            runsHtml += '<tr><td style="color:var(--text-primary);">' + escapeHtml(r.agent_name || '--') + '</td><td><span class="tag">' + escapeHtml(r.status || '--') + '</span></td><td>' + escapeHtml((r.summary || r.result || '--').substring(0, 100)) + '</td></tr>';
          });
          runsHtml += '</tbody></table>';
        } else {
          runsHtml = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">No agent runs yet</div>';
        }

        Modal.open({
          title: 'Campaign Details',
          body:
            '<div class="detail-row"><div class="detail-label">Goal</div><div class="detail-value">' + escapeHtml(data.goal || '--') + '</div></div>' +
            '<div class="detail-row"><div class="detail-label">Status</div><div class="detail-value"><span class="tag">' + escapeHtml(data.status || '--') + '</span></div></div>' +
            '<div style="margin-top:16px;"><div class="form-label">Agent Runs</div>' + runsHtml + '</div>',
          size: 'lg'
        });
      })
      .catch(function() { Modal.close(); Toast.error('Failed to load campaign'); });
  }
};
