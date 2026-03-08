/* Vigil v1.0 — Threat Hunt View */
Views.hunt = {
  init: function() {
    var el = document.getElementById('view-hunt');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">AI Threat Hunting</div>' +
      '</div>' +

      '<div class="glass-card" style="margin-bottom:20px;">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Hypothesis</div>' +
        '<textarea class="form-textarea" id="hunt-hypothesis" rows="3" placeholder="Enter your threat hunting hypothesis... e.g., \'Unauthorized SSH access from foreign IPs in the last 24 hours\'"></textarea>' +
        '<div style="display:flex;align-items:center;gap:10px;margin-top:12px;">' +
          '<button class="btn btn-primary" id="hunt-investigate">Investigate</button>' +
          '<button class="btn btn-ghost btn-sm" id="hunt-clear">Clear</button>' +
        '</div>' +
        '<div style="margin-top:12px;">' +
          '<div class="form-label">Quick Hypotheses</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:6px;" id="hunt-quick-btns">' +
            '<button class="btn btn-ghost btn-sm hunt-quick" data-q="Check for unauthorized SSH access attempts in the last 24 hours">SSH Brute Force</button>' +
            '<button class="btn btn-ghost btn-sm hunt-quick" data-q="Look for suspicious outbound connections to known malicious IPs">C2 Communication</button>' +
            '<button class="btn btn-ghost btn-sm hunt-quick" data-q="Detect privilege escalation attempts on Linux systems">Privilege Escalation</button>' +
            '<button class="btn btn-ghost btn-sm hunt-quick" data-q="Find signs of lateral movement across network segments">Lateral Movement</button>' +
            '<button class="btn btn-ghost btn-sm hunt-quick" data-q="Check for data exfiltration via DNS tunneling">DNS Exfiltration</button>' +
            '<button class="btn btn-ghost btn-sm hunt-quick" data-q="Identify persistence mechanisms such as cron jobs or startup scripts">Persistence Mechanisms</button>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card" style="margin-bottom:20px;">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Investigation Results</div>' +
        '<div id="hunt-results">' +
          '<div class="empty-state"><div class="empty-state-icon">&#128269;</div><div class="empty-state-title">No Investigation</div><div class="empty-state-desc">Enter a hypothesis and click Investigate to begin</div></div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Investigation History</div>' +
        '<div id="hunt-history">' +
          '<div class="empty-state"><div class="empty-state-icon">&#128339;</div><div class="empty-state-title">No History</div><div class="empty-state-desc">Past investigations will appear here</div></div>' +
        '</div>' +
      '</div>';

    var self = this;
    document.getElementById('hunt-investigate').addEventListener('click', function() { self.investigate(); });
    document.getElementById('hunt-clear').addEventListener('click', function() {
      document.getElementById('hunt-hypothesis').value = '';
      document.getElementById('hunt-results').innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128269;</div><div class="empty-state-title">No Investigation</div><div class="empty-state-desc">Enter a hypothesis and click Investigate to begin</div></div>';
    });

    document.querySelectorAll('.hunt-quick').forEach(function(btn) {
      btn.addEventListener('click', function() {
        document.getElementById('hunt-hypothesis').value = btn.getAttribute('data-q');
      });
    });
  },

  show: function() {
    this.loadHistory();
  },

  hide: function() {},

  investigate: function() {
    var hypothesis = document.getElementById('hunt-hypothesis').value.trim();
    if (!hypothesis) {
      Toast.warning('Enter a threat hunting hypothesis');
      return;
    }

    var btn = document.getElementById('hunt-investigate');
    btn.disabled = true;
    btn.textContent = 'Investigating...';

    var results = document.getElementById('hunt-results');
    results.innerHTML =
      '<div class="loading-state">' +
        '<div class="spinner spinner-lg"></div>' +
        '<div>AI is investigating...</div>' +
        '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);">Gathering evidence and analyzing — this may take 15-30 seconds</div>' +
      '</div>';

    fetch('/api/hunt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ hypothesis: hypothesis })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      btn.disabled = false;
      btn.textContent = 'Investigate';

      if (data.error) {
        results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Investigation Error</div><div class="empty-state-desc">' + escapeHtml(data.error) + '</div></div>';
        Toast.error(data.error);
        return;
      }

      var evidence = data.evidence || [];
      var analysis = data.analysis || 'No analysis available.';
      var verdict = data.verdict || 'inconclusive';
      var verdictColor = verdict === 'confirmed' ? 'var(--orange)' :
                        verdict === 'clear' ? 'var(--cyan)' : 'var(--text-secondary)';
      var verdictLabel = verdict === 'confirmed' ? 'THREAT CONFIRMED' :
                        verdict === 'clear' ? 'NOT CONFIRMED' : 'INCONCLUSIVE';

      var html =
        '<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;padding:12px;border-radius:8px;background:rgba(255,255,255,0.03);border:1px solid ' + verdictColor + '33;">' +
          '<span style="font-size:var(--font-size-lg);font-weight:700;color:' + verdictColor + ';">' + verdictLabel + '</span>' +
        '</div>';

      // Plan section
      if (data.plan && data.plan.plan) {
        html += '<div style="margin-bottom:16px;">' +
          '<div class="form-label">Investigation Plan</div>' +
          '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);">' + escapeHtml(data.plan.plan) + '</div>' +
          '</div>';
      }

      // Evidence section
      if (evidence.length > 0) {
        html += '<div style="margin-bottom:16px;">' +
          '<div class="form-label">Evidence Gathered (' + evidence.length + ' sources)</div>';
        evidence.forEach(function(e) {
          var statusIcon = e.status === 'collected' ? '&#9679;' : e.status === 'skipped' ? '&#9675;' : '&#10007;';
          var statusColor = e.status === 'collected' ? 'var(--cyan)' : e.status === 'skipped' ? 'var(--text-tertiary)' : 'var(--orange)';
          html += '<div style="margin-bottom:8px;">' +
            '<div style="font-size:var(--font-size-xs);color:var(--text-tertiary);margin-bottom:4px;"><span style="color:' + statusColor + ';">' + statusIcon + '</span> ' + escapeHtml(e.command) + ' — ' + e.status + '</div>' +
            '<div class="code-block" style="max-height:150px;overflow-y:auto;">' + escapeHtml(typeof e.output === 'string' ? e.output : JSON.stringify(e.output, null, 2)) + '</div>' +
            '</div>';
        });
        html += '</div>';
      }

      // AI Analysis section
      html += '<div>' +
        '<div class="form-label">AI Analysis</div>' +
        '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;white-space:pre-wrap;">' + escapeHtml(analysis) + '</div>' +
        '</div>';

      results.innerHTML = html;
      Toast.success('Investigation complete');
      Views.hunt.loadHistory();
    })
    .catch(function(e) {
      btn.disabled = false;
      btn.textContent = 'Investigate';
      results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Investigation Failed</div><div class="empty-state-desc">Could not complete the threat hunt. Check your network connection.</div></div>';
      Toast.error('Threat hunt failed');
    });
  },

  loadHistory: function() {
    var container = document.getElementById('hunt-history');
    fetch('/api/hunt/history', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var history = data.hunts || [];
        if (!Array.isArray(history) || history.length === 0) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128339;</div><div class="empty-state-title">No History</div><div class="empty-state-desc">Completed investigations will appear here</div></div>';
          return;
        }

        var html = '<table class="data-table"><thead><tr><th>Hypothesis</th><th>Verdict</th><th>Status</th><th>Time</th></tr></thead><tbody>';
        history.slice(0, 20).forEach(function(h) {
          var verdict = h.verdict || '--';
          var vColor = verdict === 'confirmed' ? 'var(--orange)' :
                      verdict === 'clear' ? 'var(--cyan)' : 'var(--text-secondary)';
          var vLabel = verdict === 'confirmed' ? 'CONFIRMED' :
                      verdict === 'clear' ? 'CLEAR' :
                      verdict === 'inconclusive' ? 'INCONCLUSIVE' : verdict.toUpperCase();
          var statusColor = h.status === 'completed' ? 'var(--cyan)' :
                           h.status === 'failed' ? 'var(--orange)' : 'var(--text-tertiary)';
          html += '<tr>' +
            '<td style="color:var(--text-primary);max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + escapeHtml(h.hypothesis || '--') + '</td>' +
            '<td><span style="color:' + vColor + ';font-weight:600;text-transform:uppercase;font-size:var(--font-size-xs);">' + escapeHtml(vLabel) + '</span></td>' +
            '<td><span style="color:' + statusColor + ';font-size:var(--font-size-xs);">' + escapeHtml(h.status || '--') + '</span></td>' +
            '<td>' + timeAgo(h.createdAt || h.timestamp) + '</td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      })
      .catch(function() {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128339;</div><div class="empty-state-title">No History</div></div>';
      });
  }
};
