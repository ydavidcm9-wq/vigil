/* Vigil v1.1 — Log Analysis View */
Views['log-analysis'] = {
  _queryHistory: [],

  init: function() {
    var el = document.getElementById('view-log-analysis');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">AI Log Analysis</div>' +
      '</div>' +

      '<div class="glass-card" style="margin-bottom:20px;">' +
        '<div class="form-group">' +
          '<label class="form-label">Natural Language Query</label>' +
          '<div class="form-inline">' +
            '<div class="form-group" style="flex:1;margin-bottom:0;">' +
              '<input type="text" class="form-input" id="log-query-input" placeholder="e.g., Show me failed SSH logins in the last hour">' +
            '</div>' +
            '<div class="form-group" style="margin-bottom:0;">' +
              '<select class="form-select" id="log-source" style="width:auto;">' +
                '<option value="auto">Auto (All Sources)</option>' +
                '<option value="vigil">Vigil Security Data</option>' +
                '<option value="syslog">Syslog (Linux)</option>' +
                '<option value="auth">Auth Log (Linux)</option>' +
                '<option value="apache">Apache (Linux)</option>' +
                '<option value="nginx">Nginx (Linux)</option>' +
                '<option value="journal">Systemd Journal (Linux)</option>' +
              '</select>' +
            '</div>' +
            '<div class="form-group" style="margin-bottom:0;">' +
              '<button class="btn btn-primary" id="log-query-btn">Analyze</button>' +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card" style="margin-bottom:20px;">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Results</div>' +
        '<div id="log-results">' +
          '<div class="empty-state"><div class="empty-state-icon">&#128270;</div><div class="empty-state-title">No Analysis</div><div class="empty-state-desc">Enter a natural language query to analyze logs</div></div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Query History</div>' +
        '<div id="log-query-history">' +
          '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">No queries yet</div>' +
        '</div>' +
      '</div>';

    var self = this;
    document.getElementById('log-query-btn').addEventListener('click', function() { self.runQuery(); });
    document.getElementById('log-query-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') self.runQuery();
    });
  },

  show: function() {
    this.renderHistory();
  },

  hide: function() {},

  runQuery: function() {
    var query = document.getElementById('log-query-input').value.trim();
    if (!query) { Toast.warning('Enter a query'); return; }

    var source = document.getElementById('log-source').value;
    var results = document.getElementById('log-results');
    var btn = document.getElementById('log-query-btn');

    btn.disabled = true;
    btn.textContent = 'Analyzing...';
    results.innerHTML = '<div class="loading-state"><div class="spinner"></div><div>AI analyzing security data...</div><div style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-top:4px;">Querying data stores and generating AI analysis (10-30s)</div></div>';

    fetch('/api/logs/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ query: query, source: source })
    })
    .then(function(r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    })
    .then(function(data) {
      btn.disabled = false;
      btn.textContent = 'Analyze';
      var command = data.command || '';
      var output = data.output || '';
      var analysis = data.analysis || data.narration || '';

      var html = '';
      if (command) {
        html += '<div style="margin-bottom:12px;"><div class="form-label">Command Executed</div><div class="code-block">' + escapeHtml(command) + '</div></div>';
      }
      if (output) {
        html += '<div style="margin-bottom:12px;"><div class="form-label">Output</div><div class="code-block" style="max-height:300px;overflow-y:auto;white-space:pre-wrap;">' + escapeHtml(output) + '</div></div>';
      }
      if (analysis) {
        html += '<div><div class="form-label">AI Analysis</div><div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;">' + escapeHtml(analysis).replace(/\n/g, '<br>') + '</div></div>';
      }
      if (!command && !output && !analysis) {
        html = '<div style="color:var(--text-tertiary);">No results returned</div>';
      }
      results.innerHTML = html;

      // Add to history
      Views['log-analysis']._queryHistory.unshift({ query: query, source: source, time: new Date().toISOString() });
      Views['log-analysis'].renderHistory();
    })
    .catch(function(err) {
      btn.disabled = false;
      btn.textContent = 'Analyze';
      results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Analysis Failed</div><div class="empty-state-desc">' + escapeHtml(err.message || 'Check server connection and try again') + '</div></div>';
      Toast.error('Log analysis failed: ' + (err.message || 'connection error'));
    });
  },

  renderHistory: function() {
    var container = document.getElementById('log-query-history');
    if (this._queryHistory.length === 0) {
      container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">No queries yet</div>';
      return;
    }

    var html = '';
    this._queryHistory.slice(0, 20).forEach(function(h) {
      html += '<div style="padding:6px 0;border-bottom:1px solid var(--border);cursor:pointer;display:flex;align-items:center;gap:8px;" onclick="document.getElementById(\'log-query-input\').value=\'' + escapeHtml(h.query).replace(/'/g, "\\'") + '\';">' +
        '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);min-width:60px;">' + timeAgo(h.time) + '</span>' +
        '<span style="color:var(--text-primary);font-size:var(--font-size-sm);">' + escapeHtml(h.query) + '</span>' +
        '<span class="tag" style="margin-left:auto;">' + escapeHtml(h.source) + '</span>' +
      '</div>';
    });
    container.innerHTML = html;
  }
};
