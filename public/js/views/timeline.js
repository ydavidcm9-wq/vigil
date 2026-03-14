/* Vigil v1.1 — Attack Timeline View */
Views.timeline = {
  _currentRange: '24h',
  _lastEvents: [],

  init: function() {
    var el = document.getElementById('view-timeline');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Attack Timeline</div>' +
        '<div style="display:flex;gap:8px;align-items:center;">' +
          '<button class="btn btn-ghost btn-sm timeline-range" data-range="1h">1h</button>' +
          '<button class="btn btn-ghost btn-sm timeline-range active" data-range="24h">24h</button>' +
          '<button class="btn btn-ghost btn-sm timeline-range" data-range="7d">7d</button>' +
          '<button class="btn btn-ghost btn-sm timeline-range" data-range="30d">30d</button>' +
          '<button class="btn btn-primary btn-sm" id="timeline-ai-btn">AI Analysis</button>' +
        '</div>' +
      '</div>' +

      // ── Stats bar ─────────────────────────────────────────────────
      '<div class="stat-grid" id="timeline-stats" style="margin-bottom:16px;display:none;">' +
        '<div class="stat-card">' +
          '<div class="stat-card-label">Total Events</div>' +
          '<div class="stat-card-value" id="tl-total">0</div>' +
        '</div>' +
        '<div class="stat-card">' +
          '<div class="stat-card-label">Critical</div>' +
          '<div class="stat-card-value" id="tl-critical" style="color:var(--orange);">0</div>' +
        '</div>' +
        '<div class="stat-card">' +
          '<div class="stat-card-label">High</div>' +
          '<div class="stat-card-value" id="tl-high" style="color:var(--orange);">0</div>' +
        '</div>' +
        '<div class="stat-card">' +
          '<div class="stat-card-label">Event Types</div>' +
          '<div class="stat-card-value" id="tl-types">0</div>' +
        '</div>' +
      '</div>' +

      // ── AI Analysis panel ─────────────────────────────────────────
      '<div class="glass-card" id="timeline-ai-panel" style="display:none;margin-bottom:16px;">' +
        '<div class="glass-card-title" style="margin-bottom:8px;color:var(--cyan);">AI Timeline Analysis</div>' +
        '<div id="timeline-ai-content"></div>' +
      '</div>' +

      // ── Filter bar ────────────────────────────────────────────────
      '<div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;" id="timeline-type-pills">' +
        '<button class="btn btn-ghost btn-sm tl-type-btn active" data-type="all">All</button>' +
        '<button class="btn btn-ghost btn-sm tl-type-btn" data-type="finding">Findings</button>' +
        '<button class="btn btn-ghost btn-sm tl-type-btn" data-type="threat">Threats</button>' +
        '<button class="btn btn-ghost btn-sm tl-type-btn" data-type="alert">Alerts</button>' +
        '<button class="btn btn-ghost btn-sm tl-type-btn" data-type="scan">Scans</button>' +
        '<button class="btn btn-ghost btn-sm tl-type-btn" data-type="incident">Incidents</button>' +
        '<button class="btn btn-ghost btn-sm tl-type-btn" data-type="hunt">Hunts</button>' +
        '<button class="btn btn-ghost btn-sm tl-type-btn" data-type="auth">Auth</button>' +
        '<button class="btn btn-ghost btn-sm tl-type-btn" data-type="osint">OSINT</button>' +
      '</div>' +

      // ── Event counts by type ──────────────────────────────────────
      '<div id="timeline-type-counts" style="display:none;margin-bottom:16px;display:flex;gap:6px;flex-wrap:wrap;"></div>' +

      // ── Timeline events ───────────────────────────────────────────
      '<div class="glass-card">' +
        '<div id="timeline-events">' +
          '<div class="loading-state"><div class="spinner"></div><div>Loading timeline...</div></div>' +
        '</div>' +
      '</div>';

    var self = this;

    // Range buttons
    document.querySelectorAll('.timeline-range').forEach(function(btn) {
      btn.addEventListener('click', function() {
        document.querySelectorAll('.timeline-range').forEach(function(b) { b.classList.remove('active'); });
        btn.classList.add('active');
        self._currentRange = btn.getAttribute('data-range');
        self.loadEvents();
      });
    });

    // Type filter pills
    document.querySelectorAll('.tl-type-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        document.querySelectorAll('.tl-type-btn').forEach(function(b) { b.classList.remove('active'); });
        btn.classList.add('active');
        self.loadEvents();
      });
    });

    // AI Analysis button
    document.getElementById('timeline-ai-btn').addEventListener('click', function() { self.runAIAnalysis(); });
  },

  show: function() {
    this.loadEvents();
  },

  hide: function() {},

  getActiveType: function() {
    var active = document.querySelector('.tl-type-btn.active');
    return active ? active.getAttribute('data-type') : 'all';
  },

  loadEvents: function() {
    var container = document.getElementById('timeline-events');
    var range = this._currentRange;
    var type = this.getActiveType();
    var url = '/api/timeline?range=' + range;
    if (type !== 'all') url += '&type=' + type;

    var self = this;

    fetch(url, { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.error) { Toast.error(data.error); return; }

        var events = data.events || [];
        self._lastEvents = events;

        // ── Update stats ────────────────────────────────────────
        var stats = document.getElementById('timeline-stats');
        stats.style.display = 'grid';
        var sev = data.severities || {};
        var totalEl = document.getElementById('tl-total');
        var critEl = document.getElementById('tl-critical');
        var highEl = document.getElementById('tl-high');
        var typesEl = document.getElementById('tl-types');

        if (typeof animateValue === 'function') {
          animateValue(totalEl, 0, data.total || events.length, 500);
          animateValue(critEl, 0, sev.critical || 0, 500);
          animateValue(highEl, 0, sev.high || 0, 500);
          animateValue(typesEl, 0, Object.keys(data.counts || {}).length, 500);
        } else {
          totalEl.textContent = data.total || events.length;
          critEl.textContent = sev.critical || 0;
          highEl.textContent = sev.high || 0;
          typesEl.textContent = Object.keys(data.counts || {}).length;
        }

        // ── Type counts badges ──────────────────────────────────
        var countsEl = document.getElementById('timeline-type-counts');
        var counts = data.counts || {};
        if (Object.keys(counts).length > 0) {
          countsEl.style.display = 'flex';
          var countsHtml = '';
          var typeColors = {
            finding: 'var(--orange)', threat: 'var(--orange)', alert: 'var(--orange)',
            incident: 'var(--orange)', scan: 'var(--cyan)', hunt: 'var(--purple)',
            auth: 'var(--text-tertiary)', osint: 'var(--cyan)'
          };
          Object.entries(counts).sort(function(a, b) { return b[1] - a[1]; }).forEach(function(pair) {
            var color = typeColors[pair[0]] || 'var(--text-secondary)';
            countsHtml += '<span style="font-size:var(--font-size-xs);color:' + color + ';background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:4px;padding:2px 8px;">' +
              escapeHtml(pair[0]) + ': ' + pair[1] + '</span>';
          });
          countsEl.innerHTML = countsHtml;
        } else {
          countsEl.style.display = 'none';
        }

        // ── Render events ───────────────────────────────────────
        if (!Array.isArray(events) || events.length === 0) {
          container.innerHTML = '<div class="empty-state">' +
            '<div class="empty-state-icon">&#128339;</div>' +
            '<div class="empty-state-title">No Events</div>' +
            '<div class="empty-state-desc">No security events in this time range. Run a scan, investigate a domain, or hunt a threat to generate events.</div>' +
            '</div>';
          return;
        }

        var html = '<div class="timeline">';
        var lastDate = '';

        events.forEach(function(ev) {
          var sev = (ev.severity || 'info').toLowerCase();
          var evClass = (sev === 'critical' || sev === 'high') ? 'event-critical' :
                        sev === 'medium' ? 'event-warning' : 'event-info';

          // Date separator
          var evDate = (ev.timestamp || '').substring(0, 10);
          if (evDate && evDate !== lastDate) {
            lastDate = evDate;
            html += '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);font-weight:600;text-transform:uppercase;padding:12px 0 4px 20px;border-left:2px solid var(--border);margin-left:3px;">' + escapeHtml(evDate) + '</div>';
          }

          // Type badge color
          var typeColor = 'var(--text-tertiary)';
          var evType = (ev.type || 'event').toLowerCase();
          if (evType === 'finding' || evType === 'threat' || evType === 'alert') typeColor = 'var(--orange)';
          else if (evType === 'scan' || evType === 'osint') typeColor = 'var(--cyan)';
          else if (evType === 'hunt') typeColor = 'var(--purple)';
          else if (evType === 'incident') typeColor = 'var(--orange)';

          // Severity indicator
          var sevBadge = '';
          if (sev === 'critical') sevBadge = '<span class="badge badge-critical" style="font-size:10px;margin-right:6px;">CRITICAL</span>';
          else if (sev === 'high') sevBadge = '<span class="badge badge-high" style="font-size:10px;margin-right:6px;">HIGH</span>';

          html += '<div class="timeline-event ' + evClass + '">' +
            '<div class="timeline-event-time">' + formatDate(ev.timestamp) + '</div>' +
            '<div class="timeline-event-title">' +
              '<span style="color:' + typeColor + ';font-size:var(--font-size-xs);font-weight:600;text-transform:uppercase;margin-right:6px;border:1px solid ' + typeColor + ';border-radius:3px;padding:1px 5px;">' + escapeHtml(evType) + '</span>' +
              sevBadge +
              escapeHtml(ev.title || '--') +
            '</div>' +
            (ev.description ? '<div class="timeline-event-desc">' + escapeHtml(ev.description) + '</div>' : '') +
            (ev.details ? '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-top:4px;font-family:var(--font-mono);">' + escapeHtml(ev.details) + '</div>' : '') +
            (ev.source ? '<div style="color:var(--text-tertiary);font-size:10px;margin-top:2px;">via ' + escapeHtml(ev.source) + '</div>' : '') +
          '</div>';
        });

        html += '</div>';
        container.innerHTML = html;

        Toast.success(events.length + ' events loaded (' + range + ')');
      })
      .catch(function() {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128339;</div><div class="empty-state-title">Timeline Error</div><div class="empty-state-desc">Could not load timeline. Check server connection.</div></div>';
      });
  },

  runAIAnalysis: function() {
    var events = this._lastEvents;
    if (!events || events.length === 0) {
      Toast.warning('No events to analyze — load the timeline first');
      return;
    }

    var btn = document.getElementById('timeline-ai-btn');
    var panel = document.getElementById('timeline-ai-panel');
    var content = document.getElementById('timeline-ai-content');

    btn.disabled = true;
    btn.textContent = 'Analyzing...';
    panel.style.display = 'block';
    content.innerHTML = '<div class="loading-state"><div class="spinner"></div><div>AI analyzing ' + events.length + ' security events...</div></div>';

    fetch('/api/timeline/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ events: events, range: this._currentRange })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      btn.disabled = false;
      btn.textContent = 'AI Analysis';

      if (data.error) {
        content.innerHTML = '<div style="color:var(--orange);font-size:var(--font-size-sm);">' + escapeHtml(data.error) + '</div>';
        return;
      }

      var analysis = data.analysis || 'No analysis available.';
      content.innerHTML = '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;white-space:pre-wrap;">' + escapeHtml(analysis) + '</div>';
      Toast.success('Timeline analysis complete');
    })
    .catch(function() {
      btn.disabled = false;
      btn.textContent = 'AI Analysis';
      content.innerHTML = '<div style="color:var(--orange);font-size:var(--font-size-sm);">AI analysis failed. Configure an AI provider in Settings.</div>';
    });
  }
};
