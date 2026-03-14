/* Vigil v1.1 — Brain Chat View (AI Brain with KB, Memory, Actions) */
Views['brain-chat'] = {
  _messages: [],
  _conversationHistory: [],
  _currentSection: null,

  init: function() {
    var el = document.getElementById('view-brain-chat');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">' +
          '<span style="margin-right:8px">&#x1f9e0;</span> Vigil Brain' +
          '<span id="brain-profile-badge" class="badge badge-info" style="margin-left:12px;font-size:11px"></span>' +
        '</div>' +
        '<div style="display:flex;gap:8px">' +
          '<button class="btn btn-ghost btn-sm" id="brain-kb-stats" title="KB Stats">KB Stats</button>' +
          '<button class="btn btn-ghost btn-sm" id="brain-memories-btn" title="View Memories">Memories</button>' +
          '<button class="btn btn-ghost btn-sm" id="brain-clear">Clear</button>' +
        '</div>' +
      '</div>' +

      // Discovery banner (shown when profile incomplete)
      '<div id="brain-discovery-banner" class="glass-card" style="display:none;margin-bottom:12px;padding:12px;border-left:3px solid var(--accent)">' +
        '<div style="display:flex;justify-content:space-between;align-items:center">' +
          '<div>' +
            '<strong>Profile Setup</strong> — ' +
            '<span id="brain-discovery-question"></span>' +
          '</div>' +
          '<div style="display:flex;gap:6px">' +
            '<input type="text" class="form-input" id="brain-discovery-input" placeholder="Your answer..." style="width:200px">' +
            '<button class="btn btn-primary btn-sm" id="brain-discovery-submit">Save</button>' +
            '<button class="btn btn-ghost btn-sm" id="brain-discovery-skip">Skip</button>' +
          '</div>' +
        '</div>' +
      '</div>' +

      // Chat area
      '<div class="glass-card" style="display:flex;flex-direction:column;height:calc(100vh - var(--topbar-height) - var(--statusbar-height) - 180px);min-height:400px;">' +
        '<div class="chat-messages" id="brain-chat-messages" style="flex:1;max-height:none;overflow-y:auto">' +
          '<div class="chat-msg ai">' +
            'Welcome to <strong>Vigil Brain</strong> — your AI security operations analyst with built-in knowledge of MITRE ATT&amp;CK, OWASP, NIST, CompTIA Security+, and more.<br><br>' +
            'I can answer security questions instantly from my knowledge base, guide you through Vigil\'s tools, and remember your infrastructure context.<br><br>' +
            '<em>Try: "What is T1059?", "port 445", "how do I scan for vulnerabilities?", or ask anything about security.</em>' +
          '</div>' +
        '</div>' +

        // Suggested actions bar
        '<div id="brain-suggestions" style="display:flex;gap:6px;padding:8px 12px;flex-wrap:wrap;border-top:1px solid var(--border-color)"></div>' +

        // Input
        '<div class="chat-input-row">' +
          '<input type="text" class="form-input" id="brain-chat-input" placeholder="Ask about security, MITRE techniques, ports, compliance...">' +
          '<button class="btn btn-primary" id="brain-chat-send">Send</button>' +
        '</div>' +
      '</div>';

    var self = this;
    document.getElementById('brain-chat-send').addEventListener('click', function() { self.sendMessage(); });
    document.getElementById('brain-chat-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') { e.preventDefault(); self.sendMessage(); }
    });
    document.getElementById('brain-clear').addEventListener('click', function() {
      self._messages = [];
      self._conversationHistory = [];
      document.getElementById('brain-chat-messages').innerHTML =
        '<div class="chat-msg ai">Chat cleared. How can I help with security?</div>';
      document.getElementById('brain-suggestions').innerHTML = '';
    });
    document.getElementById('brain-kb-stats').addEventListener('click', function() { self.showKBStats(); });
    document.getElementById('brain-memories-btn').addEventListener('click', function() { self.showMemories(); });
    document.getElementById('brain-discovery-submit').addEventListener('click', function() { self.submitDiscovery(); });
    document.getElementById('brain-discovery-skip').addEventListener('click', function() {
      document.getElementById('brain-discovery-banner').style.display = 'none';
    });

    this.loadProfileStatus();
  },

  show: function() {
    var input = document.getElementById('brain-chat-input');
    if (input) setTimeout(function() { input.focus(); }, 100);
    this._currentSection = window._brainLastSection || null;
    this.loadSuggestions();
  },

  hide: function() {},

  sendMessage: function() {
    var input = document.getElementById('brain-chat-input');
    var message = input.value.trim();
    if (!message) return;

    input.value = '';
    this.appendMessage('user', message);
    this._conversationHistory.push({ role: 'user', content: message });

    var self = this;
    var container = document.getElementById('brain-chat-messages');

    // Show typing indicator
    var typingId = 'typing-' + Date.now();
    var typingEl = document.createElement('div');
    typingEl.className = 'chat-msg ai';
    typingEl.id = typingId;
    typingEl.innerHTML = '<em>Thinking...</em>';
    container.appendChild(typingEl);
    container.scrollTop = container.scrollHeight;

    fetch('/api/brain/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: message,
        sectionContext: self._currentSection,
        conversationHistory: self._conversationHistory.slice(-10),
      }),
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      // Remove typing indicator
      var typing = document.getElementById(typingId);
      if (typing) typing.remove();

      if (data.error) {
        self.appendMessage('ai', 'Error: ' + data.error);
        return;
      }

      // Build response with citations and actions
      var html = self.formatResponse(data.response);

      // Add source citations
      if (data.sources && data.sources.length) {
        html += '<div class="brain-sources" style="margin-top:10px;padding-top:8px;border-top:1px solid var(--border-color);font-size:12px;opacity:0.7">';
        html += '<strong>Sources:</strong> ';
        html += data.sources.map(function(s) {
          return '<span class="badge badge-ghost" style="font-size:11px;cursor:pointer" onclick="Views[\'brain-chat\'].lookupKB(\'' + self.escapeAttr(s.id) + '\')">[' + self.escapeHtml(s.id) + '] ' + self.escapeHtml(s.title) + '</span>';
        }).join(' ');
        html += '</div>';
      }

      // Add action buttons
      if (data.suggestedActions && data.suggestedActions.length) {
        html += '<div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap">';
        html += data.suggestedActions.map(function(a) {
          return '<button class="btn btn-sm btn-outline" onclick="App.navigate(\'' + self.escapeAttr(a.targetSection) + '\')">' +
            self.escapeHtml(a.name) + ' &rarr;</button>';
        }).join('');
        html += '</div>';
      }

      // KB badge
      if (data.fromKB) {
        html = '<span class="badge badge-success" style="font-size:10px;margin-bottom:6px">Instant KB Answer</span><br>' + html;
      }

      self.appendMessageHTML('ai', html);
      self._conversationHistory.push({ role: 'assistant', content: data.response });

      // Update profile badge
      if (data.profileCompletion !== null && data.profileCompletion !== undefined) {
        var badge = document.getElementById('brain-profile-badge');
        if (badge) {
          badge.textContent = 'Profile: ' + data.profileCompletion + '%';
          badge.className = 'badge ' + (data.profileCompletion >= 80 ? 'badge-success' : data.profileCompletion >= 40 ? 'badge-warning' : 'badge-info');
        }
      }
    })
    .catch(function(err) {
      var typing = document.getElementById(typingId);
      if (typing) typing.remove();
      self.appendMessage('ai', 'Network error: ' + err.message);
    });
  },

  appendMessage: function(role, text) {
    var container = document.getElementById('brain-chat-messages');
    var div = document.createElement('div');
    div.className = 'chat-msg ' + role;
    div.textContent = text;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
  },

  appendMessageHTML: function(role, html) {
    var container = document.getElementById('brain-chat-messages');
    var div = document.createElement('div');
    div.className = 'chat-msg ' + role;
    div.innerHTML = html;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
  },

  formatResponse: function(text) {
    if (!text) return '';
    // Escape HTML first
    var html = this.escapeHtml(text);
    // Markdown-like formatting
    html = html.replace(/\*\*\[KB:\s*([^\]]+)\]\s*([^*]*)\*\*/g, '<strong class="brain-kb-ref" style="color:var(--accent);cursor:pointer" onclick="Views[\'brain-chat\'].lookupKB(\'$1\')">[$1] $2</strong>');
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
    html = html.replace(/\*\*Go to:\s*([^*]+)\*\*/g, function(match, section) {
      return '<button class="btn btn-sm btn-outline" onclick="App.navigate(\'' + section.toLowerCase().replace(/\s+/g, '-') + '\')">' + section + ' &rarr;</button>';
    });
    html = html.replace(/\n/g, '<br>');
    return html;
  },

  lookupKB: function(id) {
    var self = this;
    fetch('/api/brain/kb/lookup/' + encodeURIComponent(id), {
      headers: { 'Content-Type': 'application/json' },
    })
    .then(function(r) { return r.json(); })
    .then(function(entry) {
      if (entry.error) return;
      var html = '<div style="background:var(--surface-2);padding:12px;border-radius:8px;margin:4px 0">';
      html += '<strong>[' + self.escapeHtml(entry.id) + '] ' + self.escapeHtml(entry.title) + '</strong><br>';
      html += '<span style="font-size:12px">' + self.escapeHtml(entry.content) + '</span>';
      if (entry.severity) html += '<br><span class="badge badge-' + (entry.severity === 'critical' ? 'danger' : entry.severity === 'high' ? 'warning' : 'info') + '">' + entry.severity + '</span>';
      html += '</div>';
      self.appendMessageHTML('ai', html);
    });
  },

  showKBStats: function() {
    var self = this;
    fetch('/api/brain/kb/stats', { headers: { 'Content-Type': 'application/json' } })
    .then(function(r) { return r.json(); })
    .then(function(stats) {
      var html = '<strong>Knowledge Base Stats</strong><br>';
      html += 'Total entries: <strong>' + stats.totalEntries + '</strong><br>';
      html += 'MITRE techniques: ' + stats.mitreCount + '<br>';
      html += 'CWE mappings: ' + stats.cweCount + '<br>';
      html += 'Port mappings: ' + stats.portCount + '<br>';
      html += '<br>Domains:<br>';
      for (var d in stats.domains) {
        html += '&nbsp;&nbsp;' + d + ': ' + stats.domains[d] + '<br>';
      }
      self.appendMessageHTML('ai', html);
    });
  },

  showMemories: function() {
    var self = this;
    fetch('/api/brain/memories?limit=10', { headers: { 'Content-Type': 'application/json' } })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (!data.memories || !data.memories.length) {
        self.appendMessageHTML('ai', '<em>No memories stored yet. As we chat, I\'ll remember important details about your infrastructure and findings.</em>');
        return;
      }
      var html = '<strong>Recent Memories (' + data.count + ' total)</strong><br>';
      data.memories.forEach(function(m) {
        html += '<div style="padding:4px 0;border-bottom:1px solid var(--border-color);font-size:13px">';
        html += '<span class="badge badge-ghost" style="font-size:10px">' + self.escapeHtml(m.type) + '</span> ';
        html += self.escapeHtml(m.content);
        html += '</div>';
      });
      self.appendMessageHTML('ai', html);
    });
  },

  loadProfileStatus: function() {
    fetch('/api/brain/profile/next-question', { headers: { 'Content-Type': 'application/json' } })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      var badge = document.getElementById('brain-profile-badge');
      if (badge) {
        badge.textContent = 'Profile: ' + (data.completion || 0) + '%';
        badge.className = 'badge ' + (data.completion >= 80 ? 'badge-success' : data.completion >= 40 ? 'badge-warning' : 'badge-info');
      }
      if (data.question && data.completion < 80) {
        document.getElementById('brain-discovery-banner').style.display = 'block';
        document.getElementById('brain-discovery-question').textContent = data.question;
        document.getElementById('brain-discovery-input').dataset.field = data.field || '';
      }
    })
    .catch(function() {}); // Silently fail on profile load
  },

  submitDiscovery: function() {
    var input = document.getElementById('brain-discovery-input');
    var value = input.value.trim();
    if (!value) return;

    // Send as a chat message so the brain can extract profile updates
    this.appendMessage('user', value);
    this._conversationHistory.push({ role: 'user', content: value });

    var self = this;
    fetch('/api/brain/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: value, sectionContext: 'brain-chat' }),
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.response) {
        self.appendMessageHTML('ai', self.formatResponse(data.response));
      }
      input.value = '';
      document.getElementById('brain-discovery-banner').style.display = 'none';
      self.loadProfileStatus(); // Refresh
    });
  },

  loadSuggestions: function() {
    var section = this._currentSection || 'dashboard';
    var container = document.getElementById('brain-suggestions');
    if (!container) return;

    fetch('/api/brain/sections/' + encodeURIComponent(section) + '/context', {
      headers: { 'Content-Type': 'application/json' },
    })
    .then(function(r) { return r.json(); })
    .then(function(ctx) {
      if (!ctx.helpPrompts || !ctx.helpPrompts.length) {
        container.innerHTML = '';
        return;
      }
      container.innerHTML = ctx.helpPrompts.map(function(prompt) {
        return '<button class="btn btn-ghost btn-sm" style="font-size:11px" onclick="document.getElementById(\'brain-chat-input\').value=\'' +
          prompt.replace(/'/g, "\\'") + '\';Views[\'brain-chat\'].sendMessage()">' + prompt + '</button>';
      }).join('');
    })
    .catch(function() { container.innerHTML = ''; });
  },

  escapeHtml: function(s) {
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  },

  escapeAttr: function(s) {
    return String(s).replace(/['"&<>]/g, function(c) {
      return { "'": '&#39;', '"': '&quot;', '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c];
    });
  },
};
