/* Vigil v1.0 — AI Security Chat View */
Views['ai-chat'] = {
  _messages: [],

  init: function() {
    var el = document.getElementById('view-ai-chat');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">AI Security Chat</div>' +
        '<button class="btn btn-ghost btn-sm" id="ai-chat-clear">Clear Chat</button>' +
      '</div>' +

      '<div class="glass-card" style="display:flex;flex-direction:column;height:calc(100vh - var(--topbar-height) - var(--statusbar-height) - 120px);min-height:400px;">' +
        '<div class="chat-messages" id="ai-chat-messages" style="flex:1;max-height:none;">' +
          '<div class="chat-msg ai">Welcome to Vigil AI Chat. Ask me anything about security, threat analysis, vulnerability assessment, or incident response.</div>' +
        '</div>' +
        '<div class="chat-input-row">' +
          '<input type="text" class="form-input" id="ai-chat-input" placeholder="Ask about security...">' +
          '<button class="btn btn-primary" id="ai-chat-send">Send</button>' +
        '</div>' +
      '</div>';

    var self = this;
    document.getElementById('ai-chat-send').addEventListener('click', function() { self.sendMessage(); });
    document.getElementById('ai-chat-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') { e.preventDefault(); self.sendMessage(); }
    });
    document.getElementById('ai-chat-clear').addEventListener('click', function() {
      self._messages = [];
      document.getElementById('ai-chat-messages').innerHTML = '<div class="chat-msg ai">Chat cleared. How can I help with security?</div>';
    });
  },

  show: function() {
    var input = document.getElementById('ai-chat-input');
    if (input) setTimeout(function() { input.focus(); }, 100);
  },

  hide: function() {},

  sendMessage: function() {
    var input = document.getElementById('ai-chat-input');
    var message = input.value.trim();
    if (!message) return;

    input.value = '';
    this._messages.push({ role: 'user', content: message });

    var container = document.getElementById('ai-chat-messages');
    // Use DOM APIs instead of innerHTML += (prevents re-parsing and potential XSS)
    var userMsg = document.createElement('div');
    userMsg.className = 'chat-msg user';
    userMsg.textContent = message;
    container.appendChild(userMsg);
    var pendingMsg = document.createElement('div');
    pendingMsg.className = 'chat-msg ai';
    pendingMsg.id = 'ai-chat-pending';
    pendingMsg.innerHTML = '<span class="spinner spinner-sm" style="display:inline-block;vertical-align:middle;margin-right:8px;"></span>Thinking...';
    container.appendChild(pendingMsg);
    container.scrollTop = container.scrollHeight;

    var sendBtn = document.getElementById('ai-chat-send');
    sendBtn.disabled = true;

    fetch('/api/brain/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({
        message: message,
        sectionContext: 'ai-chat',
        conversationHistory: this._messages.slice(-10)
      })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      var response = data.response || data.output || data.result || data.text || 'No response from AI.';
      // Append source citations if available
      if (data.sources && data.sources.length) {
        response += '\n\n**Sources:** ' + data.sources.map(function(s) { return '[' + s.id + '] ' + s.title; }).join(', ');
      }
      if (data.fromKB) {
        response = '[Instant KB Answer]\n\n' + response;
      }
      Views['ai-chat']._messages.push({ role: 'assistant', content: response });

      var pending = document.getElementById('ai-chat-pending');
      if (pending) {
        pending.removeAttribute('id');
        pending.innerHTML = Views['ai-chat'].renderMarkdown(response);
      }

      sendBtn.disabled = false;
      container.scrollTop = container.scrollHeight;
    })
    .catch(function() {
      var pending = document.getElementById('ai-chat-pending');
      if (pending) {
        pending.removeAttribute('id');
        pending.innerHTML = '<span style="color:var(--orange);">Failed to get AI response. Check your AI provider configuration.</span>';
      }
      sendBtn.disabled = false;
    });
  },

  renderMarkdown: function(text) {
    if (!text) return '';
    // All user content is escaped FIRST — regex replacements only operate on safe HTML entities
    var html = escapeHtml(text);

    // Code blocks
    html = html.replace(/```([^`]*?)```/g, function(match, code) {
      return '<pre style="background:var(--well);padding:8px;border-radius:4px;margin:6px 0;overflow-x:auto;font-size:var(--font-size-xs);">' + code.trim() + '</pre>';
    });

    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code style="background:var(--well);padding:1px 4px;border-radius:3px;font-size:var(--font-size-xs);">$1</code>');

    // Bold
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

    // Line breaks
    html = html.replace(/\n/g, '<br>');

    // Lists
    html = html.replace(/<br>- /g, '<br>&bull; ');

    return html;
  }
};
