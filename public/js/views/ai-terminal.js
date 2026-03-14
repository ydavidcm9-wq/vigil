/* Vigil v1.1 — AI Terminal View */
Views['ai-terminal'] = {
  _history: [],
  _historyIndex: -1,
  _running: false,

  init: function() {
    var el = document.getElementById('view-ai-terminal');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">AI Terminal</div>' +
        '<button class="btn btn-ghost btn-sm" id="ai-term-clear">Clear</button>' +
      '</div>' +

      '<div class="terminal-container">' +
        '<div class="terminal-output" id="ai-term-output" style="min-height:400px;max-height:600px;">' +
          '<span class="cmd-prompt">vigil@security</span> <span class="cmd-output">~ AI Terminal ready. Type a prompt and press Enter.</span>\n' +
        '</div>' +
        '<div class="terminal-input-line">' +
          '<span class="terminal-prompt-symbol">&#9654;</span>' +
          '<input type="text" class="terminal-input" id="ai-term-input" placeholder="Ask the AI anything about security..." autocomplete="off">' +
        '</div>' +
      '</div>' +

      '<div style="margin-top:12px;color:var(--text-tertiary);font-size:var(--font-size-xs);">' +
        'Uses your configured AI provider (Claude CLI / Codex). Commands are sent via Socket.IO.' +
      '</div>';

    var self = this;
    var input = document.getElementById('ai-term-input');
    input.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        self.sendCommand(input.value.trim());
        input.value = '';
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (self._historyIndex < self._history.length - 1) {
          self._historyIndex++;
          input.value = self._history[self._history.length - 1 - self._historyIndex] || '';
        }
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (self._historyIndex > 0) {
          self._historyIndex--;
          input.value = self._history[self._history.length - 1 - self._historyIndex] || '';
        } else {
          self._historyIndex = -1;
          input.value = '';
        }
      }
    });

    document.getElementById('ai-term-clear').addEventListener('click', function() {
      document.getElementById('ai-term-output').innerHTML = '<span class="cmd-prompt">vigil@security</span> <span class="cmd-output">~ Terminal cleared.</span>\n';
    });
  },

  show: function() {
    var input = document.getElementById('ai-term-input');
    if (input) setTimeout(function() { input.focus(); }, 100);
  },

  hide: function() {},

  sendCommand: function(prompt) {
    if (!prompt || this._running) return;

    this._history.push(prompt);
    this._historyIndex = -1;

    var output = document.getElementById('ai-term-output');
    output.innerHTML += '\n<span class="cmd-prompt">&#9654; </span><span style="color:var(--text-primary);">' + escapeHtml(prompt) + '</span>\n';
    output.innerHTML += '<span class="cmd-output" id="ai-term-stream"></span>';
    output.scrollTop = output.scrollHeight;

    this._running = true;
    document.getElementById('ai-term-input').disabled = true;

    if (window._socket) {
      window._socket.emit('claude_run', { prompt: prompt });
    } else {
      // Fallback to HTTP
      fetch('/api/claude/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ prompt: prompt })
      })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        Views['ai-terminal'].appendOutput(data.output || data.result || data.text || 'No response.');
        Views['ai-terminal'].onDone();
      })
      .catch(function() {
        Views['ai-terminal'].appendOutput('Error: AI command failed.');
        Views['ai-terminal'].onDone();
      });
    }
  },

  appendOutput: function(text) {
    var stream = document.getElementById('ai-term-stream');
    var output = document.getElementById('ai-term-output');
    if (stream) {
      stream.textContent += text;
    } else {
      output.innerHTML += '<span class="cmd-output">' + escapeHtml(text) + '</span>';
    }
    output.scrollTop = output.scrollHeight;
  },

  onDone: function() {
    this._running = false;
    var input = document.getElementById('ai-term-input');
    if (input) {
      input.disabled = false;
      input.focus();
    }
    var output = document.getElementById('ai-term-output');
    output.innerHTML += '\n';
    // Remove the stream element id so next command creates a new one
    var stream = document.getElementById('ai-term-stream');
    if (stream) stream.removeAttribute('id');
    output.scrollTop = output.scrollHeight;
  }
};
