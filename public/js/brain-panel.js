/* Vigil v1.0 — Brain Context Panel (draggable floating helper) */
(function() {
  'use strict';

  var panel = null;
  var btn = null;
  var isOpen = false;
  var currentSection = null;

  function createPanel() {
    // ── Toggle Button ─────────────────────────────────────
    btn = document.createElement('button');
    btn.id = 'brain-panel-toggle';
    btn.innerHTML = '&#x1f6e1;';
    btn.title = 'Vigil Brain (Ctrl+Shift+B)';
    btn.style.cssText =
      'position:fixed;bottom:36px;right:16px;z-index:9999;width:40px;height:40px;border-radius:50%;' +
      'background:#ff6b2b;color:white;border:2px solid #1a1a1a;font-size:18px;cursor:grab;' +
      'box-shadow:0 2px 8px rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;' +
      'touch-action:none';
    // Make button draggable — click vs drag distinguished by distance moved
    (function() {
      var dragging = false, moved = false, offX = 0, offY = 0, startX = 0, startY = 0;
      btn.addEventListener('mousedown', function(e) {
        dragging = true; moved = false;
        var r = btn.getBoundingClientRect();
        offX = e.clientX - r.left; offY = e.clientY - r.top;
        startX = e.clientX; startY = e.clientY;
        // Convert to top/left
        btn.style.left = r.left + 'px'; btn.style.top = r.top + 'px';
        btn.style.right = 'auto'; btn.style.bottom = 'auto';
        btn.style.cursor = 'grabbing';
        e.preventDefault();
      });
      document.addEventListener('mousemove', function(e) {
        if (!dragging) return;
        var dx = e.clientX - startX, dy = e.clientY - startY;
        if (Math.abs(dx) > 3 || Math.abs(dy) > 3) moved = true;
        var nx = e.clientX - offX, ny = e.clientY - offY;
        nx = Math.max(0, Math.min(nx, window.innerWidth - 44));
        ny = Math.max(0, Math.min(ny, window.innerHeight - 44));
        btn.style.left = nx + 'px'; btn.style.top = ny + 'px';
      });
      document.addEventListener('mouseup', function() {
        if (!dragging) return;
        dragging = false;
        btn.style.cursor = 'grab';
        if (!moved) togglePanel(); // click — didn't drag
      });
    })();
    document.body.appendChild(btn);

    // ── Panel ─────────────────────────────────────────────
    panel = document.createElement('div');
    panel.id = 'brain-panel';
    panel.style.cssText =
      'position:fixed;top:auto;left:auto;bottom:84px;right:16px;z-index:9998;width:340px;height:420px;' +
      'background:#141414;border:1px solid rgba(255,107,43,0.35);border-radius:10px;' +
      'box-shadow:0 8px 32px rgba(0,0,0,0.8),0 0 0 1px rgba(0,0,0,0.6);' +
      'display:none;flex-direction:column;overflow:hidden';

    panel.innerHTML =
      '<div id="brain-panel-header" style="padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.1);' +
        'display:flex;justify-content:space-between;align-items:center;background:#1a1a1a;cursor:grab;user-select:none;flex-shrink:0">' +
        '<strong id="brain-panel-title" style="color:#e4e4e7;font-size:12px;pointer-events:none">&#x1f6e1; Vigil Brain</strong>' +
        '<button id="brain-panel-close" style="background:none;border:none;color:#666;cursor:pointer;font-size:16px;line-height:1">&times;</button>' +
      '</div>' +
      '<div id="brain-panel-body" style="flex:1;overflow-y:auto;padding:10px 12px;font-size:12px;color:#ccc;background:#141414">' +
        '<div id="brain-panel-context"></div>' +
        '<div id="brain-panel-prompts" style="margin-top:10px"></div>' +
      '</div>' +
      '<div style="padding:6px 10px;border-top:1px solid rgba(255,255,255,0.1);display:flex;gap:6px;background:#1a1a1a;flex-shrink:0">' +
        '<input type="text" id="brain-panel-input" placeholder="Quick question..." ' +
          'style="flex:1;font-size:11px;background:#0e0e0e;color:#e4e4e7;border:1px solid rgba(255,255,255,0.12);border-radius:5px;padding:5px 8px;outline:none;font-family:inherit">' +
        '<button id="brain-panel-send" class="btn btn-primary btn-sm" style="font-size:11px;padding:4px 10px">Ask</button>' +
      '</div>';

    document.body.appendChild(panel);

    document.getElementById('brain-panel-close').addEventListener('click', togglePanel);
    document.getElementById('brain-panel-send').addEventListener('click', sendQuickQuestion);
    document.getElementById('brain-panel-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') { e.preventDefault(); sendQuickQuestion(); }
    });

    // ── Drag via header ───────────────────────────────────
    makeDraggable(panel, document.getElementById('brain-panel-header'));

    // Keyboard shortcut
    document.addEventListener('keydown', function(e) {
      if (e.ctrlKey && e.shiftKey && e.key === 'B') {
        e.preventDefault();
        togglePanel();
      }
    });
  }

  /**
   * Make an element draggable by a handle.
   * Converts position from bottom/right to top/left on first drag.
   */
  function makeDraggable(el, handle) {
    var dragging = false;
    var offX = 0, offY = 0;

    handle.addEventListener('mousedown', function(e) {
      // Don't drag if clicking the close button
      if (e.target.tagName === 'BUTTON') return;
      dragging = true;
      handle.style.cursor = 'grabbing';
      var rect = el.getBoundingClientRect();
      offX = e.clientX - rect.left;
      offY = e.clientY - rect.top;
      // Convert to top/left positioning immediately
      el.style.left = rect.left + 'px';
      el.style.top = rect.top + 'px';
      el.style.right = 'auto';
      el.style.bottom = 'auto';
      e.preventDefault();
    });

    document.addEventListener('mousemove', function(e) {
      if (!dragging) return;
      var nx = e.clientX - offX;
      var ny = e.clientY - offY;
      // Keep within viewport
      var maxX = window.innerWidth - el.offsetWidth;
      var maxY = window.innerHeight - el.offsetHeight;
      nx = Math.max(0, Math.min(nx, maxX));
      ny = Math.max(0, Math.min(ny, maxY));
      el.style.left = nx + 'px';
      el.style.top = ny + 'px';
    });

    document.addEventListener('mouseup', function() {
      if (dragging) {
        dragging = false;
        handle.style.cursor = 'grab';
      }
    });
  }

  function togglePanel() {
    isOpen = !isOpen;
    if (panel) {
      if (isOpen) {
        panel.style.display = 'flex';
        // Reset position if panel was never dragged (still has right/bottom)
        if (panel.style.right !== 'auto') {
          panel.style.bottom = '84px';
          panel.style.right = '16px';
        }
        refreshContext();
      } else {
        panel.style.display = 'none';
      }
    }
  }

  // ── Context ───────────────────────────────────────────────
  function refreshContext() {
    var section = getCurrentSection();
    if (section === currentSection && isOpen) return;
    currentSection = section;

    var titleEl = document.getElementById('brain-panel-title');
    var contextEl = document.getElementById('brain-panel-context');
    var promptsEl = document.getElementById('brain-panel-prompts');

    if (!section) {
      if (titleEl) titleEl.innerHTML = '&#x1f6e1; Vigil Brain';
      if (contextEl) contextEl.innerHTML = '<em style="color:#666">Navigate to a section for contextual help.</em>';
      if (promptsEl) promptsEl.innerHTML = '';
      return;
    }

    fetch('/api/brain/sections/' + encodeURIComponent(section) + '/context', {
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
    })
    .then(function(r) { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(function(ctx) {
      if (ctx.error) {
        if (contextEl) contextEl.innerHTML = '<em style="color:#666">No context for this section.</em>';
        return;
      }

      if (titleEl) titleEl.innerHTML = '&#x1f6e1; ' + esc(ctx.name || section);

      if (contextEl) {
        contextEl.innerHTML =
          '<div style="margin-bottom:8px;color:#999;line-height:1.5">' + esc(ctx.description || '') + '</div>' +
          '<div style="margin-bottom:4px;color:#ccc;font-weight:600">Capabilities:</div>' +
          '<ul style="margin:0 0 0 14px;padding:0;color:#999;line-height:1.6">' +
          (ctx.capabilities || []).map(function(c) { return '<li style="list-style:disc">' + esc(c) + '</li>'; }).join('') +
          '</ul>';
      }

      if (promptsEl && ctx.helpPrompts && ctx.helpPrompts.length) {
        promptsEl.innerHTML =
          '<div style="margin-bottom:4px;color:#ccc;font-weight:600">Try asking:</div>' +
          ctx.helpPrompts.map(function(p) {
            return '<div style="padding:4px 8px;margin:3px 0;background:#1e1e1e;border:1px solid rgba(255,255,255,0.08);' +
              'border-radius:5px;cursor:pointer;font-size:11px;color:#aaa" ' +
              'onmouseenter="this.style.background=\'#252525\';this.style.color=\'#e4e4e7\'" ' +
              'onmouseleave="this.style.background=\'#1e1e1e\';this.style.color=\'#aaa\'" ' +
              'onclick="document.getElementById(\'brain-panel-input\').value=\'' + p.replace(/'/g, "\\'") +
              '\';document.getElementById(\'brain-panel-send\').click()">' +
              esc(p) + '</div>';
          }).join('');
      }
    })
    .catch(function() {
      if (contextEl) contextEl.innerHTML = '<em style="color:#666">Could not load context.</em>';
    });
  }

  // ── Quick Question ────────────────────────────────────────
  function sendQuickQuestion() {
    var input = document.getElementById('brain-panel-input');
    var message = input.value.trim();
    if (!message) return;
    input.value = '';

    var body = document.getElementById('brain-panel-body');

    var userDiv = document.createElement('div');
    userDiv.style.cssText = 'background:#ff6b2b;color:white;padding:5px 8px;border-radius:6px;margin:6px 0;font-size:11px;max-width:85%;margin-left:auto;word-wrap:break-word';
    userDiv.textContent = message;
    body.appendChild(userDiv);

    var loadingDiv = document.createElement('div');
    loadingDiv.style.cssText = 'padding:4px 8px;font-size:11px;color:#666';
    loadingDiv.innerHTML = '<em>Thinking...</em>';
    body.appendChild(loadingDiv);
    body.scrollTop = body.scrollHeight;

    fetch('/api/brain/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ message: message, sectionContext: currentSection }),
    })
    .then(function(r) { if (!r.ok) throw new Error('Server returned ' + r.status); return r.json(); })
    .then(function(data) {
      loadingDiv.remove();

      var aiDiv = document.createElement('div');
      aiDiv.style.cssText = 'background:#1e1e1e;padding:6px 8px;border-radius:6px;margin:6px 0;font-size:11px;color:#ccc;line-height:1.5;word-wrap:break-word;border:1px solid rgba(255,255,255,0.06)';

      var html = esc(data.response || data.error || 'No response');
      html = html.replace(/\*\*([^*]+)\*\*/g, '<strong style="color:#e4e4e7">$1</strong>');
      html = html.replace(/`([^`]+)`/g, '<code style="background:#2a2a2a;padding:1px 3px;border-radius:2px;font-size:10px">$1</code>');
      html = html.replace(/\n/g, '<br>');

      if (data.fromKB) {
        html = '<span style="font-size:9px;color:#4ade80;font-weight:600">&#x26a1; KB Answer</span><br>' + html;
      }

      if (data.suggestedActions && data.suggestedActions.length) {
        html += '<div style="margin-top:5px;display:flex;gap:3px;flex-wrap:wrap">';
        data.suggestedActions.forEach(function(a) {
          html += '<span style="font-size:9px;padding:2px 5px;background:#252525;border:1px solid rgba(255,107,43,0.2);border-radius:3px;color:#ff6b2b;cursor:pointer" ' +
            'onclick="App.navigate(\'' + a.targetSection + '\')">' + esc(a.name) + '</span>';
        });
        html += '</div>';
      }

      aiDiv.innerHTML = html;
      body.appendChild(aiDiv);
      body.scrollTop = body.scrollHeight;
    })
    .catch(function(err) {
      loadingDiv.remove();
      var errDiv = document.createElement('div');
      errDiv.style.cssText = 'padding:4px 8px;font-size:11px;color:#ef4444';
      errDiv.textContent = 'Error: ' + err.message;
      body.appendChild(errDiv);
    });
  }

  function getCurrentSection() {
    if (window.App && window.App.currentView) return window.App.currentView;
    var active = document.querySelector('.nav-item.active');
    if (active) return active.getAttribute('data-view');
    return null;
  }

  function esc(s) {
    var d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  }

  // Initialize
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', createPanel);
  } else {
    createPanel();
  }

  // Track section changes
  setInterval(function() {
    var section = getCurrentSection();
    if (section !== currentSection) {
      window._brainLastSection = section;
      if (isOpen) refreshContext();
    }
  }, 2000);

  window.BrainPanel = {
    toggle: togglePanel,
    refresh: refreshContext,
    isOpen: function() { return isOpen; },
  };
})();
