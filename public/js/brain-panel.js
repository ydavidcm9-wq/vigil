/* Vigil v1.0 — Brain Context Panel (floating sidebar helper) */
(function() {
  'use strict';

  var panel = null;
  var isOpen = false;
  var currentSection = null;

  function createPanel() {
    // Floating toggle button
    var btn = document.createElement('button');
    btn.id = 'brain-panel-toggle';
    btn.innerHTML = '&#x1f6e1;'; // shield emoji
    btn.title = 'Vigil Brain (Ctrl+Shift+B)';
    btn.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;width:48px;height:48px;border-radius:50%;' +
      'background:var(--accent);color:white;border:none;font-size:22px;cursor:pointer;box-shadow:0 4px 12px rgba(0,0,0,0.3);' +
      'transition:transform 0.2s;display:flex;align-items:center;justify-content:center';
    btn.addEventListener('click', togglePanel);
    btn.addEventListener('mouseenter', function() { btn.style.transform = 'scale(1.1)'; });
    btn.addEventListener('mouseleave', function() { btn.style.transform = 'scale(1)'; });
    document.body.appendChild(btn);

    // Panel
    panel = document.createElement('div');
    panel.id = 'brain-panel';
    panel.style.cssText = 'position:fixed;bottom:80px;right:24px;z-index:9998;width:360px;max-height:500px;' +
      'background:#1a1a1a;border:1px solid rgba(255,107,43,0.3);border-radius:12px;' +
      'box-shadow:0 8px 32px rgba(0,0,0,0.7),0 0 0 1px rgba(0,0,0,0.5);' +
      'display:none;flex-direction:column;overflow:hidden';

    panel.innerHTML =
      '<div style="padding:12px 16px;border-bottom:1px solid rgba(255,255,255,0.1);display:flex;justify-content:space-between;align-items:center;background:#1e1e1e">' +
        '<strong id="brain-panel-title" style="color:#e4e4e7">Vigil Brain</strong>' +
        '<button id="brain-panel-close" style="background:none;border:none;color:#8b8b92;cursor:pointer;font-size:18px">&times;</button>' +
      '</div>' +
      '<div id="brain-panel-body" style="flex:1;overflow-y:auto;padding:12px 16px;font-size:13px;color:#e4e4e7;background:#1a1a1a">' +
        '<div id="brain-panel-context"></div>' +
        '<div id="brain-panel-prompts" style="margin-top:12px"></div>' +
      '</div>' +
      '<div style="padding:8px 12px;border-top:1px solid rgba(255,255,255,0.1);display:flex;gap:6px;background:#1e1e1e">' +
        '<input type="text" id="brain-panel-input" class="form-input" placeholder="Quick question..." style="flex:1;font-size:12px;background:#111;color:#e4e4e7;border:1px solid rgba(255,255,255,0.14);border-radius:6px;padding:6px 10px">' +
        '<button id="brain-panel-send" class="btn btn-primary btn-sm" style="font-size:12px">Ask</button>' +
      '</div>';

    document.body.appendChild(panel);

    document.getElementById('brain-panel-close').addEventListener('click', togglePanel);
    document.getElementById('brain-panel-send').addEventListener('click', sendQuickQuestion);
    document.getElementById('brain-panel-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') { e.preventDefault(); sendQuickQuestion(); }
    });

    // Keyboard shortcut
    document.addEventListener('keydown', function(e) {
      if (e.ctrlKey && e.shiftKey && e.key === 'B') {
        e.preventDefault();
        togglePanel();
      }
    });
  }

  function togglePanel() {
    isOpen = !isOpen;
    if (panel) {
      panel.style.display = isOpen ? 'flex' : 'none';
      if (isOpen) refreshContext();
    }
  }

  function refreshContext() {
    // Get current section from app state
    var section = getCurrentSection();
    if (section === currentSection && isOpen) return;
    currentSection = section;

    var titleEl = document.getElementById('brain-panel-title');
    var contextEl = document.getElementById('brain-panel-context');
    var promptsEl = document.getElementById('brain-panel-prompts');

    if (!section) {
      if (titleEl) titleEl.textContent = 'Vigil Brain';
      if (contextEl) contextEl.innerHTML = '<em>Navigate to a section for contextual help.</em>';
      if (promptsEl) promptsEl.innerHTML = '';
      return;
    }

    fetch('/api/brain/sections/' + encodeURIComponent(section) + '/context', {
      headers: { 'Content-Type': 'application/json' },
    })
    .then(function(r) { return r.json(); })
    .then(function(ctx) {
      if (ctx.error) {
        if (contextEl) contextEl.innerHTML = '<em>No context available for this section.</em>';
        return;
      }

      if (titleEl) titleEl.textContent = ctx.name || section;

      if (contextEl) {
        contextEl.innerHTML =
          '<div style="margin-bottom:8px;color:#a1a1a8">' + escapeHtml(ctx.description || '') + '</div>' +
          '<div style="margin-bottom:8px;color:#e4e4e7"><strong>Capabilities:</strong></div>' +
          '<ul style="margin:0;padding-left:16px;color:#a1a1a8">' +
          (ctx.capabilities || []).map(function(c) { return '<li>' + escapeHtml(c) + '</li>'; }).join('') +
          '</ul>';
      }

      if (promptsEl && ctx.helpPrompts && ctx.helpPrompts.length) {
        promptsEl.innerHTML =
          '<div style="margin-bottom:6px"><strong>Suggested Questions:</strong></div>' +
          ctx.helpPrompts.map(function(p) {
            return '<button class="btn btn-ghost btn-sm" style="font-size:11px;text-align:left;width:100%;margin-bottom:4px;white-space:normal" ' +
              'onclick="document.getElementById(\'brain-panel-input\').value=\'' + p.replace(/'/g, "\\'") + '\';document.getElementById(\'brain-panel-send\').click()">' +
              escapeHtml(p) + '</button>';
          }).join('');
      }
    })
    .catch(function() {
      if (contextEl) contextEl.innerHTML = '<em>Could not load context.</em>';
    });
  }

  function sendQuickQuestion() {
    var input = document.getElementById('brain-panel-input');
    var message = input.value.trim();
    if (!message) return;
    input.value = '';

    var body = document.getElementById('brain-panel-body');

    // Show user message
    var userDiv = document.createElement('div');
    userDiv.style.cssText = 'background:#ff6b2b;color:white;padding:6px 10px;border-radius:8px;margin:8px 0;font-size:12px;max-width:90%;margin-left:auto';
    userDiv.textContent = message;
    body.appendChild(userDiv);

    // Show loading
    var loadingDiv = document.createElement('div');
    loadingDiv.style.cssText = 'padding:6px 10px;font-size:12px;color:#8b8b92';
    loadingDiv.innerHTML = '<em>Thinking...</em>';
    body.appendChild(loadingDiv);
    body.scrollTop = body.scrollHeight;

    fetch('/api/brain/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: message,
        sectionContext: currentSection,
      }),
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      loadingDiv.remove();

      var aiDiv = document.createElement('div');
      aiDiv.style.cssText = 'background:#222;padding:8px 10px;border-radius:8px;margin:8px 0;font-size:12px;color:#e4e4e7';

      var html = escapeHtml(data.response || data.error || 'No response');
      html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
      html = html.replace(/`([^`]+)`/g, '<code style="background:#333;padding:1px 4px;border-radius:3px">$1</code>');
      html = html.replace(/\n/g, '<br>');

      if (data.fromKB) {
        html = '<span style="font-size:10px;color:#4ade80">&#x26a1; KB Answer</span><br>' + html;
      }

      // Action buttons
      if (data.suggestedActions && data.suggestedActions.length) {
        html += '<div style="margin-top:6px;display:flex;gap:4px;flex-wrap:wrap">';
        data.suggestedActions.forEach(function(a) {
          html += '<button class="btn btn-ghost" style="font-size:10px;padding:2px 6px" onclick="App.navigate(\'' + a.targetSection + '\')">' +
            escapeHtml(a.name) + '</button>';
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
      errDiv.style.cssText = 'padding:6px 10px;font-size:12px;color:#ef4444';
      errDiv.textContent = 'Error: ' + err.message;
      body.appendChild(errDiv);
    });
  }

  function getCurrentSection() {
    // Try to read from app state
    if (window.App && window.App.currentView) return window.App.currentView;
    // Fallback: check active sidebar item
    var active = document.querySelector('.nav-item.active');
    if (active) return active.getAttribute('data-view');
    return null;
  }

  function escapeHtml(s) {
    var d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', createPanel);
  } else {
    createPanel();
  }

  // Hook into section changes to refresh context
  var origNavigate = window.App && window.App.navigate;
  var checkInterval = setInterval(function() {
    if (window.App && window.App.navigate && window.App.navigate !== origNavigate) {
      clearInterval(checkInterval);
    }
    // Track section changes for brain context
    var section = getCurrentSection();
    if (section !== currentSection) {
      window._brainLastSection = section;
      if (isOpen) refreshContext();
    }
  }, 2000);

  // Expose for external use
  window.BrainPanel = {
    toggle: togglePanel,
    refresh: refreshContext,
    isOpen: function() { return isOpen; },
  };
})();
