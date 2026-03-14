/* Vigil v1.1 — Toast Notification System */
(function() {
  'use strict';

  var ICONS = {
    success: '&#10003;',
    error: '&#10007;',
    warning: '&#9888;',
    info: '&#8505;'
  };

  function createToast(type, message) {
    var container = document.getElementById('toast-container');
    if (!container) return;

    var toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    toast.innerHTML =
      '<span class="toast-icon">' + (ICONS[type] || '') + '</span>' +
      '<span class="toast-message">' + escapeHtml(message) + '</span>' +
      '<span class="toast-dismiss">&times;</span>';

    container.appendChild(toast);

    // Dismiss click
    toast.querySelector('.toast-dismiss').addEventListener('click', function() {
      removeToast(toast);
    });

    // Auto-dismiss after 4s
    setTimeout(function() {
      removeToast(toast);
    }, 4000);

    // Limit stack to 5
    var toasts = container.querySelectorAll('.toast');
    if (toasts.length > 5) {
      removeToast(toasts[0]);
    }
  }

  function removeToast(toast) {
    if (!toast || !toast.parentNode) return;
    toast.classList.add('toast-exit');
    setTimeout(function() {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 200);
  }

  window.Toast = {
    success: function(msg) { createToast('success', msg); },
    error: function(msg) { createToast('error', msg); },
    warning: function(msg) { createToast('warning', msg); },
    info: function(msg) { createToast('info', msg); }
  };
})();
