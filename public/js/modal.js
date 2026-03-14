/* Vigil v1.1 — Modal System */
(function() {
  'use strict';

  window.Modal = {
    _backdrop: null,

    open: function(opts) {
      this.close();
      var title = opts.title || '';
      var body = opts.body || '';
      var footer = opts.footer || '';
      var size = opts.size || '';
      var sizeClass = size === 'lg' ? ' modal-lg' : size === 'xl' ? ' modal-xl' : '';

      var backdrop = document.createElement('div');
      backdrop.className = 'modal-backdrop';
      backdrop.innerHTML =
        '<div class="modal-dialog' + sizeClass + '">' +
          '<div class="modal-header">' +
            '<div class="modal-title">' + escapeHtml(title) + '</div>' +
            '<div class="modal-close" id="modal-close-btn">&times;</div>' +
          '</div>' +
          '<div class="modal-body">' + body + '</div>' +
          (footer ? '<div class="modal-footer">' + footer + '</div>' : '') +
        '</div>';

      document.body.appendChild(backdrop);
      this._backdrop = backdrop;

      // Close handlers
      var self = this;
      backdrop.querySelector('#modal-close-btn').addEventListener('click', function() {
        self.close();
      });
      backdrop.addEventListener('click', function(e) {
        if (e.target === backdrop) self.close();
      });

      // Escape key
      this._escHandler = function(e) {
        if (e.key === 'Escape') self.close();
      };
      document.addEventListener('keydown', this._escHandler);

      return backdrop;
    },

    close: function() {
      if (this._backdrop) {
        this._backdrop.remove();
        this._backdrop = null;
      }
      if (this._escHandler) {
        document.removeEventListener('keydown', this._escHandler);
        this._escHandler = null;
      }
    },

    confirm: function(opts) {
      var self = this;
      return new Promise(function(resolve) {
        var title = opts.title || 'Confirm';
        var message = opts.message || 'Are you sure?';
        var confirmText = opts.confirmText || 'Confirm';
        var dangerous = opts.dangerous || false;

        var body = '<p style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.6;">' +
          escapeHtml(message) + '</p>';

        var btnClass = dangerous ? 'btn btn-danger' : 'btn btn-primary';
        var footer =
          '<button class="btn btn-ghost" id="modal-cancel-btn">Cancel</button>' +
          '<button class="' + btnClass + '" id="modal-confirm-btn">' + escapeHtml(confirmText) + '</button>';

        var backdrop = self.open({ title: title, body: body, footer: footer });

        var resolved = false;
        function finish(val) {
          if (resolved) return;
          resolved = true;
          self.close();
          resolve(val);
        }

        backdrop.querySelector('#modal-cancel-btn').addEventListener('click', function() {
          finish(false);
        });
        backdrop.querySelector('#modal-confirm-btn').addEventListener('click', function() {
          finish(true);
        });

        // Override close to resolve false
        var origClose = self.close.bind(self);
        self._confirmCloseOverride = function() {
          finish(false);
        };
      });
    },

    loading: function(message) {
      var body = '<div class="loading-state">' +
        '<div class="spinner spinner-lg"></div>' +
        '<div>' + escapeHtml(message || 'Loading...') + '</div>' +
        '</div>';
      this.open({ title: '', body: body });
      // Hide header for loading
      if (this._backdrop) {
        var header = this._backdrop.querySelector('.modal-header');
        if (header) header.style.display = 'none';
      }
    }
  };
})();
