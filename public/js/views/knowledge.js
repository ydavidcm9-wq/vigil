/* Vigil v1.0 — Knowledge Base View */
Views.knowledge = {
  init: function() {
    var el = document.getElementById('view-knowledge');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Knowledge Base</div>' +
        '<button class="btn btn-primary btn-sm" id="kb-add-btn">Add Note</button>' +
      '</div>' +

      '<div class="filter-bar">' +
        '<input type="text" class="form-input" id="kb-search" placeholder="Search articles..." style="max-width:300px;">' +
        '<div class="tab-bar" id="kb-category-tabs" style="border-bottom:none;margin-bottom:0;">' +
          '<div class="tab-item active" data-cat="all">All</div>' +
          '<div class="tab-item" data-cat="vulnerability">Vulnerabilities</div>' +
          '<div class="tab-item" data-cat="technique">Techniques</div>' +
          '<div class="tab-item" data-cat="tool">Tools</div>' +
          '<div class="tab-item" data-cat="procedure">Procedures</div>' +
          '<div class="tab-item" data-cat="note">Notes</div>' +
        '</div>' +
      '</div>' +

      '<div id="kb-articles">' +
        '<div class="loading-state"><div class="spinner"></div><div>Loading knowledge base...</div></div>' +
      '</div>';

    var self = this;
    document.getElementById('kb-search').addEventListener('input', function() { self.filterArticles(); });
    document.getElementById('kb-add-btn').addEventListener('click', function() { self.showAddModal(); });

    document.querySelectorAll('#kb-category-tabs .tab-item').forEach(function(tab) {
      tab.addEventListener('click', function() {
        document.querySelectorAll('#kb-category-tabs .tab-item').forEach(function(t) { t.classList.remove('active'); });
        tab.classList.add('active');
        self._activeCategory = tab.getAttribute('data-cat');
        self.filterArticles();
      });
    });
  },

  _articles: [],
  _activeCategory: 'all',

  show: function() {
    this.loadArticles();
  },

  hide: function() {},

  loadArticles: function() {
    var self = this;
    fetch('/api/knowledge', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        self._articles = data.articles || data || [];
        if (!Array.isArray(self._articles)) self._articles = [];
        self.filterArticles();
      })
      .catch(function() {
        document.getElementById('kb-articles').innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#129504;</div><div class="empty-state-title">Knowledge Base Empty</div><div class="empty-state-desc">Add notes and articles to build your security knowledge base</div></div>';
      });
  },

  filterArticles: function() {
    var search = (document.getElementById('kb-search').value || '').toLowerCase();
    var cat = this._activeCategory;

    var filtered = this._articles.filter(function(a) {
      if (cat !== 'all' && (a.category || '').toLowerCase() !== cat) return false;
      if (search && !(a.title || '').toLowerCase().includes(search) && !(a.content || '').toLowerCase().includes(search)) return false;
      return true;
    });

    this.renderArticles(filtered);
  },

  renderArticles: function(articles) {
    var container = document.getElementById('kb-articles');
    if (articles.length === 0) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#129504;</div><div class="empty-state-title">No Articles Found</div></div>';
      return;
    }

    var html = '<div class="grid-2">';
    articles.forEach(function(a) {
      html += '<div class="glass-card" style="cursor:pointer;" onclick="Views.knowledge.viewArticle(\'' + escapeHtml(a.id || '') + '\')">' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">' +
          '<span class="tag tag-cyan">' + escapeHtml(a.category || 'note') + '</span>' +
          '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-left:auto;">' + timeAgo(a.created_at || a.updated_at) + '</span>' +
        '</div>' +
        '<div style="color:var(--text-primary);font-weight:600;margin-bottom:4px;">' + escapeHtml(a.title || 'Untitled') + '</div>' +
        '<div style="color:var(--text-secondary);font-size:var(--font-size-xs);line-height:1.5;max-height:60px;overflow:hidden;">' + escapeHtml((a.content || a.body || '').substring(0, 150)) + '</div>' +
      '</div>';
    });
    html += '</div>';
    container.innerHTML = html;
  },

  viewArticle: function(id) {
    var article = this._articles.find(function(a) { return a.id == id; });
    if (!article) return;

    Modal.open({
      title: article.title || 'Article',
      body:
        '<div style="margin-bottom:12px;"><span class="tag tag-cyan">' + escapeHtml(article.category || 'note') + '</span></div>' +
        '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.8;white-space:pre-wrap;">' + escapeHtml(article.content || article.body || 'No content') + '</div>',
      size: 'lg'
    });
  },

  showAddModal: function() {
    Modal.open({
      title: 'Add Knowledge Article',
      body:
        '<div class="form-group"><label class="form-label">Title</label><input type="text" class="form-input" id="kb-new-title" placeholder="Article title"></div>' +
        '<div class="form-group"><label class="form-label">Category</label><select class="form-select" id="kb-new-cat"><option value="note">Note</option><option value="vulnerability">Vulnerability</option><option value="technique">Technique</option><option value="tool">Tool</option><option value="procedure">Procedure</option></select></div>' +
        '<div class="form-group"><label class="form-label">Content</label><textarea class="form-textarea" id="kb-new-content" rows="8" placeholder="Write article content..."></textarea></div>',
      footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="kb-save-btn">Save</button>'
    });

    document.getElementById('kb-save-btn').addEventListener('click', function() {
      var title = document.getElementById('kb-new-title').value.trim();
      var category = document.getElementById('kb-new-cat').value;
      var content = document.getElementById('kb-new-content').value.trim();
      if (!title || !content) { Toast.warning('Title and content are required'); return; }

      fetch('/api/knowledge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ title: title, category: category, content: content })
      })
      .then(function() { Modal.close(); Toast.success('Article saved'); Views.knowledge.loadArticles(); })
      .catch(function() { Toast.error('Failed to save article'); });
    });
  }
};
