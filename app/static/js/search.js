/**
 * Zircon FRT — Search page (v2 with grep results)
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('searchPage', () => ({
    query: '',
    source: 'local',
    queryType: 'general',
    caseSensitive: false,
    selectedIntegrations: [],
    integrations: [],
    results: [],      // OSINT results
    grepMatches: [],  // local grep matches
    loading: false,
    history: [],
    historyLoading: false,
    showHistory: false,
    templates: [],
    showTemplates: false,
    showSaveModal: false,
    templateName: '',
    expandedResult: null,
    grepTotal: 0,
    grepFilesScanned: 0,
    grepLimit: 200,
    resultTab: 'grep',  // 'grep' or 'osint'

    queryTypes: ['general', 'email', 'domain', 'ip', 'url', 'hash'],

    async init() {
      await this.loadIntegrations();
      await this.loadHistory();
    },

    async loadIntegrations() {
      try {
        const list = await api.get('/integrations/');
        this.integrations = list.filter(i => i.is_active);
      } catch (e) {}
    },

    async loadHistory() {
      this.historyLoading = true;
      try {
        this.history = await api.get('/search/history?limit=20');
      } catch (e) {} finally {
        this.historyLoading = false;
      }
    },

    async loadTemplates() {
      try {
        this.templates = await api.get('/search/templates');
        this.showTemplates = true;
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async runSearch() {
      if (!this.query.trim()) return;
      this.loading = true;
      this.grepMatches = [];
      this.results = [];

      try {
        // Always run local grep
        if (this.source === 'local' || this.source === 'all') {
          showToast('Scanning files...', 'info');
          const grepData = await api.post('/search/grep', {
            query: this.query,
            limit: this.grepLimit,
            case_sensitive: this.caseSensitive,
          });
          this.grepMatches = grepData.matches || [];
          this.grepTotal = grepData.total || 0;
          this.grepFilesScanned = grepData.files_scanned || 0;
          this.resultTab = 'grep';
          showToast(`Found ${this.grepTotal} matches in ${this.grepFilesScanned} files`, 'success');
        }

        // OSINT if selected
        if ((this.source === 'osint' || this.source === 'all') && this.selectedIntegrations.length > 0) {
          const data = await api.post('/search/', {
            query: this.query,
            source: 'osint',
            integrations: this.selectedIntegrations,
            query_type: this.queryType,
            limit: 50,
          });
          this.results = data.results || [];
          if (this.source === 'osint') this.resultTab = 'osint';
        }

        await this.loadHistory();
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.loading = false;
      }
    },

    highlight(text) {
      if (!text || !this.query) return escapeHtml(text || '');
      const flags = this.caseSensitive ? 'g' : 'gi';
      // Escape the raw text first to prevent XSS, then search using the
      // original query (not HTML-escaped) against the escaped text so that
      // the matched portion `m` is already safe HTML and can be wrapped in <mark>.
      const safeText = escapeHtml(text);
      const safeQueryEscaped = this.query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      return safeText.replace(new RegExp(safeQueryEscaped, flags), m => `<mark class="highlight">${m}</mark>`);
    },

    copyLine(text) {
      navigator.clipboard.writeText(text).then(() => showToast('Copied!', 'success'));
    },

    exportResults() {
      const lines = this.grepMatches.map(m => `${m.file}:${m.line}: ${m.text}`);
      const content = lines.join('\n');
      const blob = new Blob([content], {type: 'text/plain'});
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `zircon_search_${this.query.replace(/[^a-z0-9]/gi,'_')}.txt`;
      a.click();
    },

    copyAllResults() {
      const lines = this.grepMatches.map(m => m.text);
      navigator.clipboard.writeText(lines.join('\n')).then(() =>
        showToast(`Copied ${lines.length} lines`, 'success')
      );
    },

    async saveTemplate() {
      if (!this.templateName) return;
      try {
        await api.post('/search/templates', {
          name: this.templateName,
          query: this.query,
          filters_json: JSON.stringify({ source: this.source, query_type: this.queryType }),
        });
        this.showSaveModal = false;
        this.templateName = '';
        showToast('Template saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async deleteTemplate(id) {
      if (!confirm(t('confirm_delete'))) return;
      try {
        await api.delete(`/search/templates/${id}`);
        this.templates = this.templates.filter(t => t.id !== id);
        showToast('Deleted', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    loadTemplate(tmpl) {
      this.query = tmpl.query;
      try {
        const f = JSON.parse(tmpl.filters_json);
        this.source = f.source || 'local';
        this.queryType = f.query_type || 'general';
      } catch {}
      this.showTemplates = false;
    },

    useHistoryQuery(item) {
      this.query = item.query;
      this.source = item.source || 'local';
    },

    toggleIntegration(id) {
      const idx = this.selectedIntegrations.indexOf(id);
      if (idx >= 0) {
        this.selectedIntegrations.splice(idx, 1);
      } else {
        this.selectedIntegrations.push(id);
      }
    },

    toggleExpand(i) {
      this.expandedResult = this.expandedResult === i ? null : i;
    },

    resultJson(result) {
      return formatJSON(result.data);
    },

    hasError(result) {
      return result.data && result.data.error;
    },

    fileGroups() {
      // Group grep matches by file for display
      const groups = {};
      for (const m of this.grepMatches) {
        if (!groups[m.file]) groups[m.file] = { name: m.file, path: m.path, lines: [] };
        groups[m.file].lines.push(m);
      }
      return Object.values(groups);
    },
  }));
});
