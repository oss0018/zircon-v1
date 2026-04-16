/**
 * Zircon FRT — Search page
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('searchPage', () => ({
    query: '',
    source: 'local',
    queryType: 'general',
    selectedIntegrations: [],
    integrations: [],
    results: [],
    loading: false,
    history: [],
    historyLoading: false,
    showHistory: false,
    templates: [],
    showTemplates: false,
    showSaveModal: false,
    templateName: '',
    expandedResult: null,

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
      this.results = [];
      try {
        const payload = {
          query: this.query,
          source: this.source,
          integrations: this.selectedIntegrations,
          query_type: this.queryType,
          limit: 50,
        };
        const data = await api.post('/search/', payload);
        this.results = data.results || [];
        await this.loadHistory();
        showToast(`Found ${data.total} results in ${data.duration_ms}ms`, 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.loading = false;
      }
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
  }));
});
