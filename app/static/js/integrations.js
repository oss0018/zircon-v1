/**
 * Zircon FRT — Integrations page
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('integrationsPage', () => ({
    integrations: [],
    services: [],
    loading: false,
    showModal: false,
    showQueryModal: false,
    testResult: null,
    queryResult: null,
    queryLoading: false,
    newIntegration: {
      service_type: '',
      name: '',
      api_key: '',
      rate_limit: 60,
      cache_ttl: 3600,
    },
    queryForm: {
      integration_id: null,
      query: '',
      query_type: 'general',
    },
    editModal: false,
    editIntegration: null,

    queryTypes: ['general', 'email', 'domain', 'ip', 'url', 'hash'],

    async init() {
      await Promise.all([this.loadIntegrations(), this.loadServices()]);
    },

    async loadIntegrations() {
      this.loading = true;
      try {
        this.integrations = await api.get('/integrations/');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.loading = false;
      }
    },

    async loadServices() {
      try {
        this.services = await api.get('/integrations/services');
      } catch (e) {}
    },

    selectService(svc) {
      this.newIntegration.service_type = svc.type;
      this.newIntegration.name = svc.name;
    },

    async createIntegration() {
      try {
        await api.post('/integrations/', this.newIntegration);
        await this.loadIntegrations();
        this.showModal = false;
        this.newIntegration = { service_type: '', name: '', api_key: '', rate_limit: 60, cache_ttl: 3600 };
        showToast('Integration added', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    openEdit(integration) {
      this.editIntegration = {
        ...integration,
        api_key: '',  // Don't expose existing key
      };
      this.editModal = true;
    },

    async saveEdit() {
      try {
        const patch = {
          name: this.editIntegration.name,
          rate_limit: this.editIntegration.rate_limit,
          cache_ttl: this.editIntegration.cache_ttl,
          is_active: this.editIntegration.is_active,
        };
        if (this.editIntegration.api_key) {
          patch.api_key = this.editIntegration.api_key;
        }
        await api.put(`/integrations/${this.editIntegration.id}`, patch);
        await this.loadIntegrations();
        this.editModal = false;
        showToast('Saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async testIntegration(id) {
      this.testResult = null;
      try {
        const result = await api.post(`/integrations/${id}/test`);
        this.testResult = { id, ok: result.ok, data: result };
        showToast(result.ok ? 'API key valid ✓' : 'API key invalid ✗', result.ok ? 'success' : 'error');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    openQuery(id) {
      this.queryForm.integration_id = id;
      this.queryResult = null;
      this.showQueryModal = true;
    },

    async runQuery() {
      this.queryLoading = true;
      this.queryResult = null;
      try {
        const result = await api.post(`/integrations/${this.queryForm.integration_id}/query`, {
          query: this.queryForm.query,
          query_type: this.queryForm.query_type,
        });
        this.queryResult = result;
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.queryLoading = false;
      }
    },

    async deleteIntegration(id) {
      if (!confirm(t('confirm_delete'))) return;
      try {
        await api.delete(`/integrations/${id}`);
        this.integrations = this.integrations.filter(i => i.id !== id);
        showToast('Deleted', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    serviceName(type) {
      const s = this.services.find(s => s.type === type);
      return s ? s.name : type;
    },

    queryResultJson() {
      return formatJSON(this.queryResult);
    },

    notConfigured(svc) {
      return !this.integrations.find(i => i.service_type === svc.type);
    },
  }));
});
