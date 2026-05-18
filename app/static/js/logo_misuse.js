/**
 * Zircon FRT — Logo & Content Misuse page
 * Alpine.js component: logoMisusePage
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('logoMisusePage', () => ({
    brands: [],
    cases: [],
    stats: { total: 0, by_status: {}, by_match_type: {}, by_brand: {} },
    loading: false,
    searchLoading: false,

    // Filter state
    filterBrandId: '',
    filterStatus: 'all',
    filterMatchType: 'all',
    filterQuery: '',

    // Logo upload state: { [brand_id]: true/false }
    uploadingLogo: {},

    // Search modal
    showSearchModal: false,
    searchBrandId: null,
    searchForm: { search_type: 'text', query: '', max_results: 20 },
    searchResults: [],

    // Add case modal
    showAddModal: false,
    newCase: {
      brand_id: '',
      source_url: '',
      page_title: '',
      match_type: 'logo',
      confidence: 0.5,
      description: '',
    },

    async init() {
      await Promise.all([this.loadBrands(), this.loadCases(), this.loadStats()]);
    },

    async loadBrands() {
      try {
        this.brands = await api.get('/brands/');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async loadCases() {
      this.loading = true;
      try {
        const params = new URLSearchParams();
        if (this.filterBrandId) params.set('brand_id', this.filterBrandId);
        if (this.filterStatus && this.filterStatus !== 'all') params.set('status', this.filterStatus);
        if (this.filterMatchType && this.filterMatchType !== 'all') params.set('match_type', this.filterMatchType);
        if (this.filterQuery) params.set('q', this.filterQuery);
        params.set('limit', '200');
        const qs = params.toString();
        this.cases = await api.get('/logo-misuse/cases' + (qs ? '?' + qs : ''));
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.loading = false;
      }
    },

    async loadStats() {
      try {
        this.stats = await api.get('/logo-misuse/stats');
      } catch (e) {
        // silently ignore stats errors
      }
    },

    brandName(brand_id) {
      const b = this.brands.find(b => b.id === brand_id);
      return b ? b.name : String(brand_id);
    },

    brandHasLogo(brand_id) {
      const b = this.brands.find(b => b.id === brand_id);
      return b && b.logo_path;
    },

    async uploadLogo(brandId, event) {
      const file = event.target.files[0];
      if (!file) return;
      this.uploadingLogo = { ...this.uploadingLogo, [brandId]: true };
      try {
        const fd = new FormData();
        fd.append('file', file);
        await api.upload(`/logo-misuse/brands/${brandId}/logo`, fd);
        await this.loadBrands();
        showToast('Logo uploaded', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.uploadingLogo = { ...this.uploadingLogo, [brandId]: false };
        event.target.value = '';
      }
    },

    async deleteLogo(brandId) {
      if (!confirm(t('confirm_delete'))) return;
      try {
        await api.delete(`/logo-misuse/brands/${brandId}/logo`);
        await this.loadBrands();
        showToast('Logo removed', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    openSearchModal(brandId) {
      this.searchBrandId = brandId;
      const brand = this.brands.find(b => b.id === brandId);
      this.searchForm = { search_type: 'text', query: brand ? brand.name : '', max_results: 20 };
      this.searchResults = [];
      this.showSearchModal = true;
    },

    async triggerSearch() {
      if (!this.searchBrandId) return;
      this.searchLoading = true;
      try {
        const result = await api.post(`/logo-misuse/brands/${this.searchBrandId}/search`, this.searchForm);
        this.searchResults = result.cases || [];
        showToast(`Search complete: ${result.found} new cases found`, 'success');
        await this.loadCases();
        await this.loadStats();
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.searchLoading = false;
      }
    },

    async createCase() {
      try {
        const payload = {
          ...this.newCase,
          brand_id: parseInt(this.newCase.brand_id),
          confidence: parseFloat(this.newCase.confidence),
        };
        await api.post('/logo-misuse/cases', payload);
        this.showAddModal = false;
        this.newCase = { brand_id: '', source_url: '', page_title: '', match_type: 'logo', confidence: 0.5, description: '' };
        await this.loadCases();
        await this.loadStats();
        showToast('Case added', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async updateCaseStatus(caseId, status) {
      try {
        await api.patch(`/logo-misuse/cases/${caseId}`, { status });
        await this.loadCases();
        await this.loadStats();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async deleteCase(caseId) {
      if (!confirm(t('confirm_delete'))) return;
      try {
        await api.delete(`/logo-misuse/cases/${caseId}`);
        this.cases = this.cases.filter(c => c.id !== caseId);
        await this.loadStats();
        showToast('Deleted', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async requestTakedown(caseId) {
      try {
        await api.post(`/logo-misuse/cases/${caseId}/request-takedown`, {});
        await this.loadCases();
        await this.loadStats();
        showToast('Takedown requested', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async dismissCase(caseId) {
      try {
        await api.post(`/logo-misuse/cases/${caseId}/dismiss`, {});
        await this.loadCases();
        await this.loadStats();
        showToast('Case dismissed', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async exportCases(format) {
      try {
        const params = new URLSearchParams({ format });
        if (this.filterBrandId) params.set('brand_id', this.filterBrandId);
        const url = (window.API_BASE || '/api/v1') + '/logo-misuse/cases/export?' + params.toString();
        const token = localStorage.getItem('zircon_token');
        const resp = await fetch(url, { headers: token ? { Authorization: 'Bearer ' + token } : {} });
        if (!resp.ok) throw new Error('Export failed');
        const blob = await resp.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `logo_misuse_cases.${format}`;
        a.click();
        URL.revokeObjectURL(a.href);
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    // ── Helper getters ─────────────────────────────────────────────────────

    statusColor(status) {
      const map = {
        new: 'badge-blue',
        reviewing: 'badge-yellow',
        confirmed: 'badge-red',
        dismissed: 'badge-gray',
        takedown_requested: 'badge-purple',
      };
      return map[status] || 'badge-gray';
    },

    statusLabel(status) {
      const map = {
        new: 'New',
        reviewing: 'Reviewing',
        confirmed: 'Confirmed',
        dismissed: 'Dismissed',
        takedown_requested: 'Takedown Sent',
      };
      return map[status] || status;
    },

    matchTypeIcon(match_type) {
      const map = { logo: '🖼️', text: '📝', domain: '🌐', manual: '✋' };
      return map[match_type] || '❓';
    },

    confidenceColor(conf) {
      if (conf >= 0.7) return 'color:var(--danger)';
      if (conf >= 0.4) return 'color:var(--warning)';
      return 'color:var(--text-muted)';
    },
  }));
});
