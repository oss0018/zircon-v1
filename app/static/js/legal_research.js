document.addEventListener('alpine:init', () => {
  Alpine.data('legalResearchPage', () => ({
    activeTab: 'entities',
    entityForm: {
      query: '',
      uk_company_number: '',
      delaware_name: '',
      delaware_entity_number: '',
      delaware_status: '',
      delaware_incorporated_on: '',
      delaware_registered_address: '',
    },
    entityResult: null,
    entityLoading: false,
    entityError: '',
    caseForm: { query: '', limit: 5 },
    caseResult: null,
    caseLoading: false,
    caseError: '',
    regulatorForm: {
      query: '',
      limit: 5,
      fca_entity_name: '',
      fca_reference: '',
      fca_action_type: '',
      fca_date: '',
      fca_summary: '',
      fca_source_url: '',
    },
    regulatorResult: null,
    regulatorLoading: false,
    regulatorError: '',

    init() {},

    async compareEntities() {
      const body = Object.fromEntries(
        Object.entries(this.entityForm).map(([key, value]) => [
          key,
          typeof value === 'string' ? value.trim() || null : value,
        ]),
      );
      if (!body.query && !body.uk_company_number) {
        this.entityError = t('enter_lookup');
        return;
      }

      this.entityLoading = true;
      this.entityError = '';
      this.entityResult = null;
      try {
        this.entityResult = await api.post('/entity-registry/compare', body);
      } catch (error) {
        this.entityError = error.message || t('request_failed');
      } finally {
        this.entityLoading = false;
      }
    },

    async searchCases() {
      const query = this.caseForm.query.trim();
      if (!query) return;
      this.caseLoading = true;
      this.caseError = '';
      this.caseResult = null;
      try {
        this.caseResult = await api.post('/case-law/search', {
          query,
          limit: this.caseForm.limit,
        });
      } catch (error) {
        this.caseError = error.message || t('request_failed');
      } finally {
        this.caseLoading = false;
      }
    },

    async searchRegulators() {
      const body = Object.fromEntries(
        Object.entries(this.regulatorForm).map(([key, value]) => [
          key,
          typeof value === 'string' ? value.trim() || null : value,
        ]),
      );
      if (!body.query) return;
      this.regulatorLoading = true;
      this.regulatorError = '';
      this.regulatorResult = null;
      try {
        this.regulatorResult = await api.post('/regulators/search', body);
      } catch (error) {
        this.regulatorError = error.message || t('request_failed');
      } finally {
        this.regulatorLoading = false;
      }
    },
  }));
});
