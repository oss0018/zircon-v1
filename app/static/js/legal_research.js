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
    manualRegistries: [
      {
        code: 'cyprus',
        url: 'https://efiling.drcor.mcit.gov.cy/DrcorPublic/SearchForm.aspx?sc=0&cultureInfo=en-AU',
        form: { name: '', company_number: '', status: '', incorporated_on: '', registered_address: '' },
        result: null, loading: false, error: '',
      },
      {
        code: 'curacao',
        url: 'https://www.curacaochamberofcommerce.com/registry-services/registry-search/',
        form: { name: '', company_number: '', status: '', incorporated_on: '', registered_address: '' },
        result: null, loading: false, error: '',
      },
    ],
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
    nazkForm: { query: '', workplace_edrpou: '' },
    nazkSearch: null,
    nazkResult: null,
    nazkLoading: false,
    nazkError: '',
    nazkWatches: [],
    nazkWatchError: '',
    nazkWatchMessage: '',
    nazkChangesWatch: null,
    nazkChanges: [],
    nazkChangesOffset: 0,
    nazkChangesLoading: false,
    uaCompanyQuery: '',
    uaCompanyOffset: 0,
    uaCompanySearchQuery: '',
    uaCompanyResult: null,
    uaCompanyStatus: null,
    uaCompanyError: '',
    uaCompanyBusy: false,
    uaSnapshotDate: '',
    uaSnapshotFile: null,
    uaCompanyWatches: [],
    uaWatchChanges: null,
    uaWatchChangesId: null,
    uaWatchChangesOffset: 0,

    init() {},

    async prepareManualRecord(registry) {
      const body = Object.fromEntries(Object.entries(registry.form).map(
        ([key, value]) => [key, value.trim() || null],
      ));
      if (!body.name && !body.company_number) {
        registry.error = t(registry.code + '_identity_required');
        return;
      }
      registry.loading = true;
      registry.result = null;
      registry.error = '';
      try {
        registry.result = await api.post('/entity-registry/' + registry.code, body);
      } catch (error) {
        registry.error = error.message || t('request_failed');
      } finally {
        registry.loading = false;
      }
    },

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

    async searchNazk(page = 1, useSaved = false) {
      if (!useSaved) {
        const query = this.nazkForm.query.trim();
        const workplace_edrpou = this.nazkForm.workplace_edrpou.trim();
        if ((!query && !workplace_edrpou) || (query && query.length < 3) ||
            (workplace_edrpou && !/^[0-9]{8}$/.test(workplace_edrpou))) {
          this.nazkError = this.t('nazk_invalid_search');
          return;
        }
        this.nazkSearch = { query: query || null, workplace_edrpou: workplace_edrpou || null };
      }
      if (!this.nazkSearch || this.nazkLoading) return;
      this.nazkLoading = true;
      this.nazkError = '';
      this.nazkResult = null;
      try {
        this.nazkResult = await api.post('/nazk/search', { ...this.nazkSearch, page });
      } catch (error) {
        this.nazkError = error.message || this.t('request_failed');
      } finally {
        this.nazkLoading = false;
      }
    },

    async loadNazkWatches() {
      try {
        this.nazkWatches = await api.get('/nazk/watches');
        this.nazkWatchError = '';
      } catch (error) {
        this.nazkWatchError = error.message || this.t('request_failed');
      }
    },

    async createNazkWatch(target) {
      this.nazkWatchError = '';
      this.nazkWatchMessage = '';
      try {
        await api.post('/nazk/watches', target);
        this.nazkWatchMessage = this.t('nazk_watch_created');
        await this.loadNazkWatches();
      } catch (error) {
        this.nazkWatchError = error.message || this.t('request_failed');
      }
    },

    async deleteNazkWatch(watch) {
      this.nazkWatchError = '';
      try {
        await api.delete('/nazk/watches/' + watch.id);
        if (this.nazkChangesWatch === watch.id) this.nazkChangesWatch = null;
        await this.loadNazkWatches();
      } catch (error) {
        this.nazkWatchError = error.message || this.t('request_failed');
      }
    },

    async viewNazkWatch(watch) {
      this.nazkSearch = { query: null, workplace_edrpou: watch.workplace_edrpou,
                          declarant_id: watch.declarant_id };
      await this.searchNazk(1, true);
    },

    async viewNazkChanges(watch, offset = 0) {
      if (this.nazkChangesLoading) return;
      this.nazkChangesLoading = true;
      this.nazkWatchError = '';
      try {
        this.nazkChanges = await api.get('/nazk/watches/' + watch.id + '/changes?offset=' + offset);
        this.nazkChangesWatch = watch.id;
        this.nazkChangesOffset = offset;
      } catch (error) {
        this.nazkWatchError = error.message || this.t('request_failed');
      } finally {
        this.nazkChangesLoading = false;
      }
    },

    async loadUaCompanyStatus() {
      try {
        this.uaCompanyStatus = await api.get('/ukraine-registry/status');
        this.uaCompanyWatches = await api.get('/ukraine-registry/watches');
      } catch (error) {
        this.uaCompanyError = error.message || this.t('request_failed');
      }
    },

    async watchUaCompany(company) {
      try {
        await api.post('/ukraine-registry/watches/' + company.edrpou);
        this.uaCompanyError = '';
        await this.loadUaCompanyStatus();
      } catch (error) {
        this.uaCompanyError = error.message || this.t('request_failed');
      }
    },

    async removeUaWatch(watch) {
      try {
        await api.delete('/ukraine-registry/watches/' + watch.id);
        if (this.uaWatchChangesId === watch.id) this.uaWatchChangesId = null;
        this.uaCompanyError = '';
        await this.loadUaCompanyStatus();
      } catch (error) {
        this.uaCompanyError = error.message || this.t('request_failed');
      }
    },

    async viewUaChanges(watch, offset = 0) {
      try {
        this.uaWatchChanges = await api.get('/ukraine-registry/watches/' + watch.id + '/changes?offset=' + offset);
        this.uaWatchChangesId = watch.id;
        this.uaWatchChangesOffset = offset;
        this.uaCompanyError = '';
      } catch (error) {
        this.uaCompanyError = error.message || this.t('request_failed');
      }
    },

    uaChangeValue(value) {
      return Array.isArray(value) ? value.join('; ') || '—' : value || '—';
    },

    async toggleUaSnapshot() {
      this.uaCompanyError = '';
      try {
        await api.put('/ukraine-registry/enabled?enabled=' + !this.uaCompanyStatus.enabled);
        this.uaCompanyResult = null;
        await this.loadUaCompanyStatus();
      } catch (error) {
        this.uaCompanyError = error.message || this.t('request_failed');
      }
    },

    async uploadUaSnapshot() {
      if (!this.uaSnapshotFile || !this.uaSnapshotDate || this.uaCompanyBusy) return;
      this.uaCompanyBusy = true;
      this.uaCompanyError = '';
      try {
        const form = new FormData();
        form.append('file', this.uaSnapshotFile);
        form.append('snapshot_date', this.uaSnapshotDate);
        await api.upload('/ukraine-registry/snapshot', form);
        this.uaCompanyResult = null;
        this.uaWatchChangesId = null;
        await this.loadUaCompanyStatus();
      } catch (error) {
        this.uaCompanyError = error.message || this.t('request_failed');
      } finally {
        this.uaCompanyBusy = false;
      }
    },

    async searchUaCompanies(offset = 0, useSaved = false) {
      if (this.uaCompanyBusy) return;
      if (!useSaved) this.uaCompanySearchQuery = this.uaCompanyQuery.trim();
      if (this.uaCompanySearchQuery.length < 2) {
        this.uaCompanyError = this.t('ua_company_query_error');
        return;
      }
      this.uaCompanyError = '';
      this.uaCompanyBusy = true;
      try {
        this.uaCompanyResult = await api.get('/ukraine-registry/companies?q=' +
          encodeURIComponent(this.uaCompanySearchQuery) + '&offset=' + offset);
        this.uaCompanyOffset = offset;
      } catch (error) {
        this.uaCompanyResult = null;
        this.uaCompanyError = error.message || this.t('request_failed');
      } finally {
        this.uaCompanyBusy = false;
      }
    },
  }));
});
