/**
 * Zircon FRT — Infrastructure Intelligence page
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('infraIntelApp', () => ({
    // Form
    target: '',
    targetType: 'domain',
    selectedModules: ['dns', 'network', 'cert', 'cloud'],

    // Investigations list
    investigations: [],
    investigationsLoading: false,
    investigationsTotal: 0,
    investigationsPage: 0,
    investigationsPageSize: 20,

    // Detail view
    selectedInvestigation: null,
    investigationLoading: false,
    findings: [],
    summaryData: null,
    evidenceFindingIds: [],
    evidenceLoading: false,
    savedEvidence: [],
    savedEvidenceOffset: 0,
    evidenceEvents: null,
    evidenceEventsOffset: 0,
    evidenceEventsPackage: null,

    async saveEvidence() {
      if (!this.selectedInvestigation || !this.evidenceFindingIds.length || this.evidenceFindingIds.length > 200) {
        showToast('Select 1–200 findings', 'error');
        return;
      }
      this.evidenceLoading = true;
      try {
        await api.post('/evidence/packages', {
          investigation_id: this.selectedInvestigation.id,
          finding_ids: this.evidenceFindingIds.map(Number),
        });
        showToast('Evidence package saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.evidenceLoading = false;
      }
    },

    async openEvidencePackages(offset = 0) {
      this.activeTab = 'evidence';
      try {
        this.savedEvidence = await api.get(`/evidence/packages?offset=${offset}`);
        this.savedEvidenceOffset = offset;
        this.evidenceEvents = null;
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async loadEvidenceEvents(id, offset = 0) {
      try {
        this.evidenceEvents = await api.get(`/evidence/packages/${id}/events?offset=${offset}`);
        this.evidenceEventsPackage = id;
        this.evidenceEventsOffset = offset;
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async downloadEvidenceFile(path, options, filename) {
      const headers = { ...(options.headers || {}) };
      if (api._token()) headers.Authorization = `Bearer ${api._token()}`;
      const response = await fetch(path, { ...options, headers });
      if (!response.ok) {
        const error = await response.json();
        throw new Error(typeof error.detail === 'string' ? error.detail : 'Evidence download failed');
      }
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      link.click();
      URL.revokeObjectURL(url);
    },

    async downloadSavedEvidence(id) {
      try {
        await this.downloadEvidenceFile(`/api/v1/evidence/packages/${id}/download`, {}, `evidence-package-${id}.zip`);
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async downloadEvidence() {
      if (!this.selectedInvestigation || !this.evidenceFindingIds.length || this.evidenceFindingIds.length > 200) {
        showToast('Select 1–200 findings', 'error');
        return;
      }
      this.evidenceLoading = true;
      try {
        await this.downloadEvidenceFile('/api/v1/evidence/infrastructure', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            investigation_id: this.selectedInvestigation.id,
            finding_ids: this.evidenceFindingIds.map(Number),
          }),
        }, `infrastructure-evidence-${this.selectedInvestigation.id}.zip`);
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.evidenceLoading = false;
      }
    },

    // UI state
    activeTab: 'list',         // 'list' | 'new' | 'detail'
    activeDetailTab: 'all',    // 'all' | 'dns' | 'network' | 'cert' | 'cloud'
    submitLoading: false,
    pollingTimer: null,
    graphCompanies: [
      { name: '', investigationIds: [], btcWallets: '', tronWallets: '' },
      { name: '', investigationIds: [], btcWallets: '', tronWallets: '' },
    ],
    graphInvestigations: [],
    graphResult: null,
    graphLoading: false,
    walletWatches: [],
    walletChain: 'btc',
    walletAddress: '',
    walletLabel: '',
    walletChanges: null,
    walletChangesOffset: 0,
    walletSelectedId: null,
    walletCompareChain: 'btc',
    walletCompareAddresses: '',
    walletCompareResult: null,
    walletCompareLoading: false,
    walletTraceSource: '',
    walletTraceDestination: '',
    walletTraceResult: null,
    walletTraceLoading: false,
    trafficEvidence: '',
    trafficResult: null,
    trafficLoading: false,

    async analyzeTraffic() {
      this.trafficResult = null;
      if (!this.trafficEvidence.trim() || this.trafficEvidence.length > 200000) {
        showToast('Enter evidence of at most 200,000 characters', 'error');
        return;
      }
      this.trafficLoading = true;
      try {
        this.trafficResult = await api.post('/infra/analyze-traffic-evidence', { text: this.trafficEvidence });
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.trafficLoading = false;
      }
    },

    async traceWallets() {
      const source = this.walletTraceSource.trim();
      const destination = this.walletTraceDestination.trim();
      this.walletTraceResult = null;
      if (!source || !destination || source === destination) {
        showToast('Enter two distinct TRON addresses', 'error');
        return;
      }
      this.walletTraceLoading = true;
      try {
        this.walletTraceResult = await api.post('/wallet-monitoring/trace-usdt', {
          source_address: source, destination_address: destination,
        });
      } catch (e) {
        showToast(e.message === '[object Object]' ? 'Check both TRON address formats' : e.message, 'error');
      } finally {
        this.walletTraceLoading = false;
      }
    },

    async compareWallets() {
      const addresses = this.walletCompareAddresses.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
      this.walletCompareResult = null;
      if (addresses.length < 2 || addresses.length > 10) {
        showToast('Enter 2–10 distinct wallet addresses, one per line', 'error');
        return;
      }
      this.walletCompareLoading = true;
      try {
        this.walletCompareResult = await api.post('/wallet-monitoring/compare', {
          chain: this.walletCompareChain, addresses,
        });
      } catch (e) {
        showToast(e.message === '[object Object]' ? 'Check that all addresses are distinct and valid for the selected network' : e.message, 'error');
      } finally {
        this.walletCompareLoading = false;
      }
    },

    async openWalletWatches() {
      this.activeTab = 'wallets';
      try {
        this.walletWatches = await api.get('/wallet-monitoring/watches');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async createWalletWatch() {
      if (!this.walletAddress.trim() || !this.walletLabel.trim()) {
        showToast('Enter a label and wallet address', 'error');
        return;
      }
      try {
        await api.post('/wallet-monitoring/watches', {
          chain: this.walletChain, address: this.walletAddress.trim(), label: this.walletLabel.trim(),
        });
        this.walletAddress = '';
        this.walletLabel = '';
        await this.openWalletWatches();
        showToast('Wallet watch saved', 'success');
      } catch (e) {
        showToast(e.message === '[object Object]' ? 'Check the address format for the selected network' : e.message, 'error');
      }
    },

    async showWalletChanges(id, offset = 0) {
      try {
        this.walletChanges = await api.get(`/wallet-monitoring/watches/${id}/changes?offset=${offset}`);
        this.walletSelectedId = id;
        this.walletChangesOffset = offset;
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async deleteWalletWatch(id) {
      if (!confirm(t('confirm_delete'))) return;
      try {
        await api.delete(`/wallet-monitoring/watches/${id}`);
        if (this.walletSelectedId === id) this.walletChanges = null;
        await this.openWalletWatches();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async openConnections() {
      this.activeTab = 'connections';
      this.graphInvestigations = [];
      try {
        let offset = 0;
        let page;
        do {
          page = await api.get(`/infra/investigations?limit=200&offset=${offset}`);
          this.graphInvestigations.push(...page.filter(inv => inv.status === 'completed'));
          offset += page.length;
        } while (page.length === 200);
      } catch (e) {
        this.graphInvestigations = [];
        showToast(e.message, 'error');
      }
    },

    async buildConnections() {
      this.graphResult = null;
      const names = this.graphCompanies.map(company => company.name.trim().toLowerCase());
      if (names.some(name => !name) || new Set(names).size !== names.length) {
        showToast('Enter a distinct name for each company', 'error');
        return;
      }
      const wallets = this.graphCompanies.map(company => [
        ...company.btcWallets.split(/\r?\n/).map(address => ({ chain: 'btc', address: address.trim() })),
        ...company.tronWallets.split(/\r?\n/).map(address => ({ chain: 'usdt_trc20', address: address.trim() })),
      ].filter(wallet => wallet.address));
      if (this.graphCompanies.some((company, index) => (
        (!company.investigationIds.length && !wallets[index].length) ||
        company.investigationIds.length > 50 || wallets[index].length > 50
      ))) {
        showToast('Assign at least one investigation or wallet; maximum 50 of each per company', 'error');
        return;
      }
      if (new Set(this.graphCompanies.flatMap(company => company.investigationIds)).size > 100) {
        showToast('Select at most 100 distinct investigations', 'error');
        return;
      }
      this.graphLoading = true;
      try {
        this.graphResult = await api.post('/company-connections/graph', {
          companies: this.graphCompanies.map((company, index) => ({
            name: company.name.trim(),
            investigation_ids: company.investigationIds.map(Number),
            wallets: wallets[index],
          })),
        });
      } catch (e) {
        showToast(e.message === '[object Object]' ? 'Check wallet address formats and remove duplicate addresses' : e.message, 'error');
      } finally {
        this.graphLoading = false;
      }
    },

    async init() {
      await this.loadInvestigations();
    },

    async loadInvestigations() {
      this.investigationsLoading = true;
      try {
        const offset = this.investigationsPage * this.investigationsPageSize;
        const limit = this.investigationsPageSize;
        this.investigations = await api.get(`/infra/investigations?limit=${limit}&offset=${offset}`);
        this.investigationsTotal = this.investigations.length;
      } catch (e) {
        this.investigations = [];
        this.investigationsTotal = 0;
        showToast(e.message, 'error');
      } finally {
        this.investigationsLoading = false;
      }
    },

    async submitInvestigation() {
      if (!this.target.trim()) {
        showToast('Target is required', 'error');
        return;
      }
      if (!this.selectedModules.length) {
        showToast('Select at least one module', 'error');
        return;
      }
      this.submitLoading = true;
      try {
        const res = await api.post('/infra/investigate', {
          target: this.target.trim(),
          target_type: this.targetType,
          modules: this.selectedModules,
        });
        showToast('Investigation started', 'success');
        this.activeTab = 'list';
        await this.loadInvestigations();
        if (res && res.investigation_id) {
          this.startPolling(res.investigation_id);
        }
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.submitLoading = false;
      }
    },

    async loadInvestigationDetail(id) {
      this.investigationLoading = true;
      try {
        const summary = await api.get(`/infra/investigations/${id}/summary`);
        this.summaryData = summary || null;
        this.selectedInvestigation = {
          id: summary.investigation_id,
          target: summary.target,
          target_type: summary.summary_json?.target_type || this.selectedInvestigation?.target_type || '',
          status: summary.status,
          summary_json: summary.summary_json || {},
          severity_counts: summary.severity_counts || {},
        };

        const detail = await api.get(`/infra/investigations/${id}`);
        this.selectedInvestigation = {
          ...this.selectedInvestigation,
          ...detail,
        };
        this.findings = detail.findings || [];
        this.evidenceFindingIds = [];
        this.activeDetailTab = 'all';
        this.activeTab = 'detail';
        if (detail.status === 'running' || detail.status === 'pending') {
          this.startPolling(id);
        } else {
          this.stopPolling();
        }
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.investigationLoading = false;
      }
    },

    async deleteInvestigation(id) {
      if (!confirm(t('confirm_delete'))) return;
      try {
        await api.delete(`/infra/investigations/${id}`);
        if (this.selectedInvestigation && this.selectedInvestigation.id === id) {
          this.selectedInvestigation = null;
          this.findings = [];
          this.summaryData = null;
          this.activeTab = 'list';
          this.stopPolling();
        }
        await this.loadInvestigations();
        showToast('Deleted', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    startPolling(id) {
      this.stopPolling();
      this.pollingTimer = setInterval(async () => {
        try {
          const detail = await api.get(`/infra/investigations/${id}`);
          if (detail.status === 'completed' || detail.status === 'failed') {
            this.stopPolling();
            await this.loadInvestigations();
            if (this.selectedInvestigation && this.selectedInvestigation.id === id) {
              await this.loadInvestigationDetail(id);
            }
          }
        } catch (_) {
          this.stopPolling();
        }
      }, 4000);
    },

    stopPolling() {
      if (this.pollingTimer) {
        clearInterval(this.pollingTimer);
        this.pollingTimer = null;
      }
    },

    filteredFindings() {
      if (this.activeDetailTab === 'all') return this.findings;
      return this.findings.filter(f => f.module === this.activeDetailTab);
    },

    severityLabel(n) {
      return { 1: 'INFO', 2: 'LOW', 3: 'MEDIUM', 4: 'HIGH', 5: 'CRITICAL' }[n] || 'INFO';
    },

    severityClass(n) {
      if (n === 5) return 'badge-red';
      if (n === 4) return 'badge-red';
      if (n === 3) return 'badge-yellow';
      if (n === 2) return 'badge-green';
      return 'badge-blue';
    },

    statusBadge(status) {
      if (status === 'completed') return 'badge badge-green';
      if (status === 'failed') return 'badge badge-red';
      if (status === 'running') return 'badge badge-blue';
      return 'badge badge-gray';
    },

    moduleToggle(mod) {
      if (this.selectedModules.includes(mod)) {
        this.selectedModules = this.selectedModules.filter(m => m !== mod);
      } else {
        this.selectedModules.push(mod);
      }
    },

    isModuleSelected(mod) {
      return this.selectedModules.includes(mod);
    },

    findingsCountByModule(mod) {
      return this.findings.filter(f => f.module === mod).length;
    },

    certificateValidity(finding) {
      const data = finding.data_json || {};
      const start = data.not_before ? this.formatDate(data.not_before) : 'Unknown';
      const end = data.not_after ? this.formatDate(data.not_after) : 'Unknown';
      return `${start} – ${end}`;
    },

    certificateExpiryLabel(finding) {
      const data = finding.data_json || {};
      if (
        data.days_until_expiry === null ||
        data.days_until_expiry === undefined ||
        data.days_until_expiry === ''
      ) return '';
      const expiry = Number(data.days_until_expiry);
      if (!Number.isFinite(expiry)) return '';
      if (expiry < 0) return `Expired ${Math.abs(expiry)}d ago`;
      return `${expiry}d remaining`;
    },

    parseSummary(inv) {
      if (!inv || !inv.summary_json) return {};
      if (typeof inv.summary_json === 'object') return inv.summary_json;
      try {
        return JSON.parse(inv.summary_json);
      } catch (_) {
        return {};
      }
    },

    formatDate(str) {
      return window.formatDate(str);
    },
  }));
});
