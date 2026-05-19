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

    // UI state
    activeTab: 'list',         // 'list' | 'new' | 'detail'
    activeDetailTab: 'all',    // 'all' | 'dns' | 'network' | 'cert' | 'cloud'
    submitLoading: false,
    pollingTimer: null,

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
