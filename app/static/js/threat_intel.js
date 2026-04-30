/**
 * Zircon FRT — Threat Intelligence (TI) Page  [CSINT section]
 */

document.addEventListener('alpine:init', () => {
  Alpine.data('threatIntelPage', () => ({
    // Active TI integrations
    activeIntegrations: [],
    integrationsLoading: false,

    // IoC lookup form
    iocForm: { ioc: '', ioc_type: 'general' },
    lookupLoading: false,
    lookupResults: null,    // {ioc, ioc_type, results: [...]}
    rawDataModal: { show: false, source: '', data: null },

    // History
    history: [],
    historyLoading: false,
    historyDetailModal: { show: false, entry: null },

    // Stats / charts
    stats: null,
    statsLoading: false,
    _charts: {},            // keyed by service_type

    // Filter for history table
    historyFilter: { type: '', source: '', date: '' },

    iocTypes: ['general', 'ip', 'domain', 'hash', 'url', 'email'],

    async init() {
      await Promise.all([
        this.loadIntegrations(),
        this.loadHistory(),
        this.loadStats(),
      ]);
    },

    async loadIntegrations() {
      this.integrationsLoading = true;
      try {
        this.activeIntegrations = await api.get('/ti/integrations');
      } catch (e) {
        this.activeIntegrations = [];
      } finally {
        this.integrationsLoading = false;
      }
    },

    async loadHistory() {
      this.historyLoading = true;
      try {
        this.history = await api.get('/ti/history?limit=100');
      } catch (e) {
        this.history = [];
      } finally {
        this.historyLoading = false;
      }
    },

    async loadStats() {
      this.statsLoading = true;
      try {
        this.stats = await api.get('/ti/stats');
        this.$nextTick(() => this._renderCharts());
      } catch (e) {
        this.stats = null;
      } finally {
        this.statsLoading = false;
      }
    },

    _renderCharts() {
      if (!this.stats || !this.stats.service_stats) return;
      this.stats.service_stats.forEach(svc => {
        const canvasId = `ti-chart-${svc.service_type}`;
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;

        // Destroy existing chart instance if any
        if (this._charts[svc.service_type]) {
          this._charts[svc.service_type].destroy();
        }

        const labels = svc.days.map(d => d.slice(5)); // MM-DD
        this._charts[svc.service_type] = new Chart(canvas, {
          type: 'bar',
          data: {
            labels,
            datasets: [{
              label: 'Lookups',
              data: svc.counts,
              backgroundColor: 'rgba(0,255,157,0.35)',
              borderColor: 'rgba(0,255,157,0.85)',
              borderWidth: 1,
              borderRadius: 3,
            }],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { display: false },
              tooltip: { mode: 'index' },
            },
            scales: {
              x: {
                ticks: { color: '#94a3b8', font: { size: 10 } },
                grid: { color: 'rgba(255,255,255,0.04)' },
              },
              y: {
                beginAtZero: true,
                ticks: { color: '#94a3b8', font: { size: 10 }, stepSize: 1 },
                grid: { color: 'rgba(255,255,255,0.04)' },
              },
            },
          },
        });
      });
    },

    async runLookup() {
      if (!this.iocForm.ioc.trim()) return;
      this.lookupLoading = true;
      this.lookupResults = null;
      try {
        this.lookupResults = await api.post('/ti/lookup', {
          ioc: this.iocForm.ioc.trim(),
          ioc_type: this.iocForm.ioc_type,
        });
        await this.loadHistory();
        await this.loadStats();
        this.$nextTick(() => this._renderCharts());
        showToast('Lookup completed', 'success');
      } catch (e) {
        showToast('Lookup failed: ' + e.message, 'error');
      } finally {
        this.lookupLoading = false;
      }
    },

    openRawData(result) {
      this.rawDataModal = { show: true, source: result.name, data: result.data };
    },

    closeRawData() {
      this.rawDataModal = { show: false, source: '', data: null };
    },

    async openHistoryDetail(entry) {
      try {
        const detail = await api.get(`/ti/history/${entry.id}`);
        this.historyDetailModal = { show: true, entry: detail };
      } catch (e) {
        showToast('Could not load details', 'error');
      }
    },

    closeHistoryDetail() {
      this.historyDetailModal = { show: false, entry: null };
    },

    filteredHistory() {
      return this.history.filter(h => {
        if (this.historyFilter.type && h.ioc_type !== this.historyFilter.type) return false;
        if (this.historyFilter.source && !h.sources.includes(this.historyFilter.source)) return false;
        if (this.historyFilter.date && !(h.created_at || '').startsWith(this.historyFilter.date)) return false;
        return true;
      });
    },

    clearHistoryFilters() {
      this.historyFilter = { type: '', source: '', date: '' };
    },

    availableHistorySources() {
      const set = new Set();
      this.history.forEach(h => (h.sources || []).forEach(s => set.add(s)));
      return [...set].sort();
    },

    hasActiveIntegrations() {
      return this.activeIntegrations.length > 0;
    },

    resultSummary(data) {
      if (!data || typeof data !== 'object') return '—';
      if (data.error) return '⚠ ' + data.error;
      // Try to extract a meaningful snippet
      const keys = Object.keys(data);
      if (keys.length === 0) return 'No data';
      // Common patterns
      if (data.not_found) return 'Not found';
      if (data.positives !== undefined) return `${data.positives} detections`;
      if (data.abuse_confidence_score !== undefined) return `Abuse score: ${data.abuse_confidence_score}%`;
      if (data.pulse_count !== undefined) return `${data.pulse_count} pulses`;
      if (data.total !== undefined && typeof data.total === 'number') return `${data.total} results`;
      if (data.urls_count !== undefined) return `${data.urls_count} URLs`;
      if (data.result !== undefined) return String(data.result).substring(0, 80);
      return keys.length + ' fields';
    },

    formatDate(dateStr) {
      if (!dateStr) return '—';
      const d = new Date(dateStr);
      return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    },

    prettyJson(data) {
      try { return JSON.stringify(data, null, 2); } catch { return String(data); }
    },
  }));
});
