/**
 * Zircon FRT — TI Dashboard Page (Variant B)
 * Manifest-driven read-only widget grid for Threat Intelligence.
 */

document.addEventListener('alpine:init', () => {
  Alpine.data('tiDashboardPage', () => ({
    // Dashboard list & current selection
    dashboards: [],
    currentDashboard: null,
    loading: false,

    // Widget data (loaded once; shared by all widget instances)
    tiStats: null,
    tiHistory: [],
    tiIntegrations: [],
    dataLoading: false,

    // Quick-search widget state
    qsIoc: '',
    qsIocType: 'general',
    qsLoading: false,
    qsResult: null,
    qsError: '',

    // Chart instances keyed by canvas id
    _charts: {},

    iocTypes: ['general', 'ip', 'domain', 'hash', 'url', 'email'],

    // Number of free (no-API-key) TI sources (urlhaus, phishtank, malwarebazaar, threatfox)
    FREE_CONNECTORS_COUNT: 4,

    async init() {
      await this.loadDashboards();
      await this.loadData();
    },

    async loadDashboards() {
      this.loading = true;
      try {
        this.dashboards = await api.get('/ti-dashboards');
        if (this.dashboards.length > 0) {
          this.currentDashboard =
            this.dashboards.find(d => d.is_default) || this.dashboards[0];
        }
      } catch (e) {
        console.error('Failed to load TI dashboards', e);
      } finally {
        this.loading = false;
      }
    },

    async loadData() {
      this.dataLoading = true;
      try {
        const [stats, history, integrations] = await Promise.all([
          api.get('/ti/stats').catch(() => null),
          api.get('/ti/history?limit=20').catch(() => []),
          api.get('/ti/integrations').catch(() => []),
        ]);
        this.tiStats = stats;
        this.tiHistory = Array.isArray(history) ? history : [];
        this.tiIntegrations = Array.isArray(integrations) ? integrations : [];
        // Render charts after DOM update
        await this.$nextTick();
        this.renderCharts();
      } finally {
        this.dataLoading = false;
      }
    },

    selectDashboard(d) {
      this.currentDashboard = d;
      this.$nextTick(() => this.renderCharts());
    },

    // ── Grid layout helpers ───────────────────────────────────────

    /**
     * Group widgets into rows by their `y` layout coordinate.
     * Returns an array of rows; each row is sorted by `x`.
     */
    widgetRows() {
      if (!this.currentDashboard || !this.currentDashboard.widgets) return [];
      const rows = {};
      for (const w of this.currentDashboard.widgets) {
        const layout = this._parseLayout(w);
        const y = layout.y;
        if (!rows[y]) rows[y] = [];
        rows[y].push({ ...w, _layout: layout });
      }
      return Object.keys(rows)
        .map(Number)
        .sort((a, b) => a - b)
        .map(y => rows[y].sort((a, b) => a._layout.x - b._layout.x));
    },

    _parseLayout(widget) {
      try {
        return JSON.parse(widget.layout_json || '{"x":0,"y":0,"w":12,"h":2}');
      } catch {
        return { x: 0, y: 0, w: 12, h: 2 };
      }
    },

    parseParams(widget) {
      try {
        return JSON.parse(widget.params_json || '{}');
      } catch {
        return {};
      }
    },

    // ── Chart rendering ───────────────────────────────────────────

    renderCharts() {
      if (!this.currentDashboard) return;
      for (const w of this.currentDashboard.widgets) {
        const canvasId = 'tid-chart-' + w.id;
        if (w.type === 'ti_source_distribution') {
          this._renderDonutChart(canvasId);
        } else if (w.type === 'ti_top_sources') {
          this._renderBarChart(canvasId);
        }
      }
    },

    _renderDonutChart(canvasId) {
      if (!this.tiStats || !this.tiStats.service_stats) return;
      const canvas = document.getElementById(canvasId);
      if (!canvas) return;
      if (this._charts[canvasId]) {
        this._charts[canvasId].destroy();
        delete this._charts[canvasId];
      }
      const stats = this.tiStats.service_stats.filter(s => s.total > 0);
      if (!stats.length) return;
      const COLORS = [
        'rgba(0,255,157,0.65)', 'rgba(0,180,216,0.65)', 'rgba(124,58,237,0.65)',
        'rgba(255,179,0,0.65)',  'rgba(255,0,60,0.65)',  'rgba(100,200,255,0.65)',
        'rgba(255,100,150,0.65)','rgba(160,255,60,0.65)',
      ];
      this._charts[canvasId] = new Chart(canvas, {
        type: 'doughnut',
        data: {
          labels: stats.map(s => s.name),
          datasets: [{
            data: stats.map(s => s.total),
            backgroundColor: COLORS.slice(0, stats.length),
            borderWidth: 1,
            borderColor: 'rgba(0,0,0,0.3)',
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              labels: { color: '#94a3b8', font: { size: 11 }, boxWidth: 12 },
              position: 'right',
            },
          },
        },
      });
    },

    _renderBarChart(canvasId) {
      if (!this.tiStats || !this.tiStats.service_stats) return;
      const canvas = document.getElementById(canvasId);
      if (!canvas) return;
      if (this._charts[canvasId]) {
        this._charts[canvasId].destroy();
        delete this._charts[canvasId];
      }
      const stats = [...this.tiStats.service_stats]
        .sort((a, b) => b.total - a.total)
        .slice(0, 8);
      if (!stats.length) return;
      this._charts[canvasId] = new Chart(canvas, {
        type: 'bar',
        data: {
          labels: stats.map(s => s.name),
          datasets: [{
            label: 'Lookups (7d)',
            data: stats.map(s => s.total),
            backgroundColor: 'rgba(0,255,157,0.35)',
            borderColor: 'rgba(0,255,157,0.8)',
            borderWidth: 1,
            borderRadius: 3,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: {
              ticks: { color: '#94a3b8', font: { size: 10 } },
              grid: { color: 'rgba(255,255,255,0.04)' },
            },
            y: {
              ticks: { color: '#94a3b8', font: { size: 10 } },
              grid: { color: 'rgba(255,255,255,0.04)' },
              beginAtZero: true,
            },
          },
        },
      });
    },

    // ── Quick-search widget ───────────────────────────────────────

    async runQuickSearch() {
      if (!this.qsIoc.trim() || this.qsLoading) return;
      this.qsLoading = true;
      this.qsResult = null;
      this.qsError = '';
      try {
        this.qsResult = await api.post('/ti/search', {
          query: this.qsIoc.trim(),
          query_type: this.qsIocType,
        });
        showToast('IOC search complete', 'success');
      } catch (e) {
        this.qsError = e.message || 'Search failed';
        showToast('Search failed: ' + (e.message || ''), 'error');
      } finally {
        this.qsLoading = false;
      }
    },

    clearQuickSearch() {
      this.qsIoc = '';
      this.qsResult = null;
      this.qsError = '';
    },

    // ── Stat helpers ──────────────────────────────────────────────

    statValue(key) {
      if (key === 'active_sources') {
        return this.tiStats ? (this.tiStats.active_ti_integrations ?? '—') : '—';
      }
      if (key === 'lookups_7d') {
        return this.tiStats ? (this.tiStats.total_lookups_7d ?? '—') : '—';
      }
      if (key === 'history') return this.tiHistory.length;
      if (key === 'free_connectors') return this.FREE_CONNECTORS_COUNT;
      return '—';
    },

    verdictIcon(verdict) {
      const icons = { malicious: '🔴', suspicious: '🟡', clean: '🟢', unknown: '⚪' };
      return icons[verdict] || '⚪';
    },

    confidencePct(val) {
      if (val === undefined || val === null) return null;
      return Math.round(val * 100);
    },

    formatDate(d) {
      if (!d) return '—';
      try {
        return new Date(d).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' });
      } catch {
        return d;
      }
    },

    knownWidgetTypes: [
      'ti_stats', 'ti_quick_search', 'ti_recent_lookups',
      'ti_source_distribution', 'ti_top_sources',
    ],

    isKnownType(type) {
      return this.knownWidgetTypes.includes(type);
    },
  }));
});
