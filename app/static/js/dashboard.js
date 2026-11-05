/**
 * Zircon FRT — Dashboard page
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('dashboardPage', () => ({
    stats: null,
    loading: false,
    loadError: false,
    reindexing: false,
    reindexMsg: '',
    showWidgetSettings: false,
    lastUpdatedAt: null,
    notifications: [],
    notificationError: '',
    indicatorsLoaded: false,
    indicatorError: '',
    countryRows: [],
    countryCount: 0,
    widgetVisibility: {
      priority_metrics: true,
      metric_brand_alerts: true,
      metric_monitoring: true,
      metric_watchlist: true,
      metric_notifications: true,
      metric_files: false,
      metric_indexed: false,
      metric_searches: false,
      metric_integrations: false,
      alert_feed: true,
      threat_geo: true,
      recent_searches: false,
      file_types: false,
      quick_actions: false,
    },
    widgetOptions: [
      { id: 'priority_metrics', label: 'priority_metrics' },
      { id: 'metric_brand_alerts', label: 'brand_alerts' },
      { id: 'metric_monitoring', label: 'monitoring_jobs' },
      { id: 'metric_watchlist', label: 'watchlist_items' },
      { id: 'metric_notifications', label: 'unread_notifications' },
      { id: 'metric_files', label: 'total_files' },
      { id: 'metric_indexed', label: 'indexed_files' },
      { id: 'metric_searches', label: 'total_searches' },
      { id: 'metric_integrations', label: 'active_integrations' },
      { id: 'alert_feed', label: 'alert_feed' },
      { id: 'threat_geo', label: 'threat_geography' },
      { id: 'recent_searches', label: 'recent_searches' },
      { id: 'file_types', label: 'file_types' },
      { id: 'quick_actions', label: 'quick_actions' },
    ],

    // Chart.js instance for File Types donut
    _fileTypesChart: null,

    async init() {
      this.$cleanup(() => {
        if (this._fileTypesChart) this._fileTypesChart.destroy();
      });
      this.loadWidgetPreferences();
      await this.load();
    },

    async load() {
      this.loading = true;
      this.loadError = false;
      try {
        const [statsResult, notificationsResult, indicatorsResult] = await Promise.allSettled([
          api.get('/dashboard/stats'),
          api.get('/dashboard/notifications?limit=5'),
          api.get('/cti/indicators'),
        ]);
        if (statsResult.status === 'rejected') throw statsResult.reason;
        this.stats = statsResult.value;
        if (notificationsResult.status === 'fulfilled') {
          this.notifications = Array.isArray(notificationsResult.value) ? notificationsResult.value : [];
          this.notificationError = '';
        } else {
          this.notifications = [];
          this.notificationError = notificationsResult.reason.message || t('dashboard_load_error');
        }
        if (indicatorsResult.status === 'fulfilled') {
          this.setCountryRows(Array.isArray(indicatorsResult.value) ? indicatorsResult.value : []);
          this.indicatorsLoaded = true;
          this.indicatorError = '';
        } else {
          this.countryRows = [];
          this.indicatorsLoaded = false;
          this.indicatorError = indicatorsResult.reason.message || t('dashboard_load_error');
        }
        this.lastUpdatedAt = new Date();
        await this.$nextTick();
        if (this.widgetVisibility.file_types) this._renderFileTypesChart();
      } catch (e) {
        this.loadError = true;
        showToast(e.message, 'error');
      } finally {
        this.loading = false;
      }
    },

    loadWidgetPreferences() {
      try {
        const saved = JSON.parse(localStorage.getItem('zircon_dashboard_widgets') || '{}');
        for (const option of this.widgetOptions) {
          if (typeof saved[option.id] === 'boolean') {
            this.widgetVisibility[option.id] = saved[option.id];
          }
        }
      } catch (e) {
        console.warn('Could not load dashboard widget preferences', e);
      }
    },

    toggleWidget(id, enabled) {
      this.widgetVisibility[id] = enabled;
      try {
        localStorage.setItem('zircon_dashboard_widgets', JSON.stringify(this.widgetVisibility));
      } catch (e) {
        showToast(t('preferences_save_error'), 'error');
      }
      if (id === 'file_types' && enabled) {
        this.$nextTick(() => this._renderFileTypesChart());
      }
    },

    resetWidgets() {
      try {
        localStorage.removeItem('zircon_dashboard_widgets');
      } catch (e) {
        showToast(t('preferences_save_error'), 'error');
      }
      this.widgetVisibility = {
        priority_metrics: true,
        metric_brand_alerts: true,
        metric_monitoring: true,
        metric_watchlist: true,
        metric_notifications: true,
        metric_files: false,
        metric_indexed: false,
        metric_searches: false,
        metric_integrations: false,
        alert_feed: true,
        threat_geo: true,
        recent_searches: false,
        file_types: false,
        quick_actions: false,
      };
      this.$nextTick(() => this._renderFileTypesChart());
    },

    metricWidgets() {
      return [
        { id: 'metric_brand_alerts', statKey: 'brand_alerts_new', label: 'brand_alerts', page: 'brands', tone: 'text-red' },
        { id: 'metric_monitoring', statKey: 'active_monitoring_jobs', label: 'monitoring_jobs', page: 'monitoring', tone: '' },
        { id: 'metric_watchlist', statKey: 'watchlist_items', label: 'watchlist_items', page: 'watchlist', tone: '' },
        { id: 'metric_notifications', statKey: 'unread_notifications', label: 'unread_notifications', page: 'notifications', tone: 'text-red' },
        { id: 'metric_files', statKey: 'total_files', label: 'total_files', page: 'files', tone: '' },
        { id: 'metric_indexed', statKey: 'indexed_files', label: 'indexed_files', page: 'files', tone: 'text-blue' },
        { id: 'metric_searches', statKey: 'total_searches', label: 'total_searches', page: 'search', tone: '' },
        { id: 'metric_integrations', statKey: 'active_integrations', label: 'active_integrations', page: 'integrations', tone: 'text-blue' },
      ].filter(widget => this.widgetVisibility[widget.id]);
    },

    setCountryRows(indicators) {
      const counts = new Map();
      for (const indicator of indicators) {
        const code = String(indicator.country_code || '').trim().toUpperCase();
        if (/^[A-Z]{2}$/.test(code)) counts.set(code, (counts.get(code) || 0) + 1);
      }
      let displayNames;
      try {
        displayNames = new Intl.DisplayNames([window._lang || 'en'], { type: 'region' });
      } catch (_) {
        displayNames = { of: code => code };
      }
      const rows = [...counts.entries()]
        .map(([code, count]) => ({
          code,
          count,
          name: displayNames.of(code) || code,
        }))
        .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
        .slice(0, 6);
      this.countryCount = counts.size;
      const maxCount = rows.length ? rows[0].count : 0;
      this.countryRows = rows.map(row => ({
        ...row,
        percentage: maxCount ? Math.max(8, Math.round((row.count / maxCount) * 100)) : 0,
      }));
    },

    indicatorCountLabel() {
      if (!this.indicatorsLoaded) return t('loading');
      return this.countryCount + ' ' + t('countries');
    },

    lastUpdatedLabel() {
      return this.lastUpdatedAt
        ? t('updated') + ' ' + this.lastUpdatedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        : '';
    },

    formatDashboardDate(value) {
      if (!value) return '';
      const date = new Date(value);
      return Number.isNaN(date.getTime()) ? '' : date.toLocaleString([], { dateStyle: 'short', timeStyle: 'short' });
    },

    async markNotificationRead(id) {
      try {
        await api.post(`/dashboard/notifications/${id}/read`);
        await this.load();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    // ── File Types donut chart ────────────────────────────────────────────

    _renderFileTypesChart() {
      const canvas = document.getElementById('file-types-chart');
      if (!canvas) return;

      // Destroy previous instance to avoid double-init / memory leaks
      if (this._fileTypesChart) {
        this._fileTypesChart.destroy();
        this._fileTypesChart = null;
      }

      const fileTypes = this.stats ? (this.stats.file_types || {}) : {};
      const sortedEntries = Object.entries(fileTypes).sort((a, b) => b[1] - a[1]);
      const entries = sortedEntries.length > 8
        ? [...sortedEntries.slice(0, 7), ['other', sortedEntries.slice(7).reduce((sum, [, count]) => sum + count, 0)]]
        : sortedEntries;
      if (!entries.length) return;

      const COLORS = [
        'rgba(0,255,157,0.7)', 'rgba(0,180,216,0.7)', 'rgba(124,58,237,0.7)',
        'rgba(255,179,0,0.7)', 'rgba(255,0,60,0.7)',   'rgba(100,200,255,0.7)',
        'rgba(255,100,150,0.7)', 'rgba(160,255,60,0.7)',
      ];

      this._fileTypesChart = new Chart(canvas, {
        type: 'doughnut',
        data: {
          labels: entries.map(([ext]) => ext || 'other'),
          datasets: [{
            data: entries.map(([, count]) => count),
            backgroundColor: COLORS.slice(0, entries.length),
            borderWidth: 1,
            borderColor: 'rgba(0,0,0,0.3)',
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '65%',
          plugins: {
            legend: {
              position: 'bottom',
              labels: { color: '#94a3b8', font: { size: 11 }, boxWidth: 12 },
            },
          },
        },
      });
    },

    // ─────────────────────────────────────────────────────────────────────

    async reindexAll() {
      this.reindexing = true;
      this.reindexMsg = '';
      try {
        const res = await api.post('/files/reindex-all');
        this.reindexMsg = `Reindexed ${res.indexed} files successfully.`;
        await this.load();
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.reindexing = false;
      }
    },

    stat(key) {
      if (!this.stats) return 0;
      return this.stats[key] || 0;
    },
  }));
});
