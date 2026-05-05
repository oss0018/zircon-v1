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

    // Chart.js instance for File Types donut
    _fileTypesChart: null,

    async init() {
      await this.load();
    },

    async load() {
      this.loading = true;
      this.loadError = false;
      try {
        this.stats = await api.get('/dashboard/stats');
        await this.$nextTick();
        this._renderFileTypesChart();
      } catch (e) {
        this.loadError = true;
        showToast(e.message, 'error');
      } finally {
        this.loading = false;
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
      const entries = Object.entries(fileTypes).sort((a, b) => b[1] - a[1]);
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
