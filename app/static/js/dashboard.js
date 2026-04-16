/**
 * Zircon FRT — Dashboard page
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('dashboardPage', () => ({
    stats: null,
    loading: false,
    chart: null,

    async init() {
      await this.load();
    },

    async load() {
      this.loading = true;
      try {
        this.stats = await api.get('/dashboard/stats');
        this.$nextTick(() => this.renderChart());
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.loading = false;
      }
    },

    renderChart() {
      const ctx = document.getElementById('fileTypeChart');
      if (!ctx || !this.stats) return;
      if (this.chart) { this.chart.destroy(); }
      const types = this.stats.file_types || {};
      const labels = Object.keys(types);
      const values = Object.values(types);
      this.chart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels,
          datasets: [{
            data: values,
            backgroundColor: [
              '#00ff9d', '#00b4d8', '#7c3aed', '#ff003c',
              '#ffb300', '#06b6d4', '#ec4899', '#84cc16',
            ],
            borderColor: '#0d1117',
            borderWidth: 2,
          }],
        },
        options: {
          responsive: true,
          plugins: {
            legend: {
              position: 'right',
              labels: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 11 } },
            },
          },
        },
      });
    },

    stat(key) {
      if (!this.stats) return 0;
      return this.stats[key] || 0;
    },
  }));
});
