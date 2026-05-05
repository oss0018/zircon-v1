/**
 * Zircon FRT — Dashboard page
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('dashboardPage', () => ({
    stats: null,
    loading: false,
    reindexing: false,
    reindexMsg: '',

    async init() {
      await this.load();
    },

    async load() {
      this.loading = true;
      try {
        this.stats = await api.get('/dashboard/stats');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.loading = false;
      }
    },

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
