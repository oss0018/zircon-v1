/**
 * Zircon FRT — Monitoring page
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('monitoringPage', () => ({
    jobs: [],
    loading: false,
    showModal: false,
    triggerResult: null,
    newJob: {
      name: '',
      type: 'folder_scan',
      config_json: '{"folder": "./data/monitored"}',
      schedule: '*/15 * * * *',
    },

    jobTypes: [
      { value: 'folder_scan', label: 'Folder Scan' },
      { value: 'osint_check', label: 'OSINT Check' },
      { value: 'watchlist_check', label: 'Watchlist Check' },
      { value: 'brand_scan', label: 'Brand Scan' },
    ],

    commonSchedules: [
      { label: 'Every 15 minutes', value: '*/15 * * * *' },
      { label: 'Every hour', value: '0 * * * *' },
      { label: 'Every 6 hours', value: '0 */6 * * *' },
      { label: 'Daily at midnight', value: '0 0 * * *' },
      { label: 'Weekly (Sunday)', value: '0 0 * * 0' },
    ],

    async init() {
      await this.loadJobs();
    },

    async loadJobs() {
      this.loading = true;
      try {
        this.jobs = await api.get('/monitoring/');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.loading = false;
      }
    },

    async createJob() {
      try {
        await api.post('/monitoring/', this.newJob);
        await this.loadJobs();
        this.showModal = false;
        this.newJob = {
          name: '',
          type: 'folder_scan',
          config_json: '{"folder": "./data/monitored"}',
          schedule: '*/15 * * * *',
        };
        showToast('Job created', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async triggerJob(id) {
      try {
        const result = await api.post(`/monitoring/${id}/trigger`);
        this.triggerResult = result;
        await this.loadJobs();
        showToast('Job triggered', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async toggleJob(job) {
      try {
        await api.patch(`/monitoring/${job.id}`, { is_active: !job.is_active });
        await this.loadJobs();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async deleteJob(id) {
      if (!confirm(t('confirm_delete'))) return;
      try {
        await api.delete(`/monitoring/${id}`);
        this.jobs = this.jobs.filter(j => j.id !== id);
        showToast('Deleted', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    jobTypeLabel(type) {
      const t = this.jobTypes.find(j => j.value === type);
      return t ? t.label : type;
    },
  }));
});
