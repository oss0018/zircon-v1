/**
 * Zircon FRT — Brand Protection page
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('brandPage', () => ({
    brands: [],
    alerts: [],
    loading: false,
    showModal: false,
    showAlerts: false,
    activeBrand: null,
    scanning: false,
    fileScanResults: [],
    showFileScanResults: false,
    newBrand: {
      name: '',
      url: '',
      keywords: '',
      similarity_threshold: 0.8,
      monitoring_enabled: true,
    },

    async init() {
      await this.loadBrands();
      await this.loadAllAlerts();
    },

    async loadBrands() {
      this.loading = true;
      try {
        this.brands = await api.get('/brands/');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.loading = false;
      }
    },

    async loadAllAlerts() {
      try {
        this.alerts = await api.get('/brands/alerts/all');
      } catch (e) {}
    },

    async loadBrandAlerts(brand) {
      this.activeBrand = brand;
      this.showAlerts = true;
      try {
        this.alerts = await api.get(`/brands/${brand.id}/alerts`);
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async createBrand() {
      try {
        await api.post('/brands/', this.newBrand);
        await this.loadBrands();
        this.showModal = false;
        this.newBrand = { name: '', url: '', keywords: '', similarity_threshold: 0.8, monitoring_enabled: true };
        showToast('Brand added', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async scanBrand(id) {
      this.scanning = true;
      try {
        const result = await api.post(`/brands/${id}/scan`, {});
        showToast(`Scan complete: ${result.alerts_created} new alerts found`, 'success');
        await this.loadAllAlerts();
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.scanning = false;
      }
    },

    async updateAlertStatus(alertId, status) {
      try {
        await api.patch(`/brands/alerts/${alertId}`, { status });
        if (this.activeBrand) {
          await this.loadBrandAlerts(this.activeBrand);
        } else {
          await this.loadAllAlerts();
        }
        showToast('Status updated', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async deleteBrand(id) {
      if (!confirm(t('confirm_delete'))) return;
      try {
        await api.delete(`/brands/${id}`);
        this.brands = this.brands.filter(b => b.id !== id);
        showToast('Deleted', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    similarityColor(score) {
      if (score >= 0.9) return 'badge-red';
      if (score >= 0.7) return 'badge-yellow';
      return 'badge-gray';
    },

    statusColor(status) {
      const map = { new: 'badge-red', reviewed: 'badge-blue', dismissed: 'badge-gray' };
      return map[status] || 'badge-gray';
    },

    newAlerts() {
      return this.alerts.filter(a => a.status === 'new').length;
    },

    async scanFromFile(brandId, event) {
      const file = event.target.files[0];
      if (!file) return;
      const fd = new FormData();
      fd.append('file', file);
      try {
        showToast('Scanning domains from file...', 'info');
        const r = await api.upload(`/brands/${brandId}/scan-from-file`, fd);
        showToast(`Done: ${r.total_domains} domains, ${r.alerts_created} new alerts`, 'success');
        this.fileScanResults = r.results;
        this.showFileScanResults = true;
        await this.loadBrands();
      } catch(e) {
        showToast(e.message, 'error');
      }
      event.target.value = '';
    },

    getAlertIp(alert) {
      try {
        const d = JSON.parse(alert.details_json || '{}');
        return d.ip || '—';
      } catch { return '—'; }
    },
  }));
});
