/**
 * Zircon FRT — Brand Protection page
 * Handles typosquat scanning, async domain checks, file uploads, export.
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
    // Progress state for async checks
    checkProgress: { running: false, checked: 0, total: 0, foundAlive: 0, results: [] },
    // Filter state
    filterStatus: 'all',
    filterSimilarity: 0,
    filterQuery: '',
    // Limit selector for generate-check
    generateLimit: 1000,
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

    /**
     * Generate typosquatting variants for a brand domain and check them via SSE.
     * @param {number} brandId  - Brand ID (for saving results)
     * @param {string} domain   - Domain to generate variants for
     * @param {number} limit    - Max variants (1000 | 2000 | 5000 | 10000)
     */
    async generateAndCheck(brandId, domain, limit) {
      if (!domain) {
        showToast('Brand has no URL configured', 'error');
        return;
      }
      this.checkProgress = { running: true, checked: 0, total: 0, foundAlive: 0, results: [] };
      this.showAlerts = true;
      showToast(`Generating ${limit} variants for ${domain}…`, 'info');

      const token = localStorage.getItem('zircon_token') || sessionStorage.getItem('zircon_token') || '';
      const body = JSON.stringify({ domain, target_id: brandId, limit: Number(limit) });

      try {
        const resp = await fetch('/api/v1/brands/generate-check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
          body,
        });

        if (!resp.ok) throw new Error(`Server error ${resp.status}`);

        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop(); // keep incomplete last line
          for (const line of lines) {
            if (line.startsWith('data: ')) {
              try {
                const data = JSON.parse(line.slice(6));
                this.checkProgress.checked = data.checked || 0;
                this.checkProgress.total = data.total || 0;
                this.checkProgress.foundAlive = data.found_alive || 0;
                if (data.alive) {
                  this.checkProgress.results.unshift(data);
                }
              } catch (_) {}
            } else if (line.startsWith('event: done')) {
              this.checkProgress.running = false;
            }
          }
        }
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.checkProgress.running = false;
        showToast(`Check complete. Alive: ${this.checkProgress.foundAlive}`, 'success');
        // Reload alerts to show persisted results
        if (this.activeBrand) {
          await this.loadBrandAlerts(this.activeBrand);
        } else {
          await this.loadAllAlerts();
        }
      }
    },

    /**
     * Trigger the hidden file input for .txt domain list upload.
     * @param {number} brandId
     */
    triggerCheckFromFile(brandId) {
      const inp = document.getElementById(`file-input-check-${brandId}`);
      if (inp) inp.click();
    },

    /**
     * Handle .txt file upload for async domain checking (SSE stream).
     * @param {number} brandId
     * @param {Event} event
     */
    async checkFromFile(brandId, event) {
      const file = event.target.files[0];
      if (!file) return;

      this.checkProgress = { running: true, checked: 0, total: 0, foundAlive: 0, results: [] };
      showToast(`Uploading ${file.name}…`, 'info');

      const token = localStorage.getItem('zircon_token') || sessionStorage.getItem('zircon_token') || '';
      const fd = new FormData();
      fd.append('file', file);

      const url = `/api/v1/brands/check-from-file${brandId ? `?target_id=${brandId}` : ''}`;

      try {
        const resp = await fetch(url, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}` },
          body: fd,
        });

        if (!resp.ok) throw new Error(`Server error ${resp.status}`);

        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop();
          for (const line of lines) {
            if (line.startsWith('data: ')) {
              try {
                const data = JSON.parse(line.slice(6));
                this.checkProgress.checked = data.checked || 0;
                this.checkProgress.total = data.total || 0;
                this.checkProgress.foundAlive = data.found_alive || 0;
                if (data.alive) {
                  this.checkProgress.results.unshift(data);
                }
              } catch (_) {}
            } else if (line.startsWith('event: done')) {
              this.checkProgress.running = false;
            }
          }
        }
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.checkProgress.running = false;
        showToast(`File check complete. Alive: ${this.checkProgress.foundAlive}`, 'success');
        event.target.value = '';
        if (this.activeBrand) {
          await this.loadBrandAlerts(this.activeBrand);
        } else {
          await this.loadAllAlerts();
        }
      }
    },

    /**
     * Re-check all previously alive domains for a brand (SSE stream).
     * @param {number} brandId
     */
    async recheckAlive(brandId) {
      this.checkProgress = { running: true, checked: 0, total: 0, foundAlive: 0, results: [] };
      showToast('Re-checking alive domains…', 'info');

      const token = localStorage.getItem('zircon_token') || sessionStorage.getItem('zircon_token') || '';

      try {
        const resp = await fetch(`/api/v1/brands/${brandId}/recheck-alive`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}` },
        });

        if (!resp.ok) throw new Error(`Server error ${resp.status}`);

        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop();
          for (const line of lines) {
            if (line.startsWith('data: ')) {
              try {
                const data = JSON.parse(line.slice(6));
                this.checkProgress.checked = data.checked || 0;
                this.checkProgress.total = data.total || 0;
                this.checkProgress.foundAlive = data.found_alive || 0;
              } catch (_) {}
            } else if (line.startsWith('event: done')) {
              this.checkProgress.running = false;
            }
          }
        }
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.checkProgress.running = false;
        showToast(`Recheck complete. Alive: ${this.checkProgress.foundAlive}`, 'success');
        if (this.activeBrand) {
          await this.loadBrandAlerts(this.activeBrand);
        } else {
          await this.loadAllAlerts();
        }
      }
    },

    /**
     * Download export file (CSV or JSON) for the active brand.
     * @param {'csv'|'json'} format
     */
    exportResults(format) {
      const brandId = this.activeBrand ? this.activeBrand.id : null;
      if (!brandId) {
        showToast('Select a brand first', 'error');
        return;
      }
      const token = localStorage.getItem('zircon_token') || sessionStorage.getItem('zircon_token') || '';
      const url = `/api/v1/brands/results/${brandId}/export?format=${format}`;
      // Use fetch to include auth header, then trigger download
      fetch(url, { headers: { 'Authorization': `Bearer ${token}` } })
        .then(r => {
          if (!r.ok) throw new Error(`Export failed: ${r.status}`);
          return r.blob();
        })
        .then(blob => {
          const a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = `brand_${brandId}_results.${format}`;
          a.click();
          URL.revokeObjectURL(a.href);
        })
        .catch(e => showToast(e.message, 'error'));
    },

    /**
     * Client-side filter on the loaded alerts array.
     * Filters by status, minimum similarity %, and a text query.
     */
    get filteredAlerts() {
      return this.alerts.filter(a => {
        if (this.filterStatus !== 'all' && a.status !== this.filterStatus) return false;
        const simPct = (a.similarity_pct != null) ? a.similarity_pct : a.similarity_score * 100;
        if (this.filterSimilarity > 0 && simPct < this.filterSimilarity) return false;
        if (this.filterQuery) {
          const q = this.filterQuery.toLowerCase();
          const haystack = `${a.similar_domain} ${a.ip || ''}`.toLowerCase();
          if (!haystack.includes(q)) return false;
        }
        return true;
      });
    },

    similarityColor(score) {
      if (score >= 0.9) return 'badge-red';
      if (score >= 0.7) return 'badge-yellow';
      return 'badge-gray';
    },

    simPctColor(pct) {
      if (pct == null) return 'badge-gray';
      if (pct >= 80) return 'badge-green';
      if (pct >= 50) return 'badge-yellow';
      return 'badge-red';
    },

    statusColor(status) {
      const map = { new: 'badge-red', reviewed: 'badge-blue', dismissed: 'badge-gray' };
      return map[status] || 'badge-gray';
    },

    newAlerts() {
      return this.alerts.filter(a => a.status === 'new').length;
    },

    progressPct() {
      if (!this.checkProgress.total) return 0;
      return Math.round((this.checkProgress.checked / this.checkProgress.total) * 100);
    },

    progressBar() {
      const pct = this.progressPct();
      const filled = Math.round(pct / 5);
      const empty = 20 - filled;
      return '█'.repeat(filled) + '░'.repeat(empty);
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
      if (alert.ip) return alert.ip;
      try {
        const d = JSON.parse(alert.details_json || '{}');
        return d.ip || '—';
      } catch { return '—'; }
    },

    getAlertAlive(alert) {
      if (alert.alive === true) return '🟢 Alive';
      if (alert.alive === false) return '🔴 Dead';
      return '—';
    },

    getAlertSsl(alert) {
      if (alert.ssl_valid === true) return '✅';
      if (alert.ssl_valid === false) return '❌';
      return '—';
    },
  }));
});
