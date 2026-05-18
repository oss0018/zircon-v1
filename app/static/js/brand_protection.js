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
    brandRunning: {},
    fileScanResults: [],
    showFileScanResults: false,
    // Progress state for async checks
    checkProgress: { running: false, checked: 0, total: 0, foundAlive: 0, results: [], page: 1, pageSize: 50 },
    // Filter state
    filterStatus: 'all',
    filterSimilarity: 0,
    filterQuery: '',
    // Filter for live check results
    resultFilter: '',
    // Limit selector for generate-check (kept for backward compat, superseded by per-brand settings)
    generateLimit: 1000,
    // Per-brand owned / trusted domains
    ownedDomains: [],
    showOwnedDomainsPanel: false,
    newOwnedDomain: { domain: '', notes: '', match_subdomains: true },
    // Checklist for results selection
    selectedResults: new Set(),
    newBrand: {
      name: '',
      url: '',
      keywords: '',
      similarity_threshold: 0.8,
      monitoring_enabled: true,
    },
    // Owned domains section inside Add Brand modal
    modalOwnedDomains: [],
    modalNewOwnedDomain: '',
    modalTrustSubdomains: true,

    // Context menu for alert rows
    ctxMenu: { show: false, x: 0, y: 0, alert: null },

    /** Normalise a raw domain string: strip scheme, path, port, trailing dot, lowercase. */
    _normalizeDomain(raw) {
      return raw.trim().toLowerCase()
        .replace(/^https?:\/\//, '')
        .split('/')[0].split('?')[0].split(':')[0]
        .replace(/\.$/, '');
    },

    async init() {
      await this.loadBrands();
      await this.loadAllAlerts();
      document.addEventListener('click', () => { this.ctxMenu.show = false; });
      document.addEventListener('keydown', e => { if (e.key === 'Escape') this.ctxMenu.show = false; });
    },

    async loadBrands() {
      this.loading = true;
      try {
        const brands = await api.get('/brands/');
        // Normalise per-brand generate settings so x-model select binding works correctly
        this.brands = brands.map(b => ({
          ...b,
          generate_mode: b.generate_mode || 'domain',
          generate_limit: String(b.generate_limit ?? 1000),
        }));
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.loading = false;
      }
    },

    async loadAllAlerts() {
      // Clear per-brand owned-domain list so stale Trusted badges don't appear
      // in the all-alerts view. loadAllAlerts is only called when activeBrand is null.
      if (!this.activeBrand) this.ownedDomains = [];
      try {
        this.alerts = await api.get('/brands/alerts/all');
      } catch (e) {
        console.warn('loadAllAlerts error:', e.message);
      }
    },

    async loadBrandAlerts(brand) {
      this.activeBrand = brand;
      this.showAlerts = true;
      try {
        this.alerts = await api.get(`/brands/${brand.id}/alerts`);
        // Load owned domains for this brand so trusted badges work
        await this.loadOwnedDomains(brand.id);
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async createBrand() {
      try {
        const created = await api.post('/brands/', this.newBrand);
        // Save owned domains that were entered in the modal
        for (const od of this.modalOwnedDomains) {
          try {
            await api.post(`/brands/${created.id}/owned-domains`, {
              domain: od,
              match_subdomains: this.modalTrustSubdomains,
            });
          } catch (e) { /* skip duplicates */ }
        }
        await this.loadBrands();
        this._resetBrandModal();
        showToast('Brand added', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    _resetBrandModal() {
      this.showModal = false;
      this.newBrand = { name: '', url: '', keywords: '', similarity_threshold: 0.8, monitoring_enabled: true };
      this.modalOwnedDomains = [];
      this.modalNewOwnedDomain = '';
    },

    addModalOwnedDomain() {
      const d = this._normalizeDomain(this.modalNewOwnedDomain);
      if (!d) return;
      if (!this.modalOwnedDomains.includes(d)) {
        this.modalOwnedDomains.push(d);
      }
      this.modalNewOwnedDomain = '';
    },

    removeModalOwnedDomain(domain) {
      this.modalOwnedDomains = this.modalOwnedDomains.filter(d => d !== domain);
    },

    async importModalOwnedDomains(event) {
      const file = event.target.files[0];
      if (!file) return;
      const text = await file.text();
      let added = 0;
      for (const line of text.split(/\r?\n/)) {
        if (line.trim().startsWith('#')) continue;
        const d = this._normalizeDomain(line);
        if (!d) continue;
        if (!this.modalOwnedDomains.includes(d)) {
          this.modalOwnedDomains.push(d);
          added++;
        }
      }
      showToast(`${added} domains loaded from file`, 'success');
      event.target.value = '';
    },

    async scanBrand(id) {
      this.scanning = true;
      this.brandRunning = { ...this.brandRunning, [id]: true };
      try {
        const result = await api.post(`/brands/${id}/scan`, {});
        showToast(`Scan complete: ${result.alerts_created} new alerts found`, 'success');
        await this.loadAllAlerts();
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.scanning = false;
        this.brandRunning = { ...this.brandRunning, [id]: false };
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

    showCtxMenu(e, alert) {
      e.preventDefault();
      e.stopPropagation();
      const x = Math.min(e.clientX, window.innerWidth - 220);
      const y = Math.min(e.clientY, window.innerHeight - 130);
      this.ctxMenu = { show: true, x, y, alert };
    },

    closeCtxMenu() {
      this.ctxMenu = { show: false, x: 0, y: 0, alert: null };
    },

    ctxOpenInNewWindow() {
      this.closeCtxMenu();
      window.open('/?page=brands', '_blank');
    },

    ctxCopyDomain() {
      const alert = this.ctxMenu.alert;
      this.closeCtxMenu();
      if (!alert) return;
      navigator.clipboard.writeText(alert.similar_domain || '')
        .then(() => showToast('Domain copied to clipboard', 'success'))
        .catch(() => showToast('Failed to copy', 'error'));
    },

    ctxOpenDomain() {
      const alert = this.ctxMenu.alert;
      this.closeCtxMenu();
      if (!alert || !alert.similar_domain) return;
      window.open(`https://${alert.similar_domain}`, '_blank', 'noopener,noreferrer');
    },

    /**
     * Persist per-brand Advanced Domain Checks generation settings to the server.
     * Called automatically when the user changes mode or limit for a brand.
     * @param {number} brandId
     */
    async saveGenerateSettings(brandId) {
      const brand = this.brands.find(b => b.id === brandId);
      if (!brand) {
        console.warn('saveGenerateSettings: brand not found for id', brandId);
        return;
      }
      try {
        await api.patch(`/brands/${brandId}/generate-settings`, {
          generate_mode: brand.generate_mode,
          generate_limit: Number(brand.generate_limit),
        });
      } catch (e) {
        showToast('Failed to save generate settings: ' + e.message, 'error');
      }
    },

    /**
     * Generate typosquatting variants for a brand domain and check them via SSE.
     * @param {number} brandId  - Brand ID (for saving results)
     * @param {string} domain   - Domain to generate variants for
     * @param {number} limit    - Max variants
     * @param {string} mode     - 'domain' | 'brand_name' | 'both'
     */
    async generateAndCheck(brandId, domain, limit, mode) {
      if (mode === 'domain' && !domain) {
        showToast('Domain is required for domain-based generation (brand has no URL configured)', 'error');
        return;
      }
      const brand = this.brands.find(b => b.id === brandId);
      const brandName = brand ? brand.name : '';
      this.activeBrand = brand || null;

      this.checkProgress = { running: true, checked: 0, total: 0, foundAlive: 0, results: [], page: 1, pageSize: 50 };
      this.brandRunning = { ...this.brandRunning, [brandId]: true };
      this.selectedResults = new Set();
      this.showAlerts = true;
      showToast(`Generating up to ${limit} variants…`, 'info');

      const token = localStorage.getItem('zircon_token') || sessionStorage.getItem('zircon_token') || '';
      const body = JSON.stringify({
        domain,
        brand_name: brandName,
        mode: mode || 'domain',
        target_id: brandId,
        limit: Number(limit),
      });

      let hadError = false;
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
                  this.checkProgress.results.push(data);
                }
              } catch (parseErr) { console.warn('SSE parse error:', parseErr); }
            } else if (line.startsWith('event: done')) {
              this.checkProgress.running = false;
            }
          }
        }
      } catch (e) {
        hadError = true;
        showToast(e.message, 'error');
      } finally {
        this.checkProgress.running = false;
        this.brandRunning = { ...this.brandRunning, [brandId]: false };
        if (!hadError) showToast(`Check complete. Alive: ${this.checkProgress.foundAlive}`, 'success');
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

      const brand = this.brands.find(b => b.id === brandId);
      this.activeBrand = brand || null;
      this.checkProgress = { running: true, checked: 0, total: 0, foundAlive: 0, results: [], page: 1, pageSize: 50 };
      this.brandRunning = { ...this.brandRunning, [brandId]: true };
      this.selectedResults = new Set();
      showToast(`Uploading ${file.name}…`, 'info');

      const token = localStorage.getItem('zircon_token') || sessionStorage.getItem('zircon_token') || '';
      const fd = new FormData();
      fd.append('file', file);

      const url = `/api/v1/brands/check-from-file${brandId ? `?target_id=${brandId}` : ''}`;

      let hadError = false;
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
                  this.checkProgress.results.push(data);
                }
              } catch (parseErr) { console.warn('SSE parse error:', parseErr); }
            } else if (line.startsWith('event: done')) {
              this.checkProgress.running = false;
            }
          }
        }
      } catch (e) {
        hadError = true;
        showToast(e.message, 'error');
      } finally {
        this.checkProgress.running = false;
        this.brandRunning = { ...this.brandRunning, [brandId]: false };
        if (!hadError) showToast(`File check complete. Alive: ${this.checkProgress.foundAlive}`, 'success');
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
      const brand = this.brands.find(b => b.id === brandId);
      this.activeBrand = brand || null;
      this.checkProgress = { running: true, checked: 0, total: 0, foundAlive: 0, results: [], page: 1, pageSize: 50 };
      this.brandRunning = { ...this.brandRunning, [brandId]: true };
      showToast('Re-checking alive domains…', 'info');

      const token = localStorage.getItem('zircon_token') || sessionStorage.getItem('zircon_token') || '';

      let hadError = false;
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
                if (data.alive) {
                  this.checkProgress.results.push(data);
                }
              } catch (parseErr) { console.warn('SSE parse error:', parseErr); }
            } else if (line.startsWith('event: done')) {
              this.checkProgress.running = false;
            }
          }
        }
      } catch (e) {
        hadError = true;
        showToast(e.message, 'error');
      } finally {
        this.checkProgress.running = false;
        this.brandRunning = { ...this.brandRunning, [brandId]: false };
        if (!hadError) showToast(`Recheck complete. Alive: ${this.checkProgress.foundAlive}`, 'success');
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
     * Export alive check results (from current session) as .txt
     */
    exportCheckResultsTxt() {
      const results = this.filteredCheckResults;
      if (!results.length) {
        showToast('No results to export', 'info');
        return;
      }
      const txt = results.map(r => r.domain).join('\n');
      const blob = new Blob([txt], { type: 'text/plain' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'check_results.txt';
      a.click();
      URL.revokeObjectURL(a.href);
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

    /** Filter live check results (alive domains from current SSE session) */
    get filteredCheckResults() {
      if (!this.resultFilter) return this.checkProgress.results;
      const q = this.resultFilter.toLowerCase();
      return this.checkProgress.results.filter(r =>
        r.domain.toLowerCase().includes(q) || (r.ip || '').includes(q)
      );
    },

    /** Paginated slice of filteredCheckResults */
    get pagedCheckResults() {
      const f = this.filteredCheckResults;
      const start = (this.checkProgress.page - 1) * this.checkProgress.pageSize;
      return f.slice(start, start + this.checkProgress.pageSize);
    },

    checkResultsTotalPages() {
      return Math.max(1, Math.ceil(this.filteredCheckResults.length / this.checkProgress.pageSize));
    },

    nextResultsPage() {
      if (this.checkProgress.page < this.checkResultsTotalPages()) this.checkProgress.page++;
    },

    prevResultsPage() {
      if (this.checkProgress.page > 1) this.checkProgress.page--;
    },

    toggleResultSelected(domain) {
      if (this.selectedResults.has(domain)) {
        this.selectedResults.delete(domain);
      } else {
        this.selectedResults.add(domain);
      }
      // Trigger Alpine reactivity
      this.selectedResults = new Set(this.selectedResults);
    },

    selectAllResults() {
      this.selectedResults = new Set(this.filteredCheckResults.map(r => r.domain));
    },

    selectNoneResults() {
      this.selectedResults = new Set();
    },

    invertResultSelection() {
      const all = new Set(this.filteredCheckResults.map(r => r.domain));
      const inv = new Set([...all].filter(d => !this.selectedResults.has(d)));
      this.selectedResults = inv;
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

    // ── Per-brand Owned / Trusted Domains ────────────────────────────────────

    async loadOwnedDomains(brandId) {
      if (!brandId) {
        this.ownedDomains = [];
        return;
      }
      try {
        this.ownedDomains = await api.get(`/brands/${brandId}/owned-domains`);
      } catch (e) {
        console.warn('Could not load owned domains:', e.message);
        this.ownedDomains = [];
      }
    },

    async showOwnedDomainsFor(brand) {
      this.activeBrand = brand;
      this.showOwnedDomainsPanel = true;
      await this.loadOwnedDomains(brand.id);
    },

    async addOwnedDomain() {
      if (!this.activeBrand) return;
      const domain = this._normalizeDomain(this.newOwnedDomain.domain);
      if (!domain) return;
      try {
        await api.post(`/brands/${this.activeBrand.id}/owned-domains`, {
          ...this.newOwnedDomain,
          domain,
        });
        this.newOwnedDomain = { domain: '', notes: '', match_subdomains: true };
        await this.loadOwnedDomains(this.activeBrand.id);
        showToast(`${domain} added to owned domains`, 'success');
      } catch (e) {
        showToast(e.message || 'Failed to add domain', 'error');
      }
    },

    async importOwnedDomainsFromFile(event) {
      if (!this.activeBrand) return;
      const file = event.target.files[0];
      if (!file) return;
      const fd = new FormData();
      fd.append('file', file);
      const matchSubs = this.newOwnedDomain.match_subdomains !== false;
      try {
        const r = await api.upload(
          `/brands/${this.activeBrand.id}/owned-domains/import?match_subdomains=${matchSubs}`,
          fd
        );
        await this.loadOwnedDomains(this.activeBrand.id);
        showToast(
          `Imported: ${r.added} added, ${r.skipped_duplicate} duplicates, ${r.skipped_invalid} invalid`,
          'success'
        );
      } catch (e) {
        showToast(e.message || 'Import failed', 'error');
      }
      event.target.value = '';
    },

    async deleteOwnedDomain(id) {
      if (!this.activeBrand) return;
      try {
        await api.delete(`/brands/${this.activeBrand.id}/owned-domains/${id}`);
        await this.loadOwnedDomains(this.activeBrand.id);
        showToast('Owned domain removed', 'success');
      } catch (e) {
        showToast(e.message || 'Failed to remove domain', 'error');
      }
    },

    /**
     * Check if a given domain matches any owned domain (including subdomain matching).
     * Uses the currently-loaded per-brand ownedDomains list.
     * @param {string} domain
     * @returns {boolean}
     */
    isTrustedDomain(domain) {
      if (!domain || !this.ownedDomains.length) return false;
      const d = domain.toLowerCase();
      return this.ownedDomains.some(od => {
        const owned = od.domain.toLowerCase();
        if (d === owned) return true;
        if (od.match_subdomains && d.endsWith('.' + owned)) return true;
        return false;
      });
    },
  }));
});
