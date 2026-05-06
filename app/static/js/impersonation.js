/**
 * Zircon FRT — Impersonation Monitoring page
 * Uses openSquat API (via backend proxy) to find lookalike domains.
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('impersonationPage', () => ({
    // Integration status
    integrationConfigured: false,
    integrationActive: false,
    statusLoading: true,

    // Search
    searchQuery: '',
    searching: false,
    searchError: null,

    // Results
    results: [],
    lastSearchedKeyword: '',

    // Summary
    totalFound: 0,
    cached: false,

    async init() {
      await this.checkStatus();
    },

    async checkStatus() {
      this.statusLoading = true;
      try {
        const data = await api.get('/impersonation/status');
        this.integrationConfigured = data.configured;
        this.integrationActive = data.active;
      } catch (e) {
        this.integrationConfigured = false;
        this.integrationActive = false;
      } finally {
        this.statusLoading = false;
      }
    },

    async runSearch() {
      const kw = this.searchQuery.trim();
      if (!kw) return;

      this.searching = true;
      this.searchError = null;
      this.results = [];
      this.cached = false;
      this.lastSearchedKeyword = kw;

      try {
        const data = await api.get(`/impersonation/search?keyword=${encodeURIComponent(kw)}`);

        if (data.error) {
          this.searchError = data.error;
          this.results = [];
          this.totalFound = 0;
        } else {
          this.results = this._normalizeResults(data);
          this.totalFound = this.results.length;
          this.cached = data.cached || false;
          if (this.totalFound === 0) {
            this.searchError = null; // empty is valid
          }
        }
      } catch (e) {
        this.searchError = e.message || 'Search failed';
        this.results = [];
        this.totalFound = 0;
      } finally {
        this.searching = false;
      }
    },

    _normalizeResults(raw) {
      // openSquat returns array of domain objects or an object with a domains key
      if (Array.isArray(raw)) {
        return raw.map(item => this._normalizeItem(item));
      }
      if (raw && Array.isArray(raw.domains)) {
        return raw.domains.map(item => this._normalizeItem(item));
      }
      if (raw && Array.isArray(raw.results)) {
        return raw.results.map(item => this._normalizeItem(item));
      }
      // Fallback: if it's a single object with a domain field
      if (raw && raw.domain) {
        return [this._normalizeItem(raw)];
      }
      return [];
    },

    _normalizeItem(item) {
      if (typeof item === 'string') {
        return { domain: item, risk: null, tld: this._getTld(item), first_seen: null, reason: null };
      }
      return {
        domain: item.domain || item.name || '',
        risk: item.risk ?? item.score ?? item.risk_score ?? null,
        tld: item.tld || this._getTld(item.domain || item.name || ''),
        first_seen: item.first_seen || item.created_at || item.date || null,
        reason: item.reason || item.type || null,
      };
    },

    _getTld(domain) {
      if (!domain) return '';
      const parts = domain.split('.');
      return parts.length > 1 ? '.' + parts[parts.length - 1] : '';
    },

    riskClass(risk) {
      if (risk === null || risk === undefined) return 'badge-gray';
      const r = Number(risk);
      if (r >= 80) return 'badge-red';
      if (r >= 50) return 'badge-yellow';
      return 'badge-green';
    },

    riskLabel(risk) {
      if (risk === null || risk === undefined) return '—';
      const r = Number(risk);
      if (r >= 80) return `High (${r})`;
      if (r >= 50) return `Medium (${r})`;
      return `Low (${r})`;
    },

    // Unique TLDs breakdown
    get tldBreakdown() {
      const counts = {};
      for (const r of this.results) {
        const tld = r.tld || '.other';
        counts[tld] = (counts[tld] || 0) + 1;
      }
      return Object.entries(counts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([tld, count]) => ({ tld, count }));
    },

    // High risk count
    get highRiskCount() {
      return this.results.filter(r => r.risk !== null && Number(r.risk) >= 80).length;
    },

    // Medium risk count
    get mediumRiskCount() {
      return this.results.filter(r => r.risk !== null && Number(r.risk) >= 50 && Number(r.risk) < 80).length;
    },

    clearResults() {
      this.results = [];
      this.searchQuery = '';
      this.searchError = null;
      this.totalFound = 0;
      this.lastSearchedKeyword = '';
      this.cached = false;
    },
  }));
});
