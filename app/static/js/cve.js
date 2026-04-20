/**
 * Zircon FRT — CVE Search page
 * Uses backend proxy to NIST NVD API v2
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('cvePage', () => ({
    query: '',
    searchType: 'keyword',
    severity: '',
    results: [],
    totalResults: 0,
    searchTime: 0,
    loading: false,
    searched: false,
    error: '',
    quickSearches: ['log4j', 'apache', 'openssl', 'windows', 'chrome', 'cisco', 'vmware', 'confluence'],

    async init() {},

    async search() {
      if (!this.query.trim()) return;
      this.loading = true;
      this.error = '';
      this.results = [];
      this.searched = true;
      const t0 = Date.now();

      try {
        const params = new URLSearchParams();
        if (this.searchType === 'cve_id') {
          params.set('cve_id', this.query.trim());
        } else {
          params.set('keyword', this.query.trim());
        }
        if (this.severity) params.set('severity', this.severity);
        params.set('limit', '20');

        const data = await api.get(`/cve/search?${params}`);

        if (data.error) {
          this.error = data.error;
          return;
        }

        this.totalResults = data.totalResults || 0;
        this.searchTime = Date.now() - t0;

        this.results = (data.vulnerabilities || []).map(item => {
          const cve = item.cve;
          const metrics =
            cve.metrics?.cvssMetricV31?.[0] ||
            cve.metrics?.cvssMetricV30?.[0] ||
            cve.metrics?.cvssMetricV2?.[0];
          const cvssScore = metrics?.cvssData?.baseScore;
          const severity = metrics?.cvssData?.baseSeverity || '';
          const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
          const products = [];
          (cve.configurations || []).forEach(cfg => {
            (cfg.nodes || []).forEach(node => {
              (node.cpeMatch || []).forEach(cpe => {
                const parts = cpe.criteria?.split(':') || [];
                if (parts.length > 4) products.push(`${parts[3]} ${parts[4]}`);
              });
            });
          });
          const refs = (cve.references || []).map(r => r.url).slice(0, 3);

          return {
            id: cve.id,
            description: desc,
            severity: severity,
            cvss_score: cvssScore,
            published: cve.published,
            products: [...new Set(products)].slice(0, 5),
            references: refs,
          };
        });

      } catch (e) {
        this.error = e.message || 'Search failed';
      } finally {
        this.loading = false;
      }
    },

    severityClass(sev) {
      const map = {
        'CRITICAL': 'badge-red',
        'HIGH': 'badge-red',
        'MEDIUM': 'badge-yellow',
        'LOW': 'badge-gray',
      };
      return map[sev] || 'badge-gray';
    },

    severityBorder(sev) {
      const map = {
        'CRITICAL': 'border-left-color: #ff003c;',
        'HIGH': 'border-left-color: #ff6b35;',
        'MEDIUM': 'border-left-color: #ffb300;',
        'LOW': 'border-left-color: #94a3b8;',
      };
      return map[sev] || '';
    },
  }));
});
