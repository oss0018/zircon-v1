/**
 * Zircon FRT — Threat Intelligence (TI) Page  [CSINT section]
 * Enhanced with normalized results, enrichment, detections, artifacts, timeline.
 */

document.addEventListener('alpine:init', () => {
  Alpine.data('threatIntelPage', () => ({
    // Active TI integrations
    activeIntegrations: [],
    integrationsLoading: false,

    // Source selection
    selectedSources: [],        // empty = all sources
    selectAllSources: true,

    // IoC lookup form
    iocForm: { ioc: '', ioc_type: 'ip' },
    lookupLoading: false,
    lookupError: null,

    // Search results (normalized + per-source)
    searchResult: null,         // full API response {ioc, ioc_type, normalized, per_source, queried_at}
    activeResultTab: 'summary', // 'summary' | 'detections' | 'enrichment' | 'artifacts' | 'timeline' | 'sources'

    // Per-source raw data modal
    rawModal: { show: false, source: '', data: null },

    // History
    history: [],
    historyLoading: false,
    historyDetailModal: { show: false, entry: null },
    historyDetailLoading: false,

    // Stats / charts
    stats: null,
    statsLoading: false,
    statsError: false,
    _charts: {},
    _summaryChart: null,
    _severityChart: null,
    _topSourcesChart: null,

    // History filter
    historyFilter: { type: '', source: '', date: '' },

    // Context menu for history rows
    ctxMenu: { show: false, x: 0, y: 0, entry: null },

    iocTypes: ['ip', 'domain', 'hash', 'url', 'email', 'general'],

    async init() {
      await Promise.all([
        this.loadIntegrations(),
        this.loadHistory(),
        this.loadStats(),
      ]);
      document.addEventListener('click', () => { this.ctxMenu.show = false; });
      document.addEventListener('keydown', e => { if (e.key === 'Escape') this.ctxMenu.show = false; });
      // Deep-link: pre-fill IOC form from URL params
      const urlParams = window._urlParams;
      if (urlParams) {
        const ioc = urlParams.get('ioc');
        const iocType = urlParams.get('ioc_type');
        if (ioc) {
          this.iocForm.ioc = decodeURIComponent(ioc);
          if (iocType) this.iocForm.ioc_type = decodeURIComponent(iocType);
        }
      }
    },

    async loadIntegrations() {
      this.integrationsLoading = true;
      try {
        this.activeIntegrations = await api.get('/ti/integrations');
        // Default: all selected
        this.selectedSources = this.activeIntegrations.map(i => i.service_type);
        this.selectAllSources = true;
      } catch (e) {
        this.activeIntegrations = [];
      } finally {
        this.integrationsLoading = false;
      }
    },

    toggleSelectAll() {
      if (this.selectAllSources) {
        this.selectedSources = this.activeIntegrations.map(i => i.service_type);
      } else {
        this.selectedSources = [];
      }
    },

    onSourceToggle() {
      this.selectAllSources = this.selectedSources.length === this.activeIntegrations.length;
    },

    async loadHistory() {
      this.historyLoading = true;
      try {
        this.history = await api.get('/ti/history?limit=100');
      } catch (e) {
        this.history = [];
      } finally {
        this.historyLoading = false;
      }
    },

    async loadStats() {
      this.statsLoading = true;
      this.statsError = false;
      try {
        this.stats = await api.get('/ti/stats');
        // Double $nextTick: first tick lets Alpine update x-show bindings,
        // second tick ensures canvases are fully laid out and measurable.
        await this.$nextTick();
        await this.$nextTick();
        this._renderCharts();
      } catch (e) {
        this.stats = null;
        this.statsError = true;
      } finally {
        this.statsLoading = false;
      }
    },

    // ── Chart rendering ────────────────────────────────────────────────────

    /** Returns true when there is at least one source with lookups in the past 7 days. */
    hasSourceStats() {
      return !!(this.stats && this.stats.service_stats && this.stats.service_stats.some(s => s.total > 0));
    },

    _renderCharts() {
      this._renderSummaryDoughnut();
      this._renderTopSourcesBar();
      this._renderPerServiceCharts();
    },

    _renderSummaryDoughnut() {
      const canvas = document.getElementById('ti-summary-chart');
      if (!canvas || !this.stats || !this.stats.service_stats || !this.stats.service_stats.length) return;
      if (this._summaryChart) this._summaryChart.destroy();
      const svcs = this.stats.service_stats;
      const palette = [
        'rgba(0,255,157,0.75)', 'rgba(0,180,216,0.75)', 'rgba(255,200,0,0.75)',
        'rgba(255,80,80,0.75)', 'rgba(130,80,255,0.75)', 'rgba(0,220,130,0.75)',
        'rgba(255,140,0,0.75)', 'rgba(0,160,255,0.75)', 'rgba(200,50,200,0.75)',
        'rgba(80,200,80,0.75)', 'rgba(255,100,150,0.75)',
      ];
      this._summaryChart = new Chart(canvas, {
        type: 'doughnut',
        data: {
          labels: svcs.map(s => s.name),
          datasets: [{
            data: svcs.map(s => s.total),
            backgroundColor: svcs.map((_, i) => palette[i % palette.length]),
            borderWidth: 1,
            borderColor: 'rgba(0,0,0,0.3)',
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '65%',
          plugins: {
            legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 11 }, boxWidth: 12 } },
            tooltip: { mode: 'index' },
          },
        },
      });
    },

    _renderTopSourcesBar() {
      const canvas = document.getElementById('ti-top-sources-bar');
      if (!canvas || !this.stats || !this.stats.service_stats || !this.stats.service_stats.length) return;
      if (this._topSourcesChart) this._topSourcesChart.destroy();
      const svcs = [...this.stats.service_stats].sort((a, b) => b.total - a.total).slice(0, 8);
      this._topSourcesChart = new Chart(canvas, {
        type: 'bar',
        data: {
          labels: svcs.map(s => s.name),
          datasets: [{
            label: 'Lookups (7 days)',
            data: svcs.map(s => s.total),
            backgroundColor: 'rgba(0,255,157,0.4)',
            borderColor: 'rgba(0,255,157,0.9)',
            borderWidth: 1,
            borderRadius: 4,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: { legend: { display: false } },
          scales: {
            x: { beginAtZero: true, ticks: { color: '#94a3b8', font: { size: 10 }, stepSize: 1 }, grid: { color: 'rgba(255,255,255,0.04)' } },
            y: { ticks: { color: '#94a3b8', font: { size: 11 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
          },
        },
      });
    },

    _renderPerServiceCharts() {
      if (!this.stats || !this.stats.service_stats) return;
      this.stats.service_stats.forEach(svc => {
        const canvasId = `ti-chart-${svc.service_type}`;
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        if (this._charts[svc.service_type]) this._charts[svc.service_type].destroy();
        const labels = svc.days.map(d => d.slice(5));
        this._charts[svc.service_type] = new Chart(canvas, {
          type: 'bar',
          data: {
            labels,
            datasets: [{
              label: 'Lookups',
              data: svc.counts,
              backgroundColor: 'rgba(0,255,157,0.35)',
              borderColor: 'rgba(0,255,157,0.85)',
              borderWidth: 1,
              borderRadius: 3,
            }],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              x: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
              y: { beginAtZero: true, ticks: { color: '#94a3b8', font: { size: 10 }, stepSize: 1 }, grid: { color: 'rgba(255,255,255,0.04)' } },
            },
          },
        });
      });
    },

    // ── Search / Lookup ────────────────────────────────────────────────────

    async runSearch() {
      if (!this.iocForm.ioc.trim()) return;
      this.lookupLoading = true;
      this.searchResult = null;
      this.lookupError = null;
      this.activeResultTab = 'summary';
      try {
        const payload = {
          query: this.iocForm.ioc.trim(),
          query_type: this.iocForm.ioc_type,
        };
        if (!this.selectAllSources && this.selectedSources.length > 0) {
          payload.sources = this.selectedSources;
        }
        this.searchResult = await api.post('/ti/search', payload);
        await this.loadHistory();
        await this.loadStats();
        this.$nextTick(() => this._renderCharts());
        showToast('Lookup complete', 'success');
      } catch (e) {
        this.lookupError = e.message || 'Lookup failed';
        showToast('Lookup failed: ' + (e.message || ''), 'error');
      } finally {
        this.lookupLoading = false;
      }
    },

    // Keep backward-compat alias
    async runLookup() { return this.runSearch(); },

    // ── Verdict helpers ────────────────────────────────────────────────────

    verdictIcon(verdict) {
      return { malicious: '🔴', suspicious: '🟠', clean: '✅', unknown: '❓' }[verdict] || '❓';
    },

    verdictLabel(verdict) {
      return { malicious: 'Malicious', suspicious: 'Suspicious', clean: 'Clean', unknown: 'Unknown' }[verdict] || verdict;
    },

    severityClass(severity) {
      const map = { critical: 'ti-sev-critical', high: 'ti-sev-high', medium: 'ti-sev-medium', low: 'ti-sev-low', none: 'ti-sev-none' };
      return map[severity] || 'ti-sev-none';
    },

    severityLabel(severity) {
      const map = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', none: 'NONE' };
      return map[severity] || (severity || 'NONE').toUpperCase();
    },

    confidenceColor(conf) {
      if (conf >= 75) return '#ff4444';
      if (conf >= 50) return '#ff9900';
      if (conf >= 25) return '#ffcc00';
      return '#00ff9d';
    },

    // ── Normalized result accessors ────────────────────────────────────────

    get normalized() {
      return this.searchResult && this.searchResult.normalized ? this.searchResult.normalized : null;
    },

    get perSource() {
      return this.searchResult && this.searchResult.per_source ? this.searchResult.per_source : [];
    },

    get hasDetections() {
      return this.normalized && this.normalized.detections && this.normalized.detections.length > 0;
    },

    get hasEnrichment() {
      if (!this.normalized) return false;
      const e = this.normalized.enrichment;
      return (e.geo && Object.keys(e.geo).some(k => e.geo[k])) ||
             (e.network && (e.network.ports && e.network.ports.length)) ||
             (e.dns && Object.keys(e.dns).length > 0);
    },

    get hasArtifacts() {
      if (!this.normalized) return false;
      const a = this.normalized.artifacts;
      return Object.values(a).some(arr => arr && arr.length > 0);
    },

    get hasTimeline() {
      return this.normalized && this.normalized.timeline && this.normalized.timeline.length > 0;
    },

    geoFields(geo) {
      const fields = [];
      if (geo.country) fields.push({ label: '🌍 Country', value: geo.country + (geo.country_code ? ` (${geo.country_code})` : '') });
      if (geo.city) fields.push({ label: '🏙️ City', value: geo.city });
      if (geo.asn) fields.push({ label: '🔌 ASN', value: geo.asn });
      if (geo.isp) fields.push({ label: '📡 ISP', value: geo.isp });
      if (geo.org) fields.push({ label: '🏢 Org', value: geo.org });
      if (geo.network) fields.push({ label: '🔗 Network', value: geo.network });
      if (geo.usage_type) fields.push({ label: '📋 Usage', value: geo.usage_type });
      if (geo.asnname) fields.push({ label: '📡 ASN Name', value: geo.asnname });
      return fields;
    },

    // ── Per-source legacy humanFields (for fallback source cards) ──────────

    humanFields(source, data) {
      if (!data || typeof data !== 'object') return [];
      if (data.error) return [{ label: 'Error', value: data.error, highlight: 'danger' }];
      if (data.not_found) return [{ label: 'Status', value: 'Not found / No data', highlight: '' }];
      try {
        switch (source) {
          case 'virustotal': return this._fieldsVirusTotal(data);
          case 'abuseipdb': return this._fieldsAbuseIPDB(data);
          case 'shodan': return this._fieldsShodan(data);
          case 'alienvault': return this._fieldsAlienVault(data);
          case 'urlhaus': return this._fieldsURLhaus(data);
          case 'phishtank': return this._fieldsPhishTank(data);
          case 'urlscan': return this._fieldsURLscan(data);
          case 'censys': return this._fieldsCensys(data);
          case 'securitytrails': return this._fieldsSecurityTrails(data);
          case 'hibp': return this._fieldsHIBP(data);
          case 'intelx': return this._fieldsIntelX(data);
          case 'malwarebazaar': return this._fieldsMalwareBazaar(data);
          case 'threatfox': return this._fieldsThreatFox(data);
          default: return this._fieldsGeneric(data);
        }
      } catch { return this._fieldsGeneric(data); }
    },

    _fieldsVirusTotal(d) {
      const fields = [];
      // v2 style
      if (d.positives !== undefined && d.total !== undefined) {
        const pct = d.total > 0 ? Math.round(d.positives / d.total * 100) : 0;
        fields.push({ label: 'Detections', value: `${d.positives} / ${d.total} engines (${pct}%)`, highlight: d.positives > 0 ? 'danger' : 'success' });
        if (d.scan_date) fields.push({ label: 'Scan date', value: d.scan_date, highlight: '' });
        if (d.permalink) fields.push({ label: 'Report', value: d.permalink, isLink: true, highlight: '' });
        const scans = d.scans || {};
        const detected = Object.entries(scans).filter(([, v]) => v && v.detected).slice(0, 5);
        if (detected.length) fields.push({ label: 'Top detections', value: detected.map(([n, v]) => `${n}: ${v.result || 'malicious'}`).join(', '), highlight: 'warning' });
        return fields;
      }
      // v3 style
      const attrs = (d.data && d.data.attributes) ? d.data.attributes : d.attributes || {};
      const stats = attrs.last_analysis_stats || {};
      const mal = stats.malicious || 0;
      const sus = stats.suspicious || 0;
      const total = Object.values(stats).reduce((a, b) => a + b, 0) || 0;
      if (total > 0) {
        let detHighlight = 'success';
        if (mal > 0) detHighlight = 'danger';
        else if (sus > 0) detHighlight = 'warning';
        fields.push({ label: 'Detections', value: `${mal} malicious / ${sus} suspicious / ${total} engines`, highlight: detHighlight });
      }
      if (attrs.meaningful_name) fields.push({ label: 'Name', value: attrs.meaningful_name, highlight: '' });
      if (attrs.type_description) fields.push({ label: 'Type', value: attrs.type_description, highlight: '' });
      if (attrs.size) fields.push({ label: 'Size', value: attrs.size + ' bytes', highlight: '' });
      const tags = attrs.tags || [];
      if (tags.length) fields.push({ label: 'Tags', value: tags.slice(0, 6).join(', '), highlight: 'warning' });
      // Analysis dates
      if (attrs.last_analysis_date) {
        const ts = new Date(attrs.last_analysis_date * 1000);
        if (!isNaN(ts)) fields.push({ label: 'Last analysis', value: ts.toLocaleDateString(), highlight: '' });
      }
      if (attrs.first_submission_date) {
        const ts = new Date(attrs.first_submission_date * 1000);
        if (!isNaN(ts)) fields.push({ label: 'First seen', value: ts.toLocaleDateString(), highlight: '' });
      }
      // Popular threat name
      const threatClass = attrs.popular_threat_classification || {};
      const threatNames = (threatClass.popular_threat_name || []).slice(0, 3);
      if (threatNames.length) fields.push({ label: 'Threat', value: threatNames.map(t => t.value || t).join(', '), highlight: 'danger' });
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsAbuseIPDB(d) {
      const data = d.data || d;
      const fields = [];
      const score = data.abuseConfidenceScore ?? data.abuse_confidence_score ?? null;
      if (score !== null) fields.push({ label: 'Abuse confidence', value: `${score}%`, highlight: score > 50 ? 'danger' : score > 10 ? 'warning' : 'success' });
      if (data.countryName || data.country_name) fields.push({ label: 'Country', value: `${data.countryName || data.country_name}${data.countryCode ? ' (' + data.countryCode + ')' : ''}`, highlight: '' });
      if (data.isp) fields.push({ label: 'ISP', value: data.isp, highlight: '' });
      if (data.domain) fields.push({ label: 'Domain', value: data.domain, highlight: '' });
      if (data.usageType || data.usage_type) fields.push({ label: 'Usage type', value: data.usageType || data.usage_type, highlight: '' });
      const reports = data.totalReports ?? data.total_reports ?? 0;
      if (reports !== undefined) fields.push({ label: 'Total reports', value: String(reports), highlight: reports > 0 ? 'warning' : '' });
      const distinct = data.numDistinctUsers ?? data.num_distinct_users;
      if (distinct !== undefined) fields.push({ label: 'Distinct reporters', value: String(distinct), highlight: distinct > 3 ? 'warning' : '' });
      if (data.lastReportedAt || data.last_reported_at) fields.push({ label: 'Last reported', value: this.formatDate(data.lastReportedAt || data.last_reported_at), highlight: '' });
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsShodan(d) {
      const fields = [];
      if (d.ip_str || d.ip) fields.push({ label: 'IP', value: d.ip_str || d.ip, highlight: '' });
      if (d.org) fields.push({ label: 'Organization', value: d.org, highlight: '' });
      if (d.isp && d.isp !== d.org) fields.push({ label: 'ISP', value: d.isp, highlight: '' });
      if (d.country_name) fields.push({ label: 'Country', value: `${d.country_name}${d.city ? ', ' + d.city : ''}`, highlight: '' });
      if (d.os) fields.push({ label: 'OS', value: d.os, highlight: '' });
      if (d.ports && d.ports.length) fields.push({ label: 'Open ports', value: d.ports.slice(0, 20).join(', ') + (d.ports.length > 20 ? '…' : ''), highlight: 'warning' });
      if (d.tags && d.tags.length) fields.push({ label: 'Shodan tags', value: (Array.isArray(d.tags) ? d.tags : [d.tags]).slice(0, 6).join(', '), highlight: '' });
      if (d.vulns && Object.keys(d.vulns).length) {
        const cves = Object.keys(d.vulns).slice(0, 8);
        fields.push({ label: 'CVEs', value: cves.join(', ') + (Object.keys(d.vulns).length > 8 ? '…' : ''), highlight: 'danger' });
      }
      // Service summary from data array
      if (d.data && d.data.length) {
        const products = [...new Set(d.data.map(s => s.product).filter(Boolean))].slice(0, 5);
        if (products.length) fields.push({ label: 'Products', value: products.join(', '), highlight: '' });
      }
      if (d.last_update) fields.push({ label: 'Last seen', value: this.formatDate(d.last_update), highlight: '' });
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsAlienVault(d) {
      const fields = [];
      const pi = d.pulse_info || {};
      const pulseCount = pi.count !== undefined ? pi.count : (d.pulse_count || 0);
      fields.push({ label: 'Pulse count', value: String(pulseCount), highlight: pulseCount > 0 ? 'warning' : 'success' });
      if (d.type_title)
        fields.push({ label: 'Type', value: d.type_title, highlight: '' });
      if (d.reputation !== undefined)
        fields.push({ label: 'Reputation', value: String(d.reputation), highlight: d.reputation < 0 ? 'danger' : '' });
      if (d.country_name)
        fields.push({ label: 'Country', value: d.country_name + (d.country_code ? ` (${d.country_code})` : ''), highlight: '' });
      if (d.asn)
        fields.push({ label: 'ASN', value: d.asn, highlight: '' });
      if (d.city)
        fields.push({ label: 'City', value: d.city, highlight: '' });

      // Validation summary
      const validation = d.validation || [];
      if (validation.length > 0) {
        const vMsg = validation.map(v => v.message || v.name || String(v)).join('; ');
        fields.push({ label: 'Validation', value: vMsg, highlight: '' });
      }

      // Top-3 pulse name/TLP summary for compact card
      const pulses = (pi.pulses || []).slice(0, 3);
      pulses.forEach((p, i) => {
        const tlp = p.tlp ? `[TLP:${p.tlp.toUpperCase()}] ` : '';
        const tags = (p.tags || []).slice(0, 4).join(', ');
        const val = `${tlp}${p.name}${tags ? ' — ' + tags : ''}`;
        fields.push({ label: `Pulse ${i + 1}`, value: val, highlight: p.tlp === 'red' ? 'danger' : p.tlp === 'amber' ? 'warning' : '' });
      });
      if (pulseCount > 3)
        fields.push({ label: '', value: `+${pulseCount - 3} more pulses (see pulse list below or Raw JSON)`, highlight: '' });

      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsURLhaus(d) {
      const fields = [];
      if (d.query_status) fields.push({ label: 'Status', value: d.query_status, highlight: d.query_status === 'is_malware' ? 'danger' : 'success' });
      if (d.threat) fields.push({ label: 'Threat', value: d.threat, highlight: 'danger' });
      if (d.tags && d.tags.length) fields.push({ label: 'Tags', value: d.tags.join(', '), highlight: 'warning' });
      const cnt = d.urls_count ?? (d.urls && d.urls.length);
      if (cnt !== undefined) fields.push({ label: 'Malicious URLs', value: String(cnt), highlight: cnt > 0 ? 'danger' : 'success' });
      if (d.urlhaus_reference) fields.push({ label: 'Reference', value: d.urlhaus_reference, isLink: true, highlight: '' });
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsPhishTank(d) {
      const fields = [];
      const results = d.results || d;
      if (results.in_database !== undefined) {
        fields.push({ label: 'In database', value: results.in_database ? 'Yes' : 'No', highlight: results.in_database ? 'danger' : 'success' });
        if (results.valid !== undefined) fields.push({ label: 'Verified phishing', value: results.valid ? 'Yes' : 'No', highlight: results.valid ? 'danger' : '' });
      } else if (d.result !== undefined) {
        fields.push({ label: 'Phishing', value: d.result === 'phishing' ? '⚠ Confirmed' : 'Not in database', highlight: d.result === 'phishing' ? 'danger' : 'success' });
      }
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsURLscan(d) {
      const fields = [];
      if (d.total !== undefined) fields.push({ label: 'Scans found', value: String(d.total), highlight: d.total > 0 ? 'warning' : '' });
      if (d.results && d.results.length) {
        const first = d.results[0];
        const page = first.page || {};
        if (page.domain) fields.push({ label: 'Domain', value: page.domain, highlight: '' });
        if (page.country) fields.push({ label: 'Country', value: page.country, highlight: '' });
        if (page.asnname) fields.push({ label: 'ASN', value: page.asnname, highlight: '' });
        const v = (first.verdicts || {}).overall || {};
        if (v.malicious !== undefined) fields.push({ label: 'Verdict', value: v.malicious ? '⚠ Malicious' : 'Clean', highlight: v.malicious ? 'danger' : 'success' });
        if (v.score) fields.push({ label: 'Score', value: String(v.score), highlight: v.score > 50 ? 'danger' : v.score > 0 ? 'warning' : '' });
        const task = first.task || {};
        if (task.time) fields.push({ label: 'Scan date', value: this.formatDate(task.time), highlight: '' });
        if (first.result) fields.push({ label: 'Report', value: first.result, isLink: true, highlight: '' });
      }
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsCensys(d) {
      const fields = [];
      // Censys v2 wraps data under "result"
      const data = (d.result && typeof d.result === 'object') ? d.result : d;
      if (data.ip) fields.push({ label: 'IP', value: data.ip, highlight: '' });
      if (data.location) {
        const loc = data.location;
        fields.push({ label: 'Location', value: [loc.city, loc.province, loc.country].filter(Boolean).join(', '), highlight: '' });
      }
      if (data.autonomous_system) {
        const as = data.autonomous_system;
        fields.push({ label: 'ASN', value: `AS${as.asn || ''} ${as.name || as.description || ''}`.trim(), highlight: '' });
      }
      if (data.services && data.services.length) {
        const ports = data.services.map(s => `${s.port}/${(s.transport_protocol || '').toLowerCase()}`.replace(/\/$/, '')).slice(0, 8);
        fields.push({ label: 'Open ports', value: ports.join(', '), highlight: 'warning' });
        const names = [...new Set(data.services.map(s => s.service_name).filter(n => n && n !== 'UNKNOWN'))].slice(0, 6);
        if (names.length) fields.push({ label: 'Services', value: names.join(', '), highlight: '' });
      }
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsSecurityTrails(d) {
      const fields = [];
      if (d.current_dns) {
        const dns = d.current_dns;
        if (dns.a && dns.a.values) fields.push({ label: 'A records', value: dns.a.values.map(v => v.ip || v).slice(0, 5).join(', '), highlight: '' });
        if (dns.aaaa && dns.aaaa.values) fields.push({ label: 'AAAA records', value: dns.aaaa.values.map(v => v.ipv6 || v).slice(0, 3).join(', '), highlight: '' });
        if (dns.mx && dns.mx.values) fields.push({ label: 'MX records', value: dns.mx.values.map(v => v.hostname || v).slice(0, 5).join(', '), highlight: '' });
        if (dns.ns && dns.ns.values) fields.push({ label: 'NS records', value: dns.ns.values.map(v => v.nameserver || v).slice(0, 5).join(', '), highlight: '' });
        if (dns.txt && dns.txt.values) fields.push({ label: 'TXT records', value: dns.txt.values.map(v => (v.value || String(v)).slice(0, 60)).slice(0, 3).join(' | '), highlight: '' });
        if (dns.cname && dns.cname.values) fields.push({ label: 'CNAME', value: dns.cname.values.map(v => v.hostname || v).slice(0, 3).join(', '), highlight: '' });
      }
      if (d.hostname) fields.push({ label: 'Hostname', value: d.hostname, highlight: '' });
      if (d.alexa_rank) fields.push({ label: 'Alexa rank', value: String(d.alexa_rank), highlight: '' });
      if (d.whois && d.whois.registrar) fields.push({ label: 'Registrar', value: d.whois.registrar, highlight: '' });
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsHIBP(d) {
      if (Array.isArray(d)) {
        if (d.length === 0) return [{ label: 'Status', value: '✅ Not found in any breach', highlight: 'success' }];
        const top = d.slice(0, 5).map(b => `${b.Name || b.name || '?'} (${b.BreachDate || b.breach_date || '?'})`).join(', ');
        return [
          { label: 'Breaches found', value: String(d.length), highlight: 'danger' },
          { label: 'Top breaches', value: top + (d.length > 5 ? ` +${d.length - 5} more` : ''), highlight: 'warning' },
        ];
      }
      return this._fieldsGeneric(d);
    },

    _fieldsIntelX(d) {
      const fields = [];
      if (d.total !== undefined) fields.push({ label: 'Total results', value: String(d.total), highlight: d.total > 0 ? 'warning' : '' });
      if (d.records && d.records.length) {
        fields.push({ label: 'Records returned', value: String(d.records.length), highlight: '' });
        const types = [...new Set(d.records.map(r => r.type || '').filter(Boolean))].slice(0, 5);
        if (types.length) fields.push({ label: 'Data types', value: types.join(', '), highlight: '' });
        const buckets = [...new Set(d.records.map(r => r.bucket || '').filter(Boolean))].slice(0, 5);
        if (buckets.length) fields.push({ label: 'Buckets', value: buckets.join(', '), highlight: '' });
        // Most recent record date
        const dates = d.records.map(r => r.date).filter(Boolean).sort().reverse();
        if (dates.length) fields.push({ label: 'Latest record', value: this.formatDate(dates[0]), highlight: '' });
      }
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsMalwareBazaar(d) {
      const fields = [];
      const qs = d.query_status;
      if (qs) fields.push({ label: 'Status', value: qs, highlight: qs === 'ok' ? 'danger' : qs === 'hash_not_found' ? 'success' : '' });
      const samples = d.data;
      if (samples && samples.length) {
        const s = samples[0];
        if (s.file_name) fields.push({ label: 'File name', value: s.file_name, highlight: '' });
        if (s.file_type) fields.push({ label: 'File type', value: s.file_type, highlight: '' });
        if (s.file_size) fields.push({ label: 'File size', value: s.file_size + ' bytes', highlight: '' });
        if (s.signature) fields.push({ label: 'Signature', value: s.signature, highlight: 'danger' });
        if (s.tags && s.tags.length) fields.push({ label: 'Tags', value: s.tags.slice(0, 6).join(', '), highlight: 'warning' });
        if (s.first_seen) fields.push({ label: 'First seen', value: s.first_seen, highlight: '' });
        if (s.last_seen) fields.push({ label: 'Last seen', value: s.last_seen, highlight: '' });
        if (s.delivery_method) fields.push({ label: 'Delivery', value: s.delivery_method, highlight: '' });
        if (samples.length > 1) fields.push({ label: 'Sample count', value: String(samples.length), highlight: '' });
      }
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsThreatFox(d) {
      const fields = [];
      const qs = d.query_status;
      if (qs) fields.push({ label: 'Status', value: qs, highlight: qs === 'ok' ? 'danger' : qs === 'no_result' ? 'success' : '' });
      const iocs = d.data;
      if (iocs && iocs.length) {
        const first = iocs[0];
        if (first.malware) fields.push({ label: 'Malware family', value: first.malware, highlight: 'danger' });
        if (first.malware_alias) fields.push({ label: 'Malware alias', value: first.malware_alias, highlight: '' });
        if (first.ioc_type) fields.push({ label: 'IOC type', value: first.ioc_type, highlight: '' });
        if (first.confidence_level !== undefined) fields.push({ label: 'Confidence', value: `${first.confidence_level}%`, highlight: first.confidence_level >= 75 ? 'danger' : 'warning' });
        if (first.first_seen) fields.push({ label: 'First seen', value: first.first_seen, highlight: '' });
        if (first.last_seen) fields.push({ label: 'Last seen', value: first.last_seen, highlight: '' });
        const allTags = iocs.flatMap(i => i.tags || []).filter(Boolean);
        if (allTags.length) fields.push({ label: 'Tags', value: [...new Set(allTags)].slice(0, 6).join(', '), highlight: 'warning' });
        if (iocs.length > 1) fields.push({ label: 'IOC entries', value: String(iocs.length), highlight: '' });
      }
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsGeneric(d) {
      if (!d || typeof d !== 'object') return [{ label: 'Data', value: String(d), highlight: '' }];
      const important = ['ip', 'ip_str', 'domain', 'url', 'country', 'country_name', 'org', 'isp', 'asn', 'threat', 'score', 'result', 'status', 'message'];
      const fields = [];
      important.forEach(k => {
        if (d[k] !== undefined && d[k] !== null && d[k] !== '') {
          fields.push({ label: this._humanKey(k), value: String(d[k]).substring(0, 200), highlight: '' });
        }
      });
      Object.entries(d).forEach(([k, v]) => {
        if (fields.length >= 8) return;
        if (important.includes(k)) return;
        if (v === null || v === undefined || v === '') return;
        if (typeof v === 'object') return;
        fields.push({ label: this._humanKey(k), value: String(v).substring(0, 200), highlight: '' });
      });
      return fields.length ? fields : [{ label: 'Raw', value: JSON.stringify(d).substring(0, 300), highlight: '' }];
    },

    _humanKey(k) {
      return k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    },

    // ── Rich per-source detail helpers (used by Sources tab) ─────────────

    // VirusTotal: list of malicious/suspicious engine results
    vtEngineDetections(d) {
      if (!d) return [];
      // v2 style
      if (d.scans && typeof d.scans === 'object') {
        return Object.entries(d.scans)
          .filter(([, v]) => v && v.detected)
          .map(([engine, v]) => ({ engine, result: v.result || 'malicious', category: 'antivirus' }))
          .slice(0, 30);
      }
      // v3 style
      const attrs = (d.data && d.data.attributes) ? d.data.attributes : (d.attributes || {});
      const results = attrs.last_analysis_results || {};
      return Object.entries(results)
        .filter(([, v]) => v && (v.category === 'malicious' || v.category === 'suspicious'))
        .map(([engine, v]) => ({ engine, result: v.result || v.category, category: v.category }))
        .slice(0, 30);
    },

    // AbuseIPDB: list of recent abuse reports
    abuseRecentReports(d) {
      const data = (d && d.data) ? d.data : (d || {});
      const reports = data.reports || [];
      return reports.slice(0, 10).map(r => ({
        date: r.reportedAt || r.reported_at || '',
        comment: (r.comment || '').slice(0, 120),
        categories: r.categories || [],
        country: r.reporterCountryCode || '',
      }));
    },

    // Shodan: service banners from data array
    shodanServices(d) {
      if (!d || !d.data || !Array.isArray(d.data)) return [];
      return d.data.slice(0, 15).map(svc => ({
        port: svc.port || '',
        proto: svc.transport || '',
        product: svc.product || '',
        version: svc.version || '',
        cpe: (svc.cpe || svc.cpe23 || []).slice(0, 2).join(' '),
        banner: (svc.data || '').slice(0, 100).replace(/\n/g, ' '),
      }));
    },

    // URLhaus: list of malicious URLs from response
    urlhausUrlList(d) {
      if (!d || !d.urls) return [];
      return (d.urls || []).slice(0, 15).map(u => ({
        url: (u.url || '').slice(0, 100),
        status: u.url_status || u.status || '',
        threat: u.threat || '',
        date_added: u.date_added || '',
        tags: u.tags || [],
      }));
    },

    // URLscan: list of scan results
    urlscanResultList(d) {
      if (!d || !d.results) return [];
      return (d.results || []).slice(0, 10).map(r => {
        const page = r.page || {};
        const verdict = ((r.verdicts || {}).overall) || {};
        const task = r.task || {};
        return {
          url: (page.url || '').slice(0, 80),
          domain: page.domain || '',
          country: page.country || '',
          malicious: verdict.malicious || false,
          score: verdict.score || 0,
          time: task.time || '',
          report: r.result || '',
        };
      });
    },

    // MalwareBazaar: first sample details
    mbSampleDetails(d) {
      if (!d || !d.data || !d.data.length) return null;
      const s = d.data[0];
      if (!s || typeof s !== 'object') return null;
      return {
        sha256: s.sha256_hash || '',
        sha1: s.sha1_hash || '',
        md5: s.md5_hash || '',
        file_name: s.file_name || '',
        file_type: s.file_type || '',
        file_size: s.file_size || '',
        mime_type: s.mime_type || '',
        signature: s.signature || '',
        tags: s.tags || [],
        first_seen: s.first_seen || '',
        last_seen: s.last_seen || '',
        delivery_method: s.delivery_method || '',
        origin_country: s.origin_country || '',
        reporter: s.reporter || '',
      };
    },

    // ThreatFox: list of IOC entries
    tfIocEntries(d) {
      if (!d || !d.data) return [];
      const items = Array.isArray(d.data) ? d.data : [d.data];
      return items.slice(0, 10).map(e => ({
        ioc: e.ioc || '',
        ioc_type: e.ioc_type || '',
        malware: e.malware || '',
        malware_alias: e.malware_alias || '',
        confidence: e.confidence_level ?? '',
        first_seen: e.first_seen || '',
        last_seen: e.last_seen || '',
        tags: e.tags || [],
      }));
    },

    // HIBP: list of breach entries
    hibpBreachList(d) {
      if (!Array.isArray(d)) return [];
      return d.slice(0, 15).map(b => ({
        name: b.Name || b.name || '',
        date: b.BreachDate || b.breach_date || '',
        count: b.PwnCount || b.pwn_count || 0,
        data_classes: (b.DataClasses || b.data_classes || []).slice(0, 5),
        domain: b.Domain || b.domain || '',
      }));
    },

    // IntelX: list of records
    intelxRecordList(d) {
      if (!d || !d.records) return [];
      return (d.records || []).slice(0, 10).map(r => ({
        type: r.type ?? '',
        name: (r.name || '').slice(0, 80),
        date: r.date || '',
        bucket: r.bucket || '',
        size: r.size || 0,
      }));
    },

    // Censys: list of services (handle v2 result wrapper)
    censysServiceList(d) {
      const data = (d && d.result && typeof d.result === 'object') ? d.result : (d || {});
      const services = data.services || [];
      return services.slice(0, 15).map(s => ({
        port: s.port || '',
        proto: s.transport_protocol || '',
        name: s.service_name || '',
        banner: (s.banner || '').slice(0, 80),
        software: ((s.software || []).map(sw => sw.product || sw).filter(Boolean)).slice(0, 2).join(', '),
      }));
    },

    // SecurityTrails: DNS record breakdown
    stDnsBreakdown(d) {
      const dns = (d && d.current_dns) ? d.current_dns : {};
      const result = [];
      const types = { a: 'A', aaaa: 'AAAA', mx: 'MX', ns: 'NS', txt: 'TXT', cname: 'CNAME', soa: 'SOA' };
      for (const [key, label] of Object.entries(types)) {
        const vals = (dns[key] || {}).values || [];
        if (!vals.length) continue;
        const displayVals = vals.slice(0, 8).map(v => {
          if (typeof v === 'string') return v;
          return v.ip || v.hostname || v.nameserver || v.value || v.ipv6 || v.name || '(complex value)';
        });
        result.push({ type: label, values: displayVals });
      }
      return result;
    },

    // OTX alexa/whois links from raw data
    otxLinks(d) {
      if (!d) return [];
      const links = [];
      if (d.whois) links.push({ label: 'Whois', url: d.whois });
      if (d.alexa) links.push({ label: 'Alexa', url: d.alexa });
      return links;
    },

    // ── Threat level helpers (legacy, used by source cards) ───────────────
    threatLevel(source, data) {
      if (!data || typeof data !== 'object') return 'none';
      if (data.error) return 'error';
      if (data.not_found) return 'none';
      if (data.positives !== undefined) {
        if (data.positives >= 10) return 'critical';
        if (data.positives >= 4) return 'high';
        if (data.positives >= 1) return 'medium';
        return 'none';
      }
      const score = (data.data || data).abuseConfidenceScore ?? (data.data || data).abuse_confidence_score;
      if (score !== undefined) {
        if (score >= 75) return 'critical';
        if (score >= 40) return 'high';
        if (score >= 10) return 'medium';
        return 'none';
      }
      const pc = data.pulse_count ?? (data.pulse_info && data.pulse_info.count);
      if (pc !== undefined) {
        if (pc >= 20) return 'high';
        if (pc >= 5) return 'medium';
        return 'none';
      }
      if (data.query_status === 'is_malware' || (data.results && data.results.valid)) return 'high';
      if (source === 'hibp' && Array.isArray(data)) {
        if (data.length >= 5) return 'high';
        if (data.length > 0) return 'medium';
        return 'none';
      }
      return 'none';
    },

    threatLevelClass(level) {
      const map = { critical: 'ti-threat-critical', high: 'ti-threat-high', medium: 'ti-threat-medium', low: 'ti-threat-low', none: 'ti-threat-none', error: 'ti-threat-error' };
      return map[level] || 'ti-threat-none';
    },

    threatLevelLabel(level) {
      const map = { critical: '🔴 Critical', high: '🟠 High', medium: '🟡 Medium', low: '🟢 Low', none: '✅ Clean', error: '⚠️ Error' };
      return map[level] || '—';
    },

    // ── Raw data modal ─────────────────────────────────────────────────────

    openRaw(name, data) {
      this.rawModal = { show: true, source: name, data };
    },

    closeRaw() {
      this.rawModal = { show: false, source: '', data: null };
    },

    // ── History ────────────────────────────────────────────────────────────

    async openHistoryDetail(entry) {
      this.historyDetailLoading = true;
      this.historyDetailModal = { show: true, entry: null };
      try {
        const detail = await api.get(`/ti/history/${entry.id}`);
        this.historyDetailModal = { show: true, entry: detail };
      } catch (e) {
        showToast('Could not load details', 'error');
        this.historyDetailModal = { show: false, entry: null };
      } finally {
        this.historyDetailLoading = false;
      }
    },

    closeHistoryDetail() {
      this.historyDetailModal = { show: false, entry: null };
    },

    showCtxMenu(e, entry) {
      e.preventDefault();
      e.stopPropagation();
      const x = Math.min(e.clientX, window.innerWidth - 220);
      const y = Math.min(e.clientY, window.innerHeight - 130);
      this.ctxMenu = { show: true, x, y, entry };
    },

    closeCtxMenu() {
      this.ctxMenu = { show: false, x: 0, y: 0, entry: null };
    },

    ctxOpenInNewWindow() {
      const entry = this.ctxMenu.entry;
      this.closeCtxMenu();
      if (!entry) {
        window.open('/?page=threat-intel', '_blank');
        return;
      }
      const ioc = encodeURIComponent(entry.ioc_value || '');
      const iocType = encodeURIComponent(entry.ioc_type || 'ip');
      window.open(`/?page=threat-intel&ioc=${ioc}&ioc_type=${iocType}`, '_blank');
    },

    ctxCopyIoc() {
      const entry = this.ctxMenu.entry;
      this.closeCtxMenu();
      if (!entry) return;
      navigator.clipboard.writeText(entry.ioc_value || '')
        .then(() => showToast('IOC copied to clipboard', 'success'))
        .catch(() => showToast('Failed to copy', 'error'));
    },

    ctxOpenDetail() {
      const entry = this.ctxMenu.entry;
      this.closeCtxMenu();
      if (entry) this.openHistoryDetail(entry);
    },

    filteredHistory() {
      return this.history.filter(h => {
        if (this.historyFilter.type && h.ioc_type !== this.historyFilter.type) return false;
        if (this.historyFilter.source && !(h.sources || []).includes(this.historyFilter.source)) return false;
        if (this.historyFilter.date && !(h.created_at || '').startsWith(this.historyFilter.date)) return false;
        return true;
      });
    },

    clearHistoryFilters() {
      this.historyFilter = { type: '', source: '', date: '' };
    },

    availableHistorySources() {
      const set = new Set();
      this.history.forEach(h => (h.sources || []).forEach(s => set.add(s)));
      return [...set].sort();
    },

    hasActiveIntegrations() {
      return this.activeIntegrations.length > 0;
    },

    // ── Reactive state for detections search ───────────────────────────────
    detectionSearchQuery: '',

    // ── Tag classification constants ────────────────────────────────────────
    _malwareFamilyKeywords: ['malware','trojan','ransomware','backdoor','rat','stealer','botnet','rootkit','spyware','worm','dropper','downloader','loader'],
    _phishingKeywords: ['phish','phishing','scam','fraud'],
    _cleanKeywords: ['clean','harmless','benign','safe','whitelist'],

    // Sources with dedicated smart cards (generic fallback used for all others)
    _smartCardSources: ['virustotal','abuseipdb','alienvault','shodan','malwarebazaar','threatfox','urlhaus','hibp','censys','securitytrails','urlscan'],

    /**
     * Returns a CSS class for a tag based on its content.
     */
    tagBadgeClass(tag) {
      if (!tag) return 'ti-tag-default';
      const t = tag.toLowerCase();
      if (tag.startsWith('CVE') || tag.startsWith('cve')) return 'ti-tag-cve';
      if (this._malwareFamilyKeywords.some(k => t.includes(k))) return 'ti-tag-malware';
      if (this._phishingKeywords.some(k => t.includes(k))) return 'ti-tag-phishing';
      if (this._cleanKeywords.some(k => t.includes(k))) return 'ti-tag-clean';
      return 'ti-tag-default';
    },

    /**
     * Returns true if a source has a dedicated smart card template.
     */
    hasSmartCard(source) {
      return this._smartCardSources.includes(source);
    },

    // ── Computed / derived helpers ──────────────────────────────────────────

    /**
     * Returns { malicious, suspicious, undetected, harmless, timeout, total,
     *           malPct, susPct, cleanPct, unkPct } from a VT per_source data object.
     */
    vtStatsBreakdown(d) {
      if (!d) return null;
      const attrs = (d.data && d.data.attributes) ? d.data.attributes : (d.attributes || {});
      const stats = attrs.last_analysis_stats || {};
      if (!Object.keys(stats).length) {
        // v2 fallback
        if (d.positives !== undefined && d.total !== undefined) {
          const mal = d.positives || 0;
          const total = d.total || 0;
          const clean = total - mal;
          return { malicious: mal, suspicious: 0, undetected: clean, harmless: 0, timeout: 0, total,
                   malPct: total ? Math.round(mal/total*100) : 0, susPct: 0,
                   cleanPct: total ? Math.round(clean/total*100) : 0, unkPct: 0 };
        }
        return null;
      }
      const mal = stats.malicious || 0;
      const sus = stats.suspicious || 0;
      const und = stats.undetected || 0;
      const har = stats.harmless || 0;
      const tim = stats.timeout || 0;
      const total = mal + sus + und + har + tim;
      if (!total) return null;
      return {
        malicious: mal, suspicious: sus, undetected: und, harmless: har, timeout: tim, total,
        malPct:   Math.round(mal/total*100),
        susPct:   Math.round(sus/total*100),
        cleanPct: Math.round((und+har)/total*100),
        unkPct:   Math.round(tim/total*100),
      };
    },

    /**
     * Returns { malicious, suspicious, undetected, harmless, total, malPct, susPct, cleanPct }
     * Alias for backward compat.
     */
    vtDetectionBar(d) {
      return this.vtStatsBreakdown(d);
    },

    /**
     * Returns inline style string for an abuse confidence ring using conic-gradient.
     * score: 0–100
     */
    abuseScoreRingStyle(score) {
      const s = Math.max(0, Math.min(100, Number(score) || 0));
      let color = '#00cc66';
      if (s >= 75) color = '#ff4444';
      else if (s >= 40) color = '#ff9900';
      else if (s >= 15) color = '#fbbf24';
      const deg = Math.round(s / 100 * 360);
      return `background: conic-gradient(${color} ${deg}deg, rgba(255,255,255,0.08) ${deg}deg)`;
    },

    /**
     * Returns CSS class for port number (well-known / registered / ephemeral).
     */
    portClass(port) {
      const p = parseInt(port, 10);
      if (p < 1024) return 'ti-port-well-known';
      if (p < 49152) return 'ti-port-registered';
      return 'ti-port-ephemeral';
    },

    /**
     * Returns CSS class for TLP level.
     */
    tlpClass(tlp) {
      switch ((tlp || '').toLowerCase()) {
        case 'red':   return 'ti-tlp-red';
        case 'amber': return 'ti-tlp-amber';
        case 'green': return 'ti-tlp-green';
        default:      return 'ti-tlp-white';
      }
    },

    /**
     * Returns NVD link for a CVE identifier.
     */
    cveLink(cve) {
      return `https://nvd.nist.gov/vuln/detail/${cve}`;
    },

    /**
     * Formats bytes as human-readable string.
     */
    formatBytes(bytes) {
      if (!bytes && bytes !== 0) return '—';
      const b = Number(bytes);
      if (b < 1024) return b + ' B';
      if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
      if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
      return (b / 1073741824).toFixed(2) + ' GB';
    },

    /**
     * Maps AbuseIPDB numeric category IDs to human-readable names.
     * Reference: https://www.abuseipdb.com/categories
     */
    abuseCategory(num) {
      const cats = {
        1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders',
        4: 'DDoS Attack', 5: 'FTP Brute-Force', 6: 'Ping of Death',
        7: 'Phishing', 8: 'Fraud VoIP', 9: 'Open Proxy',
        10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
        13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking',
        16: 'SQL Injection', 17: 'Spoofing', 18: 'Brute-Force',
        19: 'Bad Web Bot', 20: 'Exploited Host', 21: 'Web App Attack',
        22: 'SSH', 23: 'IoT Targeted',
      };
      return cats[num] || `Category ${num}`;
    },

    /**
     * Returns normalized.timeline sorted by date descending.
     */
    get sortedTimeline() {
      const tl = (this.searchResult && this.searchResult.normalized && this.searchResult.normalized.timeline) || [];
      return tl.slice().sort((a, b) => new Date(b.date) - new Date(a.date));
    },

    /**
     * Returns normalized.detections filtered by detectionSearchQuery.
     */
    get detectionsFiltered() {
      const dets = (this.searchResult && this.searchResult.normalized && this.searchResult.normalized.detections) || [];
      const q = (this.detectionSearchQuery || '').toLowerCase().trim();
      if (!q) return dets;
      return dets.filter(d =>
        (d.engine || '').toLowerCase().includes(q) ||
        (d.result || '').toLowerCase().includes(q) ||
        (d.category || '').toLowerCase().includes(q)
      );
    },

    /**
     * Returns detections grouped by category as { [category]: detection[] }.
     */
    get detectionsByCategory() {
      const dets = this.detectionsFiltered;
      const groups = {};
      for (const det of dets) {
        const cat = det.category || 'other';
        if (!groups[cat]) groups[cat] = [];
        groups[cat].push(det);
      }
      return groups;
    },

    /**
     * Returns a color for a detection category.
     */
    detectionCategoryColor(cat) {
      const map = {
        antivirus: '#2196f3', malware: '#f44336', phishing: '#ff9800',
        abuse: '#e53935', vulnerability: '#9c27b0', data_breach: '#ab47bc',
        other: '#607d8b',
      };
      return map[(cat || '').toLowerCase()] || '#607d8b';
    },

    /**
     * Returns emoji icon for a detection category.
     */
    detectionCategoryIcon(cat) {
      const icons = {
        antivirus: '🦠', malware: '☠️', phishing: '🎣',
        abuse: '🚨', vulnerability: '🔓', data_breach: '💾',
        other: '⚠️',
      };
      return icons[(cat || '').toLowerCase()] || '⚠️';
    },

    // ── Misc helpers ───────────────────────────────────────────────────────

    resultSummary(data) {
      if (!data || typeof data !== 'object') return '—';
      if (data.error) return '⚠ ' + data.error;
      if (data.not_found) return 'Not found';
      if (data.positives !== undefined) return `${data.positives} detections`;
      const s = (data.data || data).abuseConfidenceScore ?? (data.data || data).abuse_confidence_score;
      if (s !== undefined) return `Abuse score: ${s}%`;
      const pc = data.pulse_count ?? (data.pulse_info && data.pulse_info.count);
      if (pc !== undefined) return `${pc} pulses`;
      if (data.query_status) return data.query_status;
      if (data.total !== undefined && typeof data.total === 'number') return `${data.total} results`;
      if (Array.isArray(data)) return `${data.length} records`;
      return Object.keys(data).length + ' fields';
    },

    formatDate(dateStr) {
      if (!dateStr) return '—';
      const parsedDate = new Date(dateStr);
      if (isNaN(parsedDate)) return dateStr;
      return parsedDate.toLocaleDateString() + ' ' + parsedDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    },

    prettyJson(data) {
      try { return JSON.stringify(data, null, 2); } catch { return String(data); }
    },
  }));
});
