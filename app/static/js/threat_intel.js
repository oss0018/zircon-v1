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
    _charts: {},
    _summaryChart: null,
    _severityChart: null,

    // History filter
    historyFilter: { type: '', source: '', date: '' },

    iocTypes: ['ip', 'domain', 'hash', 'url', 'email', 'general'],

    async init() {
      await Promise.all([
        this.loadIntegrations(),
        this.loadHistory(),
        this.loadStats(),
      ]);
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
      try {
        this.stats = await api.get('/ti/stats');
        this.$nextTick(() => this._renderCharts());
      } catch (e) {
        this.stats = null;
      } finally {
        this.statsLoading = false;
      }
    },

    // ── Chart rendering ────────────────────────────────────────────────────

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
      const total = Object.values(stats).reduce((a, b) => a + b, 0) || 0;
      if (total > 0) fields.push({ label: 'Detections', value: `${mal} / ${total} engines`, highlight: mal > 0 ? 'danger' : 'success' });
      if (attrs.meaningful_name) fields.push({ label: 'Name', value: attrs.meaningful_name, highlight: '' });
      if (attrs.type_description) fields.push({ label: 'Type', value: attrs.type_description, highlight: '' });
      const tags = attrs.tags || [];
      if (tags.length) fields.push({ label: 'Tags', value: tags.slice(0, 6).join(', '), highlight: 'warning' });
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsAbuseIPDB(d) {
      const data = d.data || d;
      const fields = [];
      const score = data.abuseConfidenceScore ?? data.abuse_confidence_score ?? null;
      if (score !== null) fields.push({ label: 'Abuse confidence', value: `${score}%`, highlight: score > 50 ? 'danger' : score > 10 ? 'warning' : 'success' });
      if (data.countryName || data.country_name) fields.push({ label: 'Country', value: `${data.countryName || data.country_name}${data.countryCode ? ' (' + data.countryCode + ')' : ''}`, highlight: '' });
      if (data.isp) fields.push({ label: 'ISP', value: data.isp, highlight: '' });
      const reports = data.totalReports ?? data.total_reports ?? 0;
      if (reports !== undefined) fields.push({ label: 'Reports', value: String(reports), highlight: reports > 0 ? 'warning' : '' });
      if (data.lastReportedAt || data.last_reported_at) fields.push({ label: 'Last reported', value: data.lastReportedAt || data.last_reported_at, highlight: '' });
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsShodan(d) {
      const fields = [];
      if (d.ip_str || d.ip) fields.push({ label: 'IP', value: d.ip_str || d.ip, highlight: '' });
      if (d.org) fields.push({ label: 'Organization', value: d.org, highlight: '' });
      if (d.country_name) fields.push({ label: 'Country', value: `${d.country_name}${d.city ? ', ' + d.city : ''}`, highlight: '' });
      if (d.os) fields.push({ label: 'OS', value: d.os, highlight: '' });
      if (d.ports && d.ports.length) fields.push({ label: 'Open ports', value: d.ports.slice(0, 20).join(', ') + (d.ports.length > 20 ? '…' : ''), highlight: 'warning' });
      if (d.vulns && Object.keys(d.vulns).length) {
        const cves = Object.keys(d.vulns).slice(0, 8);
        fields.push({ label: 'CVEs', value: cves.join(', ') + (Object.keys(d.vulns).length > 8 ? '…' : ''), highlight: 'danger' });
      }
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsAlienVault(d) {
      const fields = [];
      const pulseCount = (d.pulse_info && d.pulse_info.count !== undefined) ? d.pulse_info.count : (d.pulse_count || 0);
      fields.push({ label: 'Pulse count', value: String(pulseCount), highlight: pulseCount > 0 ? 'warning' : 'success' });
      if (d.reputation !== undefined) fields.push({ label: 'Reputation', value: String(d.reputation), highlight: d.reputation < 0 ? 'danger' : '' });
      if (d.country_name) fields.push({ label: 'Country', value: d.country_name, highlight: '' });
      if (d.asn) fields.push({ label: 'ASN', value: d.asn, highlight: '' });
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
        const v = (first.verdicts || {}).overall || {};
        if (v.malicious !== undefined) fields.push({ label: 'Verdict', value: v.malicious ? '⚠ Malicious' : 'Clean', highlight: v.malicious ? 'danger' : 'success' });
      }
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsCensys(d) {
      const fields = [];
      if (d.ip) fields.push({ label: 'IP', value: d.ip, highlight: '' });
      if (d.location) {
        const loc = d.location;
        fields.push({ label: 'Location', value: [loc.city, loc.province, loc.country].filter(Boolean).join(', '), highlight: '' });
      }
      if (d.autonomous_system) {
        const as = d.autonomous_system;
        fields.push({ label: 'ASN', value: `AS${as.asn || ''} ${as.name || ''}`.trim(), highlight: '' });
      }
      if (d.services && d.services.length) {
        const ports = d.services.map(s => `${s.port}/${s.transport_protocol || ''}`.trim()).slice(0, 8);
        fields.push({ label: 'Services', value: ports.join(', '), highlight: '' });
      }
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsSecurityTrails(d) {
      const fields = [];
      if (d.current_dns) {
        const dns = d.current_dns;
        if (dns.a && dns.a.values) fields.push({ label: 'A records', value: dns.a.values.map(v => v.ip || v).slice(0, 5).join(', '), highlight: '' });
        if (dns.mx && dns.mx.values) fields.push({ label: 'MX records', value: dns.mx.values.map(v => v.hostname || v).slice(0, 5).join(', '), highlight: '' });
        if (dns.ns && dns.ns.values) fields.push({ label: 'NS records', value: dns.ns.values.map(v => v.nameserver || v).slice(0, 5).join(', '), highlight: '' });
      }
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
      if (d.total !== undefined) fields.push({ label: 'Results', value: String(d.total), highlight: d.total > 0 ? 'warning' : '' });
      if (d.records && d.records.length) {
        fields.push({ label: 'Records', value: String(d.records.length), highlight: '' });
        const types = [...new Set(d.records.map(r => r.type || '').filter(Boolean))].slice(0, 5);
        if (types.length) fields.push({ label: 'Data types', value: types.join(', '), highlight: '' });
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
        if (s.signature) fields.push({ label: 'Signature', value: s.signature, highlight: 'danger' });
        if (s.tags && s.tags.length) fields.push({ label: 'Tags', value: s.tags.slice(0, 6).join(', '), highlight: 'warning' });
        if (s.first_seen) fields.push({ label: 'First seen', value: s.first_seen, highlight: '' });
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
        if (first.malware) fields.push({ label: 'Malware', value: first.malware, highlight: 'danger' });
        if (first.ioc_type) fields.push({ label: 'IOC type', value: first.ioc_type, highlight: '' });
        if (first.confidence_level) fields.push({ label: 'Confidence', value: `${first.confidence_level}%`, highlight: '' });
        const allTags = iocs.flatMap(i => i.tags || []).filter(Boolean);
        if (allTags.length) fields.push({ label: 'Tags', value: [...new Set(allTags)].slice(0, 6).join(', '), highlight: 'warning' });
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
