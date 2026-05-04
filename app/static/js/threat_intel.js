/**
 * Zircon FRT — Threat Intelligence (TI) Page  [CSINT section]
 */

document.addEventListener('alpine:init', () => {
  Alpine.data('threatIntelPage', () => ({
    // Active TI integrations
    activeIntegrations: [],
    integrationsLoading: false,

    // IoC lookup form
    iocForm: { ioc: '', ioc_type: 'general' },
    lookupLoading: false,
    lookupResults: null,    // {ioc, ioc_type, results: [...]}
    rawDataModal: { show: false, source: '', data: null },

    // Collapse state for result cards
    collapsedCards: {},

    // History
    history: [],
    historyLoading: false,
    historyDetailModal: { show: false, entry: null },

    // Stats / charts
    stats: null,
    statsLoading: false,
    _charts: {},            // keyed by service_type
    _summaryChart: null,

    // Filter for history table
    historyFilter: { type: '', source: '', date: '' },

    iocTypes: ['general', 'ip', 'domain', 'hash', 'url', 'email'],

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
      } catch (e) {
        this.activeIntegrations = [];
      } finally {
        this.integrationsLoading = false;
      }
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

    _renderCharts() {
      // Per-service activity charts
      if (this.stats && this.stats.service_stats) {
        this.stats.service_stats.forEach(svc => {
          const canvasId = `ti-chart-${svc.service_type}`;
          const canvas = document.getElementById(canvasId);
          if (!canvas) return;
          if (this._charts[svc.service_type]) {
            this._charts[svc.service_type].destroy();
          }
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
              plugins: { legend: { display: false }, tooltip: { mode: 'index' } },
              scales: {
                x: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
                y: { beginAtZero: true, ticks: { color: '#94a3b8', font: { size: 10 }, stepSize: 1 }, grid: { color: 'rgba(255,255,255,0.04)' } },
              },
            },
          });
        });
      }

      // Summary pie chart for source distribution
      const summaryCanvas = document.getElementById('ti-summary-chart');
      if (summaryCanvas && this.stats && this.stats.service_stats && this.stats.service_stats.length > 0) {
        if (this._summaryChart) this._summaryChart.destroy();
        const svcs = this.stats.service_stats;
        const palette = [
          'rgba(0,255,157,0.7)', 'rgba(0,180,216,0.7)', 'rgba(255,200,0,0.7)',
          'rgba(255,80,80,0.7)', 'rgba(130,80,255,0.7)', 'rgba(0,220,130,0.7)',
          'rgba(255,140,0,0.7)', 'rgba(0,160,255,0.7)', 'rgba(200,50,200,0.7)',
          'rgba(80,200,80,0.7)', 'rgba(255,100,150,0.7)',
        ];
        this._summaryChart = new Chart(summaryCanvas, {
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
            plugins: {
              legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 11 }, boxWidth: 12 } },
              tooltip: { mode: 'index' },
            },
          },
        });
      }
    },

    async runLookup() {
      if (!this.iocForm.ioc.trim()) return;
      this.lookupLoading = true;
      this.lookupResults = null;
      this.collapsedCards = {};
      try {
        this.lookupResults = await api.post('/ti/lookup', {
          ioc: this.iocForm.ioc.trim(),
          ioc_type: this.iocForm.ioc_type,
        });
        await this.loadHistory();
        await this.loadStats();
        this.$nextTick(() => this._renderCharts());
        showToast('Lookup completed', 'success');
      } catch (e) {
        showToast('Lookup failed: ' + e.message, 'error');
      } finally {
        this.lookupLoading = false;
      }
    },

    toggleCard(source) {
      this.collapsedCards[source] = !this.collapsedCards[source];
    },

    isCollapsed(source) {
      return !!this.collapsedCards[source];
    },

    openRawData(result) {
      this.rawDataModal = { show: true, source: result.name, data: result.data };
    },

    closeRawData() {
      this.rawDataModal = { show: false, source: '', data: null };
    },

    async openHistoryDetail(entry) {
      try {
        const detail = await api.get(`/ti/history/${entry.id}`);
        this.historyDetailModal = { show: true, entry: detail };
      } catch (e) {
        showToast('Could not load details', 'error');
      }
    },

    closeHistoryDetail() {
      this.historyDetailModal = { show: false, entry: null };
    },

    filteredHistory() {
      return this.history.filter(h => {
        if (this.historyFilter.type && h.ioc_type !== this.historyFilter.type) return false;
        if (this.historyFilter.source && !h.sources.includes(this.historyFilter.source)) return false;
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

    // ── Threat level helpers ──────────────────────────────────────────────
    /**
     * Determine a threat level for a result card: 'critical','high','medium','low','none','error'
     */
    threatLevel(source, data) {
      if (!data || typeof data !== 'object') return 'none';
      if (data.error) return 'error';
      if (data.not_found) return 'none';

      // VirusTotal
      if (data.positives !== undefined) {
        if (data.positives >= 10) return 'critical';
        if (data.positives >= 4) return 'high';
        if (data.positives >= 1) return 'medium';
        return 'none';
      }
      // AbuseIPDB
      if (data.abuse_confidence_score !== undefined) {
        const s = data.abuse_confidence_score;
        if (s >= 75) return 'critical';
        if (s >= 40) return 'high';
        if (s >= 10) return 'medium';
        return 'none';
      }
      // AlienVault OTX
      if (data.pulse_count !== undefined) {
        if (data.pulse_count >= 20) return 'high';
        if (data.pulse_count >= 5) return 'medium';
        return 'none';
      }
      // URLhaus / PhishTank — if found, it's a threat
      if (data.query_status === 'is_malware' || data.query_status === 'isphishing') return 'high';
      if (data.result === 'phishing') return 'high';
      if (data.urls && Array.isArray(data.urls) && data.urls.length > 0) return 'medium';
      // HIBP — breach found
      if (Array.isArray(data) && data.length > 0 && source === 'hibp') {
        if (data.length >= 5) return 'high';
        return 'medium';
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

    // ── Per-source human-readable field renderers ─────────────────────────
    /**
     * Returns an array of {label, value, highlight} objects for human display.
     */
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
          default: return this._fieldsGeneric(data);
        }
      } catch {
        return this._fieldsGeneric(data);
      }
    },

    _fieldsVirusTotal(d) {
      const fields = [];
      if (d.positives !== undefined && d.total !== undefined) {
        const pct = d.total > 0 ? Math.round(d.positives / d.total * 100) : 0;
        fields.push({ label: 'Detections', value: `${d.positives} / ${d.total} engines (${pct}%)`, highlight: d.positives > 0 ? 'danger' : 'success' });
      }
      if (d.scan_date) fields.push({ label: 'Scan date', value: d.scan_date, highlight: '' });
      if (d.permalink) fields.push({ label: 'Report', value: d.permalink, isLink: true, highlight: '' });
      if (d.verbose_msg) fields.push({ label: 'Message', value: d.verbose_msg, highlight: '' });
      if (d.url) fields.push({ label: 'URL', value: d.url, highlight: '' });
      // Extract top detections
      if (d.scans && typeof d.scans === 'object') {
        const detected = Object.entries(d.scans).filter(([, v]) => v && v.detected).slice(0, 5);
        if (detected.length) {
          fields.push({ label: 'Top detections', value: detected.map(([name, v]) => `${name}: ${v.result || 'malicious'}`).join(', '), highlight: 'warning' });
        }
      }
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsAbuseIPDB(d) {
      const fields = [];
      if (d.abuse_confidence_score !== undefined) {
        fields.push({ label: 'Abuse confidence', value: `${d.abuse_confidence_score}%`, highlight: d.abuse_confidence_score > 50 ? 'danger' : d.abuse_confidence_score > 10 ? 'warning' : 'success' });
      }
      if (d.country_code) fields.push({ label: 'Country', value: `${d.country_name || ''} (${d.country_code})`.trim(), highlight: '' });
      if (d.isp) fields.push({ label: 'ISP', value: d.isp, highlight: '' });
      if (d.domain) fields.push({ label: 'Domain', value: d.domain, highlight: '' });
      if (d.total_reports !== undefined) fields.push({ label: 'Total reports', value: String(d.total_reports), highlight: d.total_reports > 0 ? 'warning' : '' });
      if (d.last_reported_at) fields.push({ label: 'Last reported', value: d.last_reported_at, highlight: '' });
      if (d.usage_type) fields.push({ label: 'Usage type', value: d.usage_type, highlight: '' });
      if (d.is_public !== undefined) fields.push({ label: 'Public IP', value: d.is_public ? 'Yes' : 'No', highlight: '' });
      if (d.is_whitelisted !== undefined) fields.push({ label: 'Whitelisted', value: d.is_whitelisted ? 'Yes' : 'No', highlight: d.is_whitelisted ? 'success' : '' });
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsShodan(d) {
      const fields = [];
      if (d.ip_str || d.ip) fields.push({ label: 'IP address', value: d.ip_str || d.ip, highlight: '' });
      if (d.org) fields.push({ label: 'Organisation', value: d.org, highlight: '' });
      if (d.isp) fields.push({ label: 'ISP', value: d.isp, highlight: '' });
      if (d.country_name) fields.push({ label: 'Country', value: `${d.country_name}${d.city ? ', ' + d.city : ''}`, highlight: '' });
      if (d.os) fields.push({ label: 'OS', value: d.os, highlight: '' });
      if (d.ports && d.ports.length) fields.push({ label: 'Open ports', value: d.ports.slice(0, 20).join(', ') + (d.ports.length > 20 ? '…' : ''), highlight: 'warning' });
      if (d.vulns && Object.keys(d.vulns).length) {
        const cves = Object.keys(d.vulns).slice(0, 10);
        fields.push({ label: 'CVEs', value: cves.join(', ') + (Object.keys(d.vulns).length > 10 ? '…' : ''), highlight: 'danger' });
      }
      if (d.hostnames && d.hostnames.length) fields.push({ label: 'Hostnames', value: d.hostnames.slice(0, 5).join(', '), highlight: '' });
      if (d.last_update) fields.push({ label: 'Last updated', value: d.last_update, highlight: '' });
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsAlienVault(d) {
      const fields = [];
      if (d.pulse_count !== undefined) fields.push({ label: 'Pulse count', value: String(d.pulse_count), highlight: d.pulse_count > 0 ? 'warning' : 'success' });
      if (d.reputation !== undefined) fields.push({ label: 'Reputation score', value: String(d.reputation), highlight: d.reputation < 0 ? 'danger' : '' });
      if (d.country_name) fields.push({ label: 'Country', value: d.country_name, highlight: '' });
      if (d.asn) fields.push({ label: 'ASN', value: d.asn, highlight: '' });
      if (d.type_title) fields.push({ label: 'Indicator type', value: d.type_title, highlight: '' });
      if (d.validation && d.validation.length) fields.push({ label: 'Validation', value: d.validation.map(v => v.source || '').join(', '), highlight: '' });
      if (d.sections && d.sections.length) fields.push({ label: 'Data sections', value: d.sections.join(', '), highlight: '' });
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsURLhaus(d) {
      const fields = [];
      if (d.query_status) fields.push({ label: 'Status', value: d.query_status, highlight: d.query_status === 'is_malware' ? 'danger' : 'success' });
      if (d.urlhaus_reference) fields.push({ label: 'Reference', value: d.urlhaus_reference, isLink: true, highlight: '' });
      if (d.threat) fields.push({ label: 'Threat', value: d.threat, highlight: 'danger' });
      if (d.tags && d.tags.length) fields.push({ label: 'Tags', value: d.tags.join(', '), highlight: 'warning' });
      if (d.urls_count !== undefined) fields.push({ label: 'Malicious URLs', value: String(d.urls_count), highlight: d.urls_count > 0 ? 'danger' : 'success' });
      if (d.urls && d.urls.length) {
        const latest = d.urls.slice(0, 3).map(u => u.url || '').join('; ');
        fields.push({ label: 'Recent URLs', value: latest, highlight: 'warning' });
      }
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsPhishTank(d) {
      const fields = [];
      if (d.result !== undefined) fields.push({ label: 'Phishing', value: d.result === 'phishing' ? 'Yes — confirmed phishing' : 'Not in database', highlight: d.result === 'phishing' ? 'danger' : 'success' });
      if (d.url) fields.push({ label: 'URL', value: d.url, highlight: '' });
      if (d.phish_detail_url) fields.push({ label: 'PhishTank report', value: d.phish_detail_url, isLink: true, highlight: '' });
      if (d.submission_time) fields.push({ label: 'Submitted', value: d.submission_time, highlight: '' });
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsURLscan(d) {
      const fields = [];
      if (d.total !== undefined) fields.push({ label: 'Scans found', value: String(d.total), highlight: d.total > 0 ? 'warning' : '' });
      if (d.results && d.results.length) {
        const first = d.results[0];
        if (first.page) {
          if (first.page.domain) fields.push({ label: 'Domain', value: first.page.domain, highlight: '' });
          if (first.page.country) fields.push({ label: 'Country', value: first.page.country, highlight: '' });
          if (first.page.server) fields.push({ label: 'Server', value: first.page.server, highlight: '' });
        }
        if (first.verdicts && first.verdicts.overall) {
          const v = first.verdicts.overall;
          fields.push({ label: 'Verdict', value: `${v.malicious ? '⚠ Malicious' : 'Clean'} (score: ${v.score || 0})`, highlight: v.malicious ? 'danger' : 'success' });
        }
        if (first.result) fields.push({ label: 'Report', value: first.result, isLink: true, highlight: '' });
      }
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsCensys(d) {
      const fields = [];
      if (d.total !== undefined) fields.push({ label: 'Results', value: String(d.total), highlight: '' });
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
        const ports = d.services.map(s => `${s.port}/${s.transport_protocol || ''} (${s.service_name || ''})`).slice(0, 8);
        fields.push({ label: 'Services', value: ports.join(', '), highlight: '' });
      }
      if (d.hits && d.hits.length) {
        const hit = d.hits[0];
        if (hit.ip) fields.push({ label: 'Top IP', value: hit.ip, highlight: '' });
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
      if (d.endpoint) fields.push({ label: 'Endpoint', value: d.endpoint, highlight: '' });
      if (d.records && d.records.length) fields.push({ label: 'Records found', value: String(d.records.length), highlight: '' });
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsHIBP(d) {
      if (Array.isArray(d)) {
        if (d.length === 0) return [{ label: 'Status', value: '✅ Not found in any breach', highlight: 'success' }];
        const fields = [
          { label: 'Breaches found', value: String(d.length), highlight: d.length > 0 ? 'danger' : 'success' },
        ];
        const top = d.slice(0, 5).map(b => `${b.Name || b.name || '?'} (${b.BreachDate || b.breach_date || '?'})`).join(', ');
        fields.push({ label: 'Top breaches', value: top + (d.length > 5 ? ` +${d.length - 5} more` : ''), highlight: 'warning' });
        return fields;
      }
      return this._fieldsGeneric(d);
    },

    _fieldsIntelX(d) {
      const fields = [];
      if (d.total !== undefined) fields.push({ label: 'Results', value: String(d.total), highlight: d.total > 0 ? 'warning' : '' });
      if (d.records && d.records.length) {
        fields.push({ label: 'Records found', value: String(d.records.length), highlight: '' });
        const types = [...new Set(d.records.map(r => r.type || '').filter(Boolean))].slice(0, 5);
        if (types.length) fields.push({ label: 'Data types', value: types.join(', '), highlight: '' });
      }
      return fields.length ? fields : this._fieldsGeneric(d);
    },

    _fieldsGeneric(d) {
      if (!d || typeof d !== 'object') return [{ label: 'Data', value: String(d), highlight: '' }];
      const important = ['ip', 'ip_str', 'domain', 'url', 'country', 'country_name', 'org', 'isp', 'asn', 'threat', 'score', 'result', 'status', 'message'];
      const fields = [];
      // Show important fields first
      important.forEach(k => {
        if (d[k] !== undefined && d[k] !== null && d[k] !== '') {
          fields.push({ label: this._humanKey(k), value: String(d[k]).substring(0, 200), highlight: '' });
        }
      });
      // Then other scalar fields (up to 8 total)
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

    resultSummary(data) {
      if (!data || typeof data !== 'object') return '—';
      if (data.error) return '⚠ ' + data.error;
      if (data.not_found) return 'Not found';
      if (data.positives !== undefined) return `${data.positives} detections`;
      if (data.abuse_confidence_score !== undefined) return `Abuse score: ${data.abuse_confidence_score}%`;
      if (data.pulse_count !== undefined) return `${data.pulse_count} pulses`;
      if (data.total !== undefined && typeof data.total === 'number') return `${data.total} results`;
      if (data.urls_count !== undefined) return `${data.urls_count} URLs`;
      if (data.result !== undefined) return String(data.result).substring(0, 80);
      if (Array.isArray(data)) return `${data.length} records`;
      const keys = Object.keys(data);
      return keys.length + ' fields';
    },

    formatDate(dateStr) {
      if (!dateStr) return '—';
      const d = new Date(dateStr);
      return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    },

    prettyJson(data) {
      try { return JSON.stringify(data, null, 2); } catch { return String(data); }
    },
  }));
});
