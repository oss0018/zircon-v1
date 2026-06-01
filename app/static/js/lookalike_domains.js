/**
 * Zircon FRT — Look-alike Domains page
 */
(function () {
  function parseCsvTags(value) {
    return String(value || '')
      .split(',')
      .map(item => item.trim())
      .filter(Boolean)
      .filter((item, index, arr) => arr.indexOf(item) === index);
  }

  async function lookalikeFetch(path, options = {}, expectJson = true) {
    const token = localStorage.getItem('zircon_token') || sessionStorage.getItem('zircon_token') || '';
    const headers = Object.assign({}, options.headers || {});
    if (token) headers.Authorization = `Bearer ${token}`;
    const resp = await fetch(API_BASE + path, Object.assign({}, options, { headers }));
    if (resp.status === 401) {
      localStorage.removeItem('zircon_token');
      window.location.reload();
      throw new Error('Unauthorized');
    }
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: resp.statusText }));
      throw new Error(err.detail || 'Request failed');
    }
    return expectJson ? resp.json() : resp;
  }

  function normalizeBool(value) {
    if (value === true) return 'Yes';
    if (value === false) return 'No';
    return '—';
  }

  document.addEventListener('alpine:init', () => {
    Alpine.data('lookalikeDomainsPage', () => ({
      brands: [],
      rules: [],
      activeTab: 'rules',
      rulesLoading: false,
      domainsLoading: false,
      trustedLoading: false,
      drawerLoading: false,
      showRuleModal: false,
      showTrustedModal: false,
      ruleModalMode: 'create',
      editingRuleId: null,
      ruleSaving: false,
      previewLoading: false,
      previewData: null,
      previewError: '',
      previewTimer: null,
      quickPreview: null,
      exportFormat: 'csv',
      domainsResult: { items: [], total: 0, page: 1, per_page: 25 },
      trustedEntries: [],
      showDrawer: false,
      selectedDomain: null,
      drawerTab: 'overview',
      enrichLoading: false,
      alertLoading: false,
      scanProgress: {
        running: false,
        ruleId: null,
        checked: 0,
        total: 0,
        latestFqdn: '',
        summary: null,
        results: [],
      },
      domainsFilters: {
        ruleId: '',
        status: 'all',
        minThreatScore: 0,
        severity: '',
        query: '',
        page: 1,
        perPage: 25,
      },
      trustedRuleId: '',
      ruleForm: {},
      trustedForm: {
        fqdn_pattern: '',
        match_type: 'exact',
        reason: '',
      },

      async init() {
        this.resetRuleForm();
        await this.loadBrands();
        await this.loadRules();
      },

      defaultRuleForm() {
        return {
          brand_id: null,
          name: '',
          protected_domain: '',
          brand_terms_text: '',
          tld_list: 'top100',
          attack_words: 'core',
          include_idn: true,
          include_bitsquatting: true,
          max_variants: 10000,
          similarity_threshold_pct: 70,
          alert_threshold: 50,
          watch_mode_enabled: false,
          watch_feed_source: 'whoisds',
          watch_alert_email: '',
          watch_alert_telegram: '',
          watch_last_run_at: null,
          active: true,
        };
      },

      resetRuleForm() {
        this.ruleForm = this.defaultRuleForm();
        this.previewData = null;
        this.previewError = '';
      },

      brandName(brandId) {
        const brand = this.brands.find(item => item.id === brandId);
        return brand ? brand.name : '—';
      },

      formatTldLabel(value) {
        const labels = {
          top30: 'Top 30',
          top100: 'Top 100',
          top500: 'Top 500',
          full1500: 'Full 1500',
        };
        return labels[value] || value || '—';
      },

      formatAttackWordsLabel(value) {
        return value === 'extended' ? 'Extended' : 'Core';
      },

      severityLabel(level) {
        const labels = { 1: 'Info', 2: 'Low', 3: 'Medium', 4: 'High', 5: 'Critical' };
        return labels[Number(level)] || '—';
      },

      severityBadge(level) {
        const n = Number(level);
        if (n >= 5) return 'badge badge-red';
        if (n === 4) return 'badge badge-yellow';
        if (n === 3) return 'badge badge-blue';
        return 'badge badge-gray';
      },

      statusBadge(status) {
        if (status === 'registered') return 'badge badge-red';
        if (status === 'trusted') return 'badge badge-green';
        if (status === 'unregistered') return 'badge badge-gray';
        return 'badge badge-yellow';
      },

      thresholdBadgeClass() {
        const value = Number(this.ruleForm.similarity_threshold_pct || 0);
        if (value < 50) return 'badge badge-red';
        if (value >= 70 && value <= 85) return 'badge badge-green';
        return 'badge badge-yellow';
      },

      threatTone(score) {
        const value = Number(score || 0);
        if (value >= 75) return 'var(--danger)';
        if (value >= 45) return 'var(--warning)';
        return 'var(--accent-green)';
      },

      threatBarStyle(score) {
        const value = Math.max(0, Math.min(100, Number(score || 0)));
        return `width:${value}%;background:${this.threatTone(value)};height:100%;border-radius:999px;`;
      },

      progressPct() {
        if (!this.scanProgress.total) return 0;
        return Math.round((this.scanProgress.checked / this.scanProgress.total) * 100);
      },

      pagedDomainsTotal() {
        return Math.max(1, Math.ceil((this.domainsResult.total || 0) / (this.domainsFilters.perPage || 25)));
      },

      thresholdHint() {
        const value = Number(this.ruleForm.similarity_threshold_pct || 0);
        if (value < 50) return 'Low threshold — expect a noisy rule and a large variant set.';
        if (value >= 70 && value <= 85) return 'Balanced threshold — recommended range for most rules.';
        return 'Higher thresholds reduce volume but may miss weaker look-alikes.';
      },

      parsedBrandTerms() {
        return parseCsvTags(this.ruleForm.brand_terms_text);
      },

      algorithmsPreview(list) {
        const items = Array.isArray(list) ? list : [];
        if (!items.length) return '—';
        if (items.length <= 2) return items.join(', ');
        return `${items.slice(0, 2).join(', ')} +${items.length - 2} more`;
      },

      boolLabel(value) {
        return normalizeBool(value);
      },

      formatYmd(value) {
        if (!value) return '—';
        const text = String(value);
        if (text.includes('T')) return text.slice(0, 10);
        return text.slice(0, 10);
      },

      formatDateTime(value) {
        if (!value) return '—';
        try {
          return new Date(value).toLocaleString();
        } catch (_) {
          return value;
        }
      },

      countryFlag(value) {
        const code = String(value || '').trim().toUpperCase();
        if (!/^[A-Z]{2}$/.test(code)) return '🌐';
        return String.fromCodePoint(...[...code].map((ch) => 127397 + ch.charCodeAt(0)));
      },

      phashRisk(distance) {
        const value = Number(distance);
        if (!Number.isFinite(value)) return { label: '—', tone: 'badge badge-gray' };
        if (value <= 10) return { label: 'Low', tone: 'badge badge-green' };
        if (value <= 20) return { label: 'Medium', tone: 'badge badge-yellow' };
        return { label: 'High', tone: 'badge badge-red' };
      },

      similarityBarStyle(value) {
        const pct = Math.max(0, Math.min(100, Number(value || 0)));
        let color = 'var(--accent-green)';
        if (pct >= 75) color = 'var(--danger)';
        else if (pct >= 45) color = 'var(--warning)';
        return `width:${pct}%;background:${color};height:100%;border-radius:999px;`;
      },

      setDrawerTab(tab) {
        this.drawerTab = tab;
      },

      canShowTakedown() {
        if (!this.selectedDomain) return false;
        const score = Number(this.selectedDomain.threat_score || 0);
        return score >= 40 || this.selectedDomain.status === 'registered';
      },

      canSendAlert() {
        if (!this.selectedDomain) return false;
        const score = Number(this.selectedDomain.threat_score || 0);
        return score >= 50;
      },

      async loadBrands() {
        try {
          const response = await api.get('/brands/');
          this.brands = Array.isArray(response) ? response : [];
          if (this.ruleModalMode === 'create' && !this.ruleForm.brand_id && this.brands[0]) {
            this.ruleForm.brand_id = this.brands[0].id;
          }
        } catch (e) {
          this.brands = [];
          showToast(e.message, 'error');
        }
      },

      syncSelectedRules() {
        const existingIds = this.rules.map(rule => String(rule.id));
        if (!existingIds.length) {
          this.domainsFilters.ruleId = '';
          this.trustedRuleId = '';
          return;
        }
        if (!existingIds.includes(String(this.domainsFilters.ruleId))) {
          this.domainsFilters.ruleId = existingIds[0];
        }
        if (!existingIds.includes(String(this.trustedRuleId))) {
          this.trustedRuleId = existingIds[0];
        }
      },

      async loadRules() {
        this.rulesLoading = true;
        try {
          this.rules = await api.get('/lookalike/rules');
          this.syncSelectedRules();
          if (this.activeTab === 'domains' && this.domainsFilters.ruleId) {
            await this.loadDomains();
          }
          if (this.activeTab === 'trusted' && this.trustedRuleId) {
            await this.loadTrusted();
          }
        } catch (e) {
          showToast(e.message, 'error');
        } finally {
          this.rulesLoading = false;
        }
      },

      setTab(tab) {
        this.activeTab = tab;
        if (tab === 'domains' && this.domainsFilters.ruleId) {
          this.domainsFilters.page = 1;
          this.loadDomains();
        }
        if (tab === 'trusted' && this.trustedRuleId) {
          this.loadTrusted();
        }
      },

      async openCreateRuleModal() {
        this.ruleModalMode = 'create';
        this.editingRuleId = null;
        this.resetRuleForm();
        if (!this.brands.length) {
          await this.loadBrands();
        }
        if (this.brands[0]) this.ruleForm.brand_id = this.brands[0].id;
        this.showRuleModal = true;
      },

      openEditRuleModal(rule) {
        this.ruleModalMode = 'edit';
        this.editingRuleId = rule.id;
        this.ruleForm = {
          brand_id: rule.brand_id,
          name: rule.name || '',
          protected_domain: rule.protected_domain || '',
          brand_terms_text: (rule.brand_terms || []).join(', '),
          tld_list: rule.tld_list || 'top100',
          attack_words: rule.attack_words || 'core',
          include_idn: rule.include_idn !== false,
          include_bitsquatting: rule.include_bitsquatting !== false,
          max_variants: rule.max_variants || 10000,
          similarity_threshold_pct: rule.similarity_threshold_pct || 70,
          alert_threshold: rule.alert_threshold || 50,
          watch_mode_enabled: !!rule.watch_mode_enabled,
          watch_feed_source: rule.watch_feed_source || 'whoisds',
          watch_alert_email: rule.watch_alert_email || '',
          watch_alert_telegram: rule.watch_alert_telegram || '',
          watch_last_run_at: rule.watch_last_run_at || null,
          active: rule.active !== false,
        };
        this.previewData = null;
        this.previewError = '';
        this.showRuleModal = true;
        this.scheduleRulePreview();
      },

      closeRuleModal() {
        this.showRuleModal = false;
        if (this.previewTimer) clearTimeout(this.previewTimer);
      },

      buildRulePayload() {
        const brandId = parseInt(this.ruleForm.brand_id, 10);
        return {
          brand_id: Number.isInteger(brandId) ? brandId : null,
          name: String(this.ruleForm.name || '').trim(),
          protected_domain: String(this.ruleForm.protected_domain || '').trim(),
          brand_terms: this.parsedBrandTerms(),
          tld_list: this.ruleForm.tld_list,
          attack_words: this.ruleForm.attack_words,
          include_idn: !!this.ruleForm.include_idn,
          include_bitsquatting: !!this.ruleForm.include_bitsquatting,
          max_variants: Number(this.ruleForm.max_variants || 0),
          similarity_threshold_pct: Number(this.ruleForm.similarity_threshold_pct || 0),
          alert_threshold: Number(this.ruleForm.alert_threshold || 50),
          watch_mode_enabled: !!this.ruleForm.watch_mode_enabled,
          watch_feed_source: String(this.ruleForm.watch_feed_source || 'whoisds'),
          watch_alert_email: String(this.ruleForm.watch_alert_email || '').trim(),
          watch_alert_telegram: String(this.ruleForm.watch_alert_telegram || '').trim(),
          active: !!this.ruleForm.active,
        };
      },

      async triggerWatchMode(rule) {
        try {
          const summary = await api.post(`/lookalike/rules/${rule.id}/watch/trigger`, {});
          const status = await api.get(`/lookalike/rules/${rule.id}/watch/status`);
          rule.watch_last_run_at = status.watch_last_run_at;
          rule.watch_mode_enabled = status.watch_mode_enabled;
          rule.watch_feed_source = status.watch_feed_source;
          if (this.editingRuleId && Number(this.editingRuleId) === Number(rule.id)) {
            this.ruleForm.watch_last_run_at = status.watch_last_run_at;
            this.ruleForm.watch_mode_enabled = status.watch_mode_enabled;
            this.ruleForm.watch_feed_source = status.watch_feed_source;
          }
          showToast(`Watch mode: checked ${summary.checked}, matched ${summary.matched}, alerted ${summary.alerted}`, 'success');
        } catch (e) {
          showToast(e.message, 'error');
        }
      },

      scheduleRulePreview() {
        if (this.previewTimer) clearTimeout(this.previewTimer);
        this.previewError = '';
        if (!String(this.ruleForm.protected_domain || '').trim()) {
          this.previewData = null;
          return;
        }
        this.previewTimer = setTimeout(() => this.loadRulePreview(), 600);
      },

      async loadRulePreview() {
        this.previewLoading = true;
        this.previewError = '';
        try {
          this.previewData = await lookalikeFetch('/lookalike/preview', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(this.buildRulePayload()),
          });
        } catch (e) {
          this.previewError = e.message;
          this.previewData = null;
        } finally {
          this.previewLoading = false;
        }
      },

      async saveRule() {
        const payload = this.buildRulePayload();
        if (!Number.isInteger(payload.brand_id) || payload.brand_id <= 0 || !payload.name || !payload.protected_domain) {
          showToast('Brand, rule name, and protected domain are required.', 'error');
          return;
        }
        this.ruleSaving = true;
        try {
          let saved;
          if (this.ruleModalMode === 'edit' && this.editingRuleId) {
            const patchPayload = Object.assign({}, payload);
            delete patchPayload.brand_id;
            saved = await api.patch(`/lookalike/rules/${this.editingRuleId}`, patchPayload);
            showToast('Rule updated', 'success');
          } else {
            saved = await api.post('/lookalike/rules', payload);
            showToast('Rule created', 'success');
          }
          this.closeRuleModal();
          await this.loadRules();
          if (saved && saved.id) {
            this.domainsFilters.ruleId = String(saved.id);
            this.trustedRuleId = String(saved.id);
          }
        } catch (e) {
          showToast(e.message, 'error');
        } finally {
          this.ruleSaving = false;
        }
      },

      async deleteRule(rule) {
        if (!confirm(t('confirm_delete'))) return;
        try {
          await api.delete(`/lookalike/rules/${rule.id}`);
          showToast('Rule deleted', 'success');
          if (String(this.domainsFilters.ruleId) === String(rule.id)) this.domainsFilters.ruleId = '';
          if (String(this.trustedRuleId) === String(rule.id)) this.trustedRuleId = '';
          await this.loadRules();
        } catch (e) {
          showToast(e.message, 'error');
        }
      },

      async previewRule(rule) {
        try {
          this.quickPreview = {
            ruleId: rule.id,
            ruleName: rule.name,
            loading: true,
            data: null,
          };
          const data = await lookalikeFetch(`/lookalike/rules/${rule.id}/preview?simulate_threshold=${encodeURIComponent(rule.similarity_threshold_pct || 70)}`, {
            method: 'POST',
          });
          this.quickPreview = {
            ruleId: rule.id,
            ruleName: rule.name,
            loading: false,
            data,
          };
        } catch (e) {
          this.quickPreview = null;
          showToast(e.message, 'error');
        }
      },

      viewRuleDomains(rule) {
        this.domainsFilters.ruleId = String(rule.id);
        this.activeTab = 'domains';
        this.domainsFilters.page = 1;
        this.loadDomains();
      },

      async runRuleScan(rule) {
        this.scanProgress = {
          running: true,
          ruleId: rule.id,
          checked: 0,
          total: 0,
          latestFqdn: '',
          summary: null,
          results: [],
        };
        try {
          const resp = await lookalikeFetch(`/lookalike/rules/${rule.id}/scan`, { method: 'POST' }, false);
          const reader = resp.body.getReader();
          const decoder = new TextDecoder();
          let buffer = '';
          let currentEvent = 'message';
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';
            for (const line of lines) {
              if (line.startsWith('event: ')) {
                currentEvent = line.slice(7).trim();
                continue;
              }
              if (!line.startsWith('data: ')) continue;
              const payload = JSON.parse(line.slice(6));
              if (currentEvent === 'done') {
                this.scanProgress.summary = payload;
                this.scanProgress.running = false;
                currentEvent = 'message';
                continue;
              }
              this.scanProgress.checked = payload.checked || 0;
              this.scanProgress.total = payload.total || 0;
              this.scanProgress.latestFqdn = payload.fqdn || '';
              this.scanProgress.results.unshift(payload);
              this.scanProgress.results = this.scanProgress.results.slice(0, 12);
            }
          }
          this.scanProgress.running = false;
          await this.loadRules();
          if (String(this.domainsFilters.ruleId) === String(rule.id)) {
            await this.loadDomains();
          }
          showToast('Look-alike scan completed', 'success');
        } catch (e) {
          this.scanProgress.running = false;
          showToast(e.message, 'error');
        }
      },

      async loadDomains() {
        if (!this.domainsFilters.ruleId) {
          this.domainsResult = { items: [], total: 0, page: 1, per_page: this.domainsFilters.perPage };
          return;
        }
        this.domainsLoading = true;
        try {
          const params = new URLSearchParams({
            page: String(this.domainsFilters.page || 1),
            per_page: String(this.domainsFilters.perPage || 25),
          });
          if (this.domainsFilters.status && this.domainsFilters.status !== 'all') params.set('status', this.domainsFilters.status);
          if (this.domainsFilters.severity) params.set('severity', String(this.domainsFilters.severity));
          if (Number(this.domainsFilters.minThreatScore) > 0) params.set('min_threat_score', String(this.domainsFilters.minThreatScore));
          if (String(this.domainsFilters.query || '').trim()) params.set('fqdn', String(this.domainsFilters.query).trim());
          this.domainsResult = await api.get(`/lookalike/rules/${this.domainsFilters.ruleId}/domains?${params.toString()}`);
        } catch (e) {
          showToast(e.message, 'error');
        } finally {
          this.domainsLoading = false;
        }
      },

      prevDomainsPage() {
        if (this.domainsFilters.page <= 1) return;
        this.domainsFilters.page -= 1;
        this.loadDomains();
      },

      nextDomainsPage() {
        if (this.domainsFilters.page >= this.pagedDomainsTotal()) return;
        this.domainsFilters.page += 1;
        this.loadDomains();
      },

      async exportDomains() {
        if (!this.domainsFilters.ruleId) return;
        try {
          const format = this.exportFormat || 'csv';
          const resp = await lookalikeFetch(`/lookalike/rules/${this.domainsFilters.ruleId}/domains/export?format=${encodeURIComponent(format)}`, {}, false);
          const blob = await resp.blob();
          const url = window.URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = url;
          link.download = `lookalike-rule-${this.domainsFilters.ruleId}.${format}`;
          document.body.appendChild(link);
          link.click();
          link.remove();
          window.URL.revokeObjectURL(url);
          showToast(`Exported ${format.toUpperCase()}`, 'success');
        } catch (e) {
          showToast(e.message, 'error');
        }
      },

      async openDomainDrawer(domain) {
        this.showDrawer = true;
        this.drawerLoading = true;
        this.selectedDomain = null;
        this.drawerTab = 'overview';
        try {
          this.selectedDomain = await api.get(`/lookalike/domains/${domain.id}`);
        } catch (e) {
          this.showDrawer = false;
          showToast(e.message, 'error');
        } finally {
          this.drawerLoading = false;
        }
      },

      closeDrawer() {
        this.showDrawer = false;
      },

      async updateSelectedDomain(body, successMessage) {
        if (!this.selectedDomain) return;
        try {
          await api.patch(`/lookalike/domains/${this.selectedDomain.id}`, body);
          this.selectedDomain = await api.get(`/lookalike/domains/${this.selectedDomain.id}`);
          await this.loadDomains();
          showToast(successMessage, 'success');
        } catch (e) {
          showToast(e.message, 'error');
        }
      },

      markFalsePositive() {
        if (!this.selectedDomain) return;
        const reason = window.prompt('False positive reason', this.selectedDomain.fp_reason || '');
        if (reason === null) return;
        this.updateSelectedDomain({ is_false_positive: true, fp_reason: reason }, 'Marked as false positive');
      },

      clearFalsePositive() {
        this.updateSelectedDomain({ is_false_positive: false, fp_reason: '' }, 'False positive cleared');
      },

      markTrusted() {
        this.updateSelectedDomain({ status: 'trusted' }, 'Domain marked as trusted');
      },

      async enrichSelectedDomain() {
        if (!this.selectedDomain || this.enrichLoading) return;
        this.enrichLoading = true;
        try {
          this.selectedDomain = await lookalikeFetch(
            `/lookalike/rules/${this.selectedDomain.rule_id}/domains/${this.selectedDomain.id}/enrich`,
            { method: 'POST' }
          );
          await this.loadDomains();
          showToast('Domain enrichment complete', 'success');
        } catch (e) {
          showToast(e.message || 'Enrichment failed', 'error');
        } finally {
          this.enrichLoading = false;
        }
      },

      async downloadTakedownPackage() {
        if (!this.selectedDomain) return;
        try {
          const resp = await lookalikeFetch(
            `/lookalike/rules/${this.selectedDomain.rule_id}/domains/${this.selectedDomain.id}/takedown`,
            {},
            false
          );
          const blob = await resp.blob();
          const url = window.URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = url;
          link.download = `takedown_rule${this.selectedDomain.rule_id}_domain${this.selectedDomain.id}.txt`;
          document.body.appendChild(link);
          link.click();
          link.remove();
          window.URL.revokeObjectURL(url);
        } catch (e) {
          showToast(e.message || 'Failed to download takedown package', 'error');
        }
      },

      async sendDomainAlert() {
        if (!this.selectedDomain || this.alertLoading) return;
        this.alertLoading = true;
        try {
          await lookalikeFetch(`/lookalike/rules/${this.selectedDomain.rule_id}/alert`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain_id: this.selectedDomain.id }),
          });
          showToast('Alert dispatched', 'success');
        } catch (e) {
          showToast(e.message || 'Alert dispatch failed', 'error');
        } finally {
          this.alertLoading = false;
        }
      },

      async loadTrusted() {
        if (!this.trustedRuleId) {
          this.trustedEntries = [];
          return;
        }
        this.trustedLoading = true;
        try {
          this.trustedEntries = await api.get(`/lookalike/rules/${this.trustedRuleId}/trusted`);
        } catch (e) {
          showToast(e.message, 'error');
        } finally {
          this.trustedLoading = false;
        }
      },

      openTrustedModal() {
        this.trustedForm = { fqdn_pattern: '', match_type: 'exact', reason: '' };
        this.showTrustedModal = true;
      },

      async saveTrusted() {
        if (!this.trustedRuleId) {
          showToast('Select a rule first.', 'error');
          return;
        }
        try {
          await api.post(`/lookalike/rules/${this.trustedRuleId}/trusted`, this.trustedForm);
          this.showTrustedModal = false;
          await this.loadTrusted();
          showToast('Trusted domain added', 'success');
        } catch (e) {
          showToast(e.message, 'error');
        }
      },

      async deleteTrusted(entry) {
        if (!confirm(t('confirm_delete'))) return;
        try {
          await api.delete(`/lookalike/rules/${this.trustedRuleId}/trusted/${entry.id}`);
          await this.loadTrusted();
          showToast('Trusted domain removed', 'success');
        } catch (e) {
          showToast(e.message, 'error');
        }
      },
    }));
  });
})();
