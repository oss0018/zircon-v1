/**
 * Zircon FRT — Social Listening page
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('socialListeningPage', () => ({
    rules: [],
    loading: false,
    rulesLoading: false,

    mentions: [],
    mentionsLoading: false,
    mentionsPage: 1,
    mentionsPerPage: 25,
    hasMoreMentions: false,

    alerts: [],
    alertsLoading: false,

    stats: { total_mentions: 0, sentiment_breakdown: {}, top_platforms: {} },
    timeline: { window: '24h', points: [] },
    statsWindow: '24h',
    activeTab: 'mentions',

    filterRuleId: '',
    filterPlatform: '',
    filterSeverity: '',
    filterSentiment: '',
    filterStatus: '',
    filterQ: '',

    showRuleModal: false,
    editingRule: null,
    showQuickBrandModal: false,
    quickBrand: { name: '', url: '' },
    quickBrandLoading: false,
    quickBrandError: '',
    ruleForm: {
      name: '',
      brand_id: '',
      brand_terms: '',
      hashtags: '',
      exclusions: '',
      languages: ['uk', 'ru', 'en'],
      platforms: ['reddit', 'rss', 'paste', 'twitter', 'telegram'],
      severity_threshold: 2,
      alert_on: 'EVERY_MENTION',
      schedule_cron: '*/15 * * * *',
      alert_email: '',
      alert_telegram: '',
      store_all: false,
      active: true,
    },
    brands: [],
    runningRules: {},

    async init() {
      this.loading = true;
      try {
        await this.loadBrands();
        await Promise.all([
          this.loadRules(),
          this.loadMentions(),
          this.loadAlerts(),
          this.loadStats(),
          this.loadTimeline(),
        ]);
      } finally {
        this.loading = false;
      }
    },

    async loadBrands() {
      try {
        this.brands = await api.get('/brands/');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async loadRules() {
      this.rulesLoading = true;
      try {
        this.rules = await api.get('/social-listening/');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.rulesLoading = false;
      }
    },

    async loadMentions(append = false) {
      this.mentionsLoading = true;
      try {
        const params = new URLSearchParams();
        if (this.filterRuleId) params.set('rule_id', String(this.filterRuleId));
        if (this.filterPlatform) params.set('platform', this.filterPlatform);
        if (this.filterSeverity) params.set('severity_min', String(this.filterSeverity));
        if (this.filterSentiment) params.set('sentiment', this.filterSentiment);
        if (this.filterStatus) params.set('status', this.filterStatus);
        if (this.filterQ) params.set('q', this.filterQ);
        params.set('sort', '-published_at');
        params.set('page', String(this.mentionsPage));
        params.set('per_page', String(this.mentionsPerPage));

        const data = await api.get('/social-listening/mentions?' + params.toString());
        this.mentions = append ? [...this.mentions, ...data] : data;
        this.hasMoreMentions = Array.isArray(data) && data.length === this.mentionsPerPage;
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.mentionsLoading = false;
      }
    },

    async loadAlerts() {
      this.alertsLoading = true;
      try {
        const params = new URLSearchParams();
        if (this.filterRuleId) params.set('rule_id', String(this.filterRuleId));
        if (this.filterSeverity) params.set('severity', String(this.filterSeverity));
        if (this.filterStatus) params.set('status', this.filterStatus);
        this.alerts = await api.get('/social-listening/alerts?' + params.toString());
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.alertsLoading = false;
      }
    },

    async loadStats() {
      try {
        this.stats = await api.get('/social-listening/dashboard/summary?window=' + encodeURIComponent(this.statsWindow));
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async loadTimeline() {
      try {
        this.timeline = await api.get('/social-listening/dashboard/timeline?window=' + encodeURIComponent(this.statsWindow));
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    resetMentionFilters() {
      this.mentionsPage = 1;
      return this.loadMentions(false);
    },

    async loadMoreMentions() {
      if (!this.hasMoreMentions || this.mentionsLoading) return;
      this.mentionsPage += 1;
      await this.loadMentions(true);
    },

    openCreateRule() {
      this.editingRule = null;
      this.ruleForm = {
        name: '',
        brand_id: '',
        brand_terms: '',
        hashtags: '',
        exclusions: '',
        languages: ['uk', 'ru', 'en'],
        platforms: ['reddit', 'rss', 'paste', 'twitter', 'telegram'],
        severity_threshold: 2,
        alert_on: 'EVERY_MENTION',
        schedule_cron: '*/15 * * * *',
        alert_email: '',
        alert_telegram: '',
        store_all: false,
        active: true,
      };
      this.showRuleModal = true;
    },

    openEditRule(rule) {
      this.editingRule = rule;
      this.ruleForm = {
        name: rule.name || '',
        brand_id: rule.brand_id || '',
        brand_terms: (rule.brand_terms || []).join(', '),
        hashtags: (rule.hashtags || []).join(', '),
        exclusions: (rule.exclusions || []).join(', '),
        languages: [...(rule.languages || [])],
        platforms: [...(rule.platforms || [])],
        severity_threshold: Number(rule.severity_threshold || 2),
        alert_on: rule.alert_on || 'EVERY_MENTION',
        schedule_cron: rule.schedule_cron || '*/15 * * * *',
        alert_email: rule.alert_email || '',
        alert_telegram: rule.alert_telegram || '',
        store_all: !!rule.store_all,
        active: !!rule.active,
      };
      this.showRuleModal = true;
    },

    onRuleBrandChange() {
      if (this.ruleForm.brand_id !== '__new__') return;
      this.ruleForm.brand_id = '';
      this.quickBrand = { name: '', url: '' };
      this.quickBrandError = '';
      this.showQuickBrandModal = true;
    },

    async saveQuickBrand() {
      this.quickBrandError = '';
      const name = (this.quickBrand.name || '').trim();
      const url = (this.quickBrand.url || '').trim();
      if (!name) {
        this.quickBrandError = 'Brand name is required';
        return;
      }
      this.quickBrandLoading = true;
      try {
        const created = await api.post('/brands/', {
          name,
          url,
          keywords: '',
          similarity_threshold: 0.8,
          monitoring_enabled: false,
        });
        await this.loadBrands();
        this.ruleForm.brand_id = String(created.id);
        this.showQuickBrandModal = false;
      } catch (e) {
        this.quickBrandError = e.message || 'Failed to create brand';
      } finally {
        this.quickBrandLoading = false;
      }
    },

    parseCsv(value) {
      return (value || '')
        .split(',')
        .map(v => v.trim())
        .filter(Boolean);
    },

    async saveRule() {
      try {
        const payload = {
          name: (this.ruleForm.name || '').trim(),
          brand_id: Number(this.ruleForm.brand_id),
          brand_terms: this.parseCsv(this.ruleForm.brand_terms),
          hashtags: this.parseCsv(this.ruleForm.hashtags),
          exclusions: this.parseCsv(this.ruleForm.exclusions),
          languages: this.ruleForm.languages || [],
          platforms: this.ruleForm.platforms || [],
          severity_threshold: Number(this.ruleForm.severity_threshold || 2),
          alert_on: this.ruleForm.alert_on || 'EVERY_MENTION',
          schedule_cron: (this.ruleForm.schedule_cron || '').trim() || '*/15 * * * *',
          alert_email: (this.ruleForm.alert_email || '').trim(),
          alert_telegram: (this.ruleForm.alert_telegram || '').trim(),
          store_all: !!this.ruleForm.store_all,
          active: !!this.ruleForm.active,
        };
        if (this.editingRule) {
          await api.patch(`/social-listening/${this.editingRule.id}`, payload);
          showToast('Rule updated', 'success');
        } else {
          await api.post('/social-listening/', payload);
          showToast('Rule created', 'success');
        }
        this.showRuleModal = false;
        await this.loadRules();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async deleteRule(id) {
      if (!confirm(t('confirm_delete'))) return;
      try {
        await api.delete(`/social-listening/${id}`);
        this.rules = this.rules.filter(r => r.id !== id);
        showToast('Deleted', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async activateRule(id) {
      try {
        await api.post(`/social-listening/${id}/activate`, {});
        await this.loadRules();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async deactivateRule(id) {
      try {
        await api.post(`/social-listening/${id}/deactivate`, {});
        await this.loadRules();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async runRuleNow(id) {
      if (this.runningRules[id]) return;
      this.runningRules = { ...this.runningRules, [id]: true };
      try {
        await api.post(`/social-listening/${id}/run`, {});
        showToast('Run started', 'success');
        await Promise.all([this.loadMentions(), this.loadAlerts(), this.loadStats(), this.loadTimeline()]);
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.runningRules = { ...this.runningRules, [id]: false };
      }
    },

    async updateMentionStatus(id, status) {
      try {
        await api.patch(`/social-listening/mentions/${id}/status`, { status });
        await this.loadMentions();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async acknowledgeAlert(id) {
      try {
        await api.post(`/social-listening/alerts/${id}/acknowledge`, {});
        await this.loadAlerts();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async exportMentions(format) {
      try {
        const params = new URLSearchParams({ format });
        const url = (window.API_BASE || '/api/v1') + '/social-listening/mentions/export?' + params.toString();
        const token = localStorage.getItem('zircon_token');
        const resp = await fetch(url, { headers: token ? { Authorization: 'Bearer ' + token } : {} });
        if (!resp.ok) throw new Error('Export failed');
        const blob = await resp.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `social_listening_mentions.${format}`;
        a.click();
        URL.revokeObjectURL(a.href);
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async changeStatsWindow(w) {
      this.statsWindow = w;
      await Promise.all([this.loadStats(), this.loadTimeline()]);
    },

    platformColor(platform) {
      const key = String(platform || '').toLowerCase();
      const map = {
        reddit: 'badge badge-red',
        rss: 'badge badge-blue',
        paste: 'badge badge-yellow',
        twitter: 'badge badge-purple',
        telegram: 'badge badge-green',
        habrahabr: 'badge badge-blue',
      };
      return map[key] || 'badge badge-gray';
    },

    platformLabel(platform) {
      const key = String(platform || '').toLowerCase();
      const map = {
        reddit: 'Reddit',
        rss: 'RSS',
        paste: 'Paste',
        twitter: 'X (Twitter)',
        telegram: 'Telegram',
        habrahabr: 'Habrahabr',
      };
      return map[key] || String(platform || 'unknown');
    },

    severityColor(severity) {
      const value = Number(severity || 1);
      if (value >= 5) return 'badge badge-red';
      if (value >= 4) return 'badge badge-yellow';
      if (value >= 3) return 'badge badge-blue';
      if (value >= 2) return 'badge badge-green';
      return 'badge badge-gray';
    },

    sentimentColor(label) {
      const key = String(label || 'NEU').toUpperCase();
      if (key === 'NEG') return 'badge badge-red';
      if (key === 'POS') return 'badge badge-green';
      return 'badge badge-gray';
    },

    alertTypeLabel(type) {
      const map = {
        FIRST_MENTION: 'First Mention',
        NEGATIVE_SPIKE: 'Negative Spike',
        CREDENTIAL_LEAK: 'Credential Leak',
        IMPERSONATION: 'Impersonation',
      };
      return map[type] || type || 'Unknown';
    },

    mentionStatusColor(status) {
      const map = {
        new: 'badge badge-blue',
        investigating: 'badge badge-yellow',
        resolved: 'badge badge-green',
        false_positive: 'badge badge-gray',
      };
      return map[status] || 'badge badge-gray';
    },

    brandName(brandId) {
      const brand = this.brands.find(b => b.id === brandId);
      return brand ? brand.name : `#${brandId}`;
    },
  }));
});
