/**
 * Zircon FRT — Impersonation Monitoring page
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('impersonationPage', () => ({
    activeTab: 'overview',
    stats: { total: 0, high_risk: 0, pending_takedowns: 0, active_rules: 0, by_module: {} },
    findings: [],
    findingsTotal: 0,
    findingsPage: 1,
    findingsPageSize: 25,
    findingsFilter: { module: '', platform: '', status: '', min_score: 0 },
    rules: [],
    ruleForm: { show: false, editing: null, data: {} },
    takedowns: [],
    takedownsFilter: { status: '', platform: '' },
    loading: false,
    findingsLoading: false,
    rulesLoading: false,
    takedownsLoading: false,
    expandedFindingId: null,
    expandedTakedownId: null,
    moduleMeta: {
      m1: { label: 'M1 Social', badge: 'badge badge-blue' },
      m2: { label: 'M2 Apps', badge: 'badge badge-purple' },
      m3: { label: 'M3 Email', badge: 'badge badge-orange' },
      m5: { label: 'M5 Executive', badge: 'badge badge-red' },
      m6: { label: 'M6 Ads', badge: 'badge badge-yellow' },
      m7: { label: 'M7 VIP', badge: 'badge badge-gray' },
      m8: { label: 'M8 Domains', badge: 'badge badge-green' },
    },

    init() {
      this.resetRuleForm();
      this.refreshAll();
    },

    defaultRuleData() {
      return {
        name: '',
        brand_id: '',
        brand_name: '',
        brand_name_uk: '',
        brand_name_ru: '',
        official_domains_text: '',
        official_developer_ids_text: '',
        executive_names_text: '',
        partner_domains_text: '',
        trademark_name: '',
        trademark_reg_no: '',
        org_name: '',
        contact_name: '',
        contact_email: '',
        contact_phone: '',
        m1_social_enabled: true,
        m2_apps_enabled: true,
        m3_email_enabled: true,
        m5_exec_enabled: true,
        m6_ads_enabled: true,
        m7_vip_enabled: true,
        m8_domain_enabled: true,
        social_platforms_text: 'telegram, instagram, vk, facebook',
        min_impersonation_score: 40,
        schedule_cron: '0 */6 * * *',
        active: true,
      };
    },

    resetRuleForm() {
      this.ruleForm = { show: false, editing: null, data: this.defaultRuleData() };
    },

    async refreshAll() {
      this.loading = true;
      try {
        await Promise.all([this.loadStats(), this.loadFindings(), this.loadRules(), this.loadTakedowns()]);
      } finally {
        this.loading = false;
      }
    },

    async loadStats() {
      try {
        this.stats = await api.get('/impersonation/stats');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async loadFindings() {
      this.findingsLoading = true;
      try {
        const params = new URLSearchParams();
        if (this.findingsFilter.module) params.set('module', this.findingsFilter.module);
        if (this.findingsFilter.platform) params.set('platform', this.findingsFilter.platform);
        if (this.findingsFilter.status) params.set('status', this.findingsFilter.status);
        params.set('min_score', String(this.findingsFilter.min_score || 0));
        params.set('limit', String(this.findingsPageSize));
        params.set('offset', String((this.findingsPage - 1) * this.findingsPageSize));
        const data = await api.get('/impersonation/findings?' + params.toString());
        this.findings = Array.isArray(data.items) ? data.items : [];
        this.findingsTotal = Number(data.total || 0);
      } catch (e) {
        this.findings = [];
        this.findingsTotal = 0;
        showToast(e.message, 'error');
      } finally {
        this.findingsLoading = false;
      }
    },

    async loadRules() {
      this.rulesLoading = true;
      try {
        this.rules = await api.get('/impersonation/rules');
      } catch (e) {
        this.rules = [];
        showToast(e.message, 'error');
      } finally {
        this.rulesLoading = false;
      }
    },

    async loadTakedowns() {
      this.takedownsLoading = true;
      try {
        const params = new URLSearchParams();
        if (this.takedownsFilter.status) params.set('status', this.takedownsFilter.status);
        if (this.takedownsFilter.platform) params.set('platform', this.takedownsFilter.platform);
        this.takedowns = await api.get('/impersonation/takedowns?' + params.toString());
      } catch (e) {
        this.takedowns = [];
        showToast(e.message, 'error');
      } finally {
        this.takedownsLoading = false;
      }
    },

    changeTab(tab) {
      this.activeTab = tab;
      if (tab === 'overview') this.loadStats();
      if (tab === 'findings') this.loadFindings();
      if (tab === 'rules') this.loadRules();
      if (tab === 'takedowns') this.loadTakedowns();
    },

    parseCsv(value) {
      return String(value || '')
        .split(',')
        .map(item => item.trim())
        .filter(Boolean)
        .filter((item, index, arr) => arr.indexOf(item) === index);
    },

    openCreateRule() {
      this.ruleForm = { show: true, editing: null, data: this.defaultRuleData() };
    },

    openEditRule(rule) {
      this.ruleForm = {
        show: true,
        editing: rule,
        data: {
          name: rule.name || '',
          brand_id: rule.brand_id || '',
          brand_name: rule.brand_name || '',
          brand_name_uk: rule.brand_name_uk || '',
          brand_name_ru: rule.brand_name_ru || '',
          official_domains_text: (rule.official_domains || []).join(', '),
          official_developer_ids_text: (rule.official_developer_ids || []).join(', '),
          executive_names_text: (rule.executive_names || []).join(', '),
          partner_domains_text: (rule.partner_domains || []).join(', '),
          trademark_name: rule.trademark_name || '',
          trademark_reg_no: rule.trademark_reg_no || '',
          org_name: rule.org_name || '',
          contact_name: rule.contact_name || '',
          contact_email: rule.contact_email || '',
          contact_phone: rule.contact_phone || '',
          m1_social_enabled: !!rule.m1_social_enabled,
          m2_apps_enabled: !!rule.m2_apps_enabled,
          m3_email_enabled: !!rule.m3_email_enabled,
          m5_exec_enabled: !!rule.m5_exec_enabled,
          m6_ads_enabled: !!rule.m6_ads_enabled,
          m7_vip_enabled: !!rule.m7_vip_enabled,
          m8_domain_enabled: !!rule.m8_domain_enabled,
          social_platforms_text: (rule.social_platforms || []).join(', '),
          min_impersonation_score: Number(rule.min_impersonation_score || 40),
          schedule_cron: rule.schedule_cron || '0 */6 * * *',
          active: !!rule.active,
        },
      };
    },

    buildRulePayload() {
      return {
        name: (this.ruleForm.data.name || '').trim(),
        brand_id: this.ruleForm.data.brand_id ? Number(this.ruleForm.data.brand_id) : null,
        brand_name: (this.ruleForm.data.brand_name || '').trim(),
        brand_name_uk: (this.ruleForm.data.brand_name_uk || '').trim(),
        brand_name_ru: (this.ruleForm.data.brand_name_ru || '').trim(),
        official_domains: this.parseCsv(this.ruleForm.data.official_domains_text),
        official_developer_ids: this.parseCsv(this.ruleForm.data.official_developer_ids_text),
        executive_names: this.parseCsv(this.ruleForm.data.executive_names_text),
        partner_domains: this.parseCsv(this.ruleForm.data.partner_domains_text),
        trademark_name: (this.ruleForm.data.trademark_name || '').trim(),
        trademark_reg_no: (this.ruleForm.data.trademark_reg_no || '').trim(),
        org_name: (this.ruleForm.data.org_name || '').trim(),
        contact_name: (this.ruleForm.data.contact_name || '').trim(),
        contact_email: (this.ruleForm.data.contact_email || '').trim(),
        contact_phone: (this.ruleForm.data.contact_phone || '').trim(),
        m1_social_enabled: !!this.ruleForm.data.m1_social_enabled,
        m2_apps_enabled: !!this.ruleForm.data.m2_apps_enabled,
        m3_email_enabled: !!this.ruleForm.data.m3_email_enabled,
        m5_exec_enabled: !!this.ruleForm.data.m5_exec_enabled,
        m6_ads_enabled: !!this.ruleForm.data.m6_ads_enabled,
        m7_vip_enabled: !!this.ruleForm.data.m7_vip_enabled,
        m8_domain_enabled: !!this.ruleForm.data.m8_domain_enabled,
        social_platforms: this.parseCsv(this.ruleForm.data.social_platforms_text),
        min_impersonation_score: Number(this.ruleForm.data.min_impersonation_score || 0),
        schedule_cron: (this.ruleForm.data.schedule_cron || '').trim() || '0 */6 * * *',
        active: !!this.ruleForm.data.active,
      };
    },

    async saveRule() {
      try {
        const payload = this.buildRulePayload();
        if (!payload.name || !payload.brand_name) {
          showToast('Rule name and brand name are required.', 'error');
          return;
        }
        if (this.ruleForm.editing) {
          await api.put(`/impersonation/rules/${this.ruleForm.editing.id}`, payload);
          showToast('Rule updated', 'success');
        } else {
          await api.post('/impersonation/rules', payload);
          showToast('Rule created', 'success');
        }
        this.resetRuleForm();
        await Promise.all([this.loadRules(), this.loadStats()]);
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async deleteRule(rule) {
      if (!confirm(`Delete rule "${rule.name}"?`)) return;
      try {
        await api.delete(`/impersonation/rules/${rule.id}`);
        showToast('Rule deleted', 'success');
        await Promise.all([this.loadRules(), this.loadStats()]);
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async scanRule(rule) {
      try {
        await api.post(`/impersonation/rules/${rule.id}/scan`, {});
        showToast('Scan started', 'success');
        await this.loadRules();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async updateFindingStatus(finding, status) {
      try {
        const payload = { status };
        if (status === 'false_positive') {
          const reason = prompt('False positive reason:');
          if (!reason) return;
          payload.false_positive_reason = reason;
        }
        await api.patch(`/impersonation/findings/${finding.id}`, payload);
        showToast('Finding updated', 'success');
        await Promise.all([this.loadFindings(), this.loadStats(), this.loadTakedowns()]);
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async createTakedown(finding) {
      try {
        await api.post('/impersonation/takedowns', { finding_id: finding.id, notes: '' });
        showToast('Takedown request created', 'success');
        await Promise.all([this.loadFindings(), this.loadStats(), this.loadTakedowns()]);
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async updateTakedownStatus(takedown, status) {
      try {
        await api.patch(`/impersonation/takedowns/${takedown.id}`, { status });
        showToast('Takedown updated', 'success');
        await Promise.all([this.loadTakedowns(), this.loadStats()]);
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async exportFindings() {
      try {
        const params = new URLSearchParams();
        if (this.findingsFilter.module) params.set('module', this.findingsFilter.module);
        if (this.findingsFilter.platform) params.set('platform', this.findingsFilter.platform);
        if (this.findingsFilter.status) params.set('status', this.findingsFilter.status);
        params.set('min_score', String(this.findingsFilter.min_score || 0));
        const url = (window.API_BASE || '/api/v1') + '/impersonation/findings/export?' + params.toString();
        const token = localStorage.getItem('zircon_token');
        const resp = await fetch(url, { headers: token ? { Authorization: 'Bearer ' + token } : {} });
        if (!resp.ok) throw new Error('Export failed');
        const blob = await resp.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'impersonation_findings.csv';
        a.click();
        URL.revokeObjectURL(a.href);
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    prevFindingsPage() {
      if (this.findingsPage <= 1) return;
      this.findingsPage -= 1;
      this.loadFindings();
    },

    nextFindingsPage() {
      if ((this.findingsPage * this.findingsPageSize) >= this.findingsTotal) return;
      this.findingsPage += 1;
      this.loadFindings();
    },

    findingsRangeLabel() {
      if (!this.findingsTotal) return '0–0';
      const start = ((this.findingsPage - 1) * this.findingsPageSize) + 1;
      const end = Math.min(this.findingsTotal, this.findingsPage * this.findingsPageSize);
      return `${start}-${end}`;
    },

    toggleFinding(findingId) {
      this.expandedFindingId = this.expandedFindingId === findingId ? null : findingId;
    },

    toggleTakedown(takedownId) {
      this.expandedTakedownId = this.expandedTakedownId === takedownId ? null : takedownId;
    },

    parseJsonList(value) {
      if (Array.isArray(value)) return value;
      try {
        const parsed = JSON.parse(value || '[]');
        return Array.isArray(parsed) ? parsed : [];
      } catch (_) {
        return [];
      }
    },

    parseEvidence(value) {
      try {
        const parsed = JSON.parse(value || '{}');
        return parsed && typeof parsed === 'object' ? Object.entries(parsed) : [];
      } catch (_) {
        return [];
      }
    },

    moduleLabel(moduleKey) {
      return this.moduleMeta[moduleKey]?.label || String(moduleKey || '').toUpperCase();
    },

    moduleBadgeClass(moduleKey) {
      return this.moduleMeta[moduleKey]?.badge || 'badge badge-gray';
    },

    scoreBadgeClass(score) {
      const value = Number(score || 0);
      if (value >= 80) return 'badge badge-red';
      if (value >= 60) return 'badge badge-yellow';
      if (value >= 40) return 'badge badge-blue';
      return 'badge badge-gray';
    },

    statusBadgeClass(status) {
      const map = {
        new: 'badge badge-blue',
        under_review: 'badge badge-yellow',
        takedown_requested: 'badge badge-purple',
        resolved: 'badge badge-green',
        false_positive: 'badge badge-gray',
        draft: 'badge badge-gray',
        pending_review: 'badge badge-yellow',
        submitted: 'badge badge-blue',
        failed: 'badge badge-red',
      };
      return map[status] || 'badge badge-gray';
    },

    formatDateTime(value) {
      if (!value) return '—';
      try {
        return new Date(value).toLocaleString();
      } catch (_) {
        return value;
      }
    },

    activeModules(rule) {
      const enabledMap = {
        m1: !!rule.m1_social_enabled,
        m2: !!rule.m2_apps_enabled,
        m3: !!rule.m3_email_enabled,
        m5: !!rule.m5_exec_enabled,
        m6: !!rule.m6_ads_enabled,
        m7: !!rule.m7_vip_enabled,
        m8: !!rule.m8_domain_enabled,
      };
      return Object.entries(this.moduleMeta)
        .filter(([key]) => enabledMap[key])
        .map(([key, value]) => ({ key, label: value.label, badge: value.badge }));
    },

    moduleRows() {
      return Object.keys(this.moduleMeta).map(key => ({
        key,
        label: this.moduleMeta[key].label,
        badge: this.moduleMeta[key].badge,
        stats: this.stats.by_module?.[key] || { total: 0, new: 0, resolved: 0 },
      }));
    },
  }));
});
