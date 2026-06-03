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
    alertRules: [],
    alertRuleForm: { show: false, editing: null, data: {} },
    threatActors: [],
    threatActorForm: { show: false, editing: null, data: {} },
    legalTasks: [],
    legalTaskForm: { show: false, editing: null, data: {} },
    slas: [],
    slaForm: { show: false, editing: null, data: {} },
    loading: false,
    findingsLoading: false,
    rulesLoading: false,
    takedownsLoading: false,
    alertRulesLoading: false,
    threatActorsLoading: false,
    legalTasksLoading: false,
    slasLoading: false,
    expandedFindingId: null,
    expandedTakedownId: null,
    expandedActorId: null,
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
      this.resetAlertRuleForm();
      this.resetThreatActorForm();
      this.resetLegalTaskForm();
      this.resetSlaForm();
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
        await Promise.all([
          this.loadStats(),
          this.loadFindings(),
          this.loadRules(),
          this.loadTakedowns(),
          this.loadAlertRules(),
          this.loadThreatActors(),
          this.loadLegalTasks(),
          this.loadSlas(),
        ]);
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
      if (tab === 'alert-rules') this.loadAlertRules();
      if (tab === 'threat-actors') this.loadThreatActors();
      if (tab === 'legal-tasks') this.loadLegalTasks();
      if (tab === 'sla') this.loadSlas();
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

    // ── Alert Rules ─────────────────────────────────────────────────────────

    defaultAlertRuleData() {
      return {
        name: '',
        description: '',
        match_module: '',
        match_finding_type: '',
        min_threat_score: 80,
        channels_json: '[]',
        active: true,
      };
    },

    resetAlertRuleForm() {
      this.alertRuleForm = { show: false, editing: null, data: this.defaultAlertRuleData() };
    },

    async loadAlertRules() {
      this.alertRulesLoading = true;
      try {
        this.alertRules = await api.get('/impersonation/alert-rules');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.alertRulesLoading = false;
      }
    },

    openAlertRuleForm(rule) {
      if (rule) {
        this.alertRuleForm = {
          show: true,
          editing: rule,
          data: {
            name: rule.name || '',
            description: rule.description || '',
            match_module: rule.match_module || '',
            match_finding_type: rule.match_finding_type || '',
            min_threat_score: Number(rule.min_threat_score ?? 80),
            channels_json: rule.channels_json || '[]',
            active: !!rule.active,
          },
        };
      } else {
        this.alertRuleForm = { show: true, editing: null, data: this.defaultAlertRuleData() };
      }
    },

    async saveAlertRule() {
      try {
        const d = this.alertRuleForm.data;
        const payload = {
          name: (d.name || '').trim(),
          description: (d.description || '').trim(),
          match_module: (d.match_module || '').trim() || null,
          match_finding_type: (d.match_finding_type || '').trim() || null,
          min_threat_score: Number(d.min_threat_score || 80),
          channels_json: (d.channels_json || '[]').trim(),
          active: !!d.active,
        };
        if (!payload.name) { showToast('Name is required.', 'error'); return; }
        if (this.alertRuleForm.editing) {
          await api.put(`/impersonation/alert-rules/${this.alertRuleForm.editing.id}`, payload);
          showToast('Alert rule updated', 'success');
        } else {
          await api.post('/impersonation/alert-rules', payload);
          showToast('Alert rule created', 'success');
        }
        this.resetAlertRuleForm();
        await this.loadAlertRules();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async deleteAlertRule(rule) {
      if (!confirm(`Delete alert rule "${rule.name}"?`)) return;
      try {
        await api.delete(`/impersonation/alert-rules/${rule.id}`);
        showToast('Alert rule deleted', 'success');
        await this.loadAlertRules();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    // ── Threat Actors ────────────────────────────────────────────────────────

    defaultThreatActorData() {
      return {
        name: '',
        description: '',
        country_of_origin: '',
        known_aliases_text: '',
        attack_patterns_text: '',
        registrar_names_text: '',
        hosting_asns_text: '',
        registrant_emails_text: '',
        payment_gateways_text: '',
      };
    },

    resetThreatActorForm() {
      this.threatActorForm = { show: false, editing: null, data: this.defaultThreatActorData() };
    },

    async loadThreatActors() {
      this.threatActorsLoading = true;
      try {
        this.threatActors = await api.get('/impersonation/threat-actors');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.threatActorsLoading = false;
      }
    },

    openThreatActorForm(actor) {
      if (actor) {
        this.threatActorForm = {
          show: true,
          editing: actor,
          data: {
            name: actor.name || '',
            description: actor.description || '',
            country_of_origin: actor.country_of_origin || '',
            known_aliases_text: (actor.known_aliases || []).join(', '),
            attack_patterns_text: (actor.attack_patterns || []).join(', '),
            registrar_names_text: (actor.registrar_names || []).join(', '),
            hosting_asns_text: (actor.hosting_asns || []).join(', '),
            registrant_emails_text: (actor.registrant_emails || []).join(', '),
            payment_gateways_text: (actor.payment_gateways || []).join(', '),
          },
        };
      } else {
        this.threatActorForm = { show: true, editing: null, data: this.defaultThreatActorData() };
      }
    },

    async saveThreatActor() {
      try {
        const d = this.threatActorForm.data;
        const payload = {
          name: (d.name || '').trim(),
          description: (d.description || '').trim(),
          country_of_origin: (d.country_of_origin || '').trim(),
          known_aliases: this.parseCsv(d.known_aliases_text),
          attack_patterns: this.parseCsv(d.attack_patterns_text),
          registrar_names: this.parseCsv(d.registrar_names_text),
          hosting_asns: this.parseCsv(d.hosting_asns_text),
          registrant_emails: this.parseCsv(d.registrant_emails_text),
          payment_gateways: this.parseCsv(d.payment_gateways_text),
          linked_finding_ids: [],
        };
        if (!payload.name) { showToast('Name is required.', 'error'); return; }
        if (this.threatActorForm.editing) {
          await api.put(`/impersonation/threat-actors/${this.threatActorForm.editing.id}`, payload);
          showToast('Threat actor updated', 'success');
        } else {
          await api.post('/impersonation/threat-actors', payload);
          showToast('Threat actor created', 'success');
        }
        this.resetThreatActorForm();
        await this.loadThreatActors();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async deleteThreatActor(actor) {
      if (!confirm(`Delete threat actor "${actor.name}"?`)) return;
      try {
        await api.delete(`/impersonation/threat-actors/${actor.id}`);
        showToast('Threat actor deleted', 'success');
        await this.loadThreatActors();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async correlateActor(actor) {
      try {
        const result = await api.post(`/impersonation/threat-actors/${actor.id}/correlate`, {});
        showToast(`Correlated: ${(result.linked_finding_ids || []).length} findings linked`, 'success');
        await this.loadThreatActors();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    toggleActor(actorId) {
      this.expandedActorId = this.expandedActorId === actorId ? null : actorId;
    },

    // ── Legal Tasks ──────────────────────────────────────────────────────────

    defaultLegalTaskData() {
      return {
        task_type: 'udrp',
        title: '',
        description: '',
        status: 'open',
        due_date: '',
        external_ref: '',
        notes: '',
        finding_id: '',
        takedown_id: '',
      };
    },

    resetLegalTaskForm() {
      this.legalTaskForm = { show: false, editing: null, data: this.defaultLegalTaskData() };
    },

    async loadLegalTasks() {
      this.legalTasksLoading = true;
      try {
        this.legalTasks = await api.get('/impersonation/legal-tasks');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.legalTasksLoading = false;
      }
    },

    openLegalTaskForm(task) {
      if (task) {
        this.legalTaskForm = {
          show: true,
          editing: task,
          data: {
            task_type: task.task_type || 'udrp',
            title: task.title || '',
            description: task.description || '',
            status: task.status || 'open',
            due_date: task.due_date ? task.due_date.substring(0, 10) : '',
            external_ref: task.external_ref || '',
            notes: task.notes || '',
            finding_id: task.finding_id || '',
            takedown_id: task.takedown_id || '',
          },
        };
      } else {
        this.legalTaskForm = { show: true, editing: null, data: this.defaultLegalTaskData() };
      }
    },

    async saveLegalTask() {
      try {
        const d = this.legalTaskForm.data;
        const payload = {
          task_type: (d.task_type || 'udrp').trim(),
          title: (d.title || '').trim(),
          description: (d.description || '').trim(),
          status: (d.status || 'open').trim(),
          due_date: d.due_date || null,
          external_ref: (d.external_ref || '').trim(),
          notes: (d.notes || '').trim(),
          finding_id: d.finding_id ? Number(d.finding_id) : null,
          takedown_id: d.takedown_id ? Number(d.takedown_id) : null,
        };
        if (!payload.title) { showToast('Title is required.', 'error'); return; }
        if (this.legalTaskForm.editing) {
          await api.put(`/impersonation/legal-tasks/${this.legalTaskForm.editing.id}`, payload);
          showToast('Legal task updated', 'success');
        } else {
          await api.post('/impersonation/legal-tasks', payload);
          showToast('Legal task created', 'success');
        }
        this.resetLegalTaskForm();
        await this.loadLegalTasks();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async deleteLegalTask(task) {
      if (!confirm(`Delete legal task "${task.title}"?`)) return;
      try {
        await api.delete(`/impersonation/legal-tasks/${task.id}`);
        showToast('Legal task deleted', 'success');
        await this.loadLegalTasks();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    // ── SLA ──────────────────────────────────────────────────────────────────

    defaultSlaData() {
      return {
        name: '',
        description: '',
        match_module: '',
        match_severity: '',
        time_to_detect_min: 0,
        time_to_triage_min: 240,
        time_to_takedown_min: 1440,
        time_to_resolve_min: 4320,
        active: true,
      };
    },

    resetSlaForm() {
      this.slaForm = { show: false, editing: null, data: this.defaultSlaData() };
    },

    async loadSlas() {
      this.slasLoading = true;
      try {
        this.slas = await api.get('/impersonation/slas');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.slasLoading = false;
      }
    },

    openSlaForm(sla) {
      if (sla) {
        this.slaForm = {
          show: true,
          editing: sla,
          data: {
            name: sla.name || '',
            description: sla.description || '',
            match_module: sla.match_module || '',
            match_severity: sla.match_severity || '',
            time_to_detect_min: Number(sla.time_to_detect_min ?? 0),
            time_to_triage_min: Number(sla.time_to_triage_min ?? 240),
            time_to_takedown_min: Number(sla.time_to_takedown_min ?? 1440),
            time_to_resolve_min: Number(sla.time_to_resolve_min ?? 4320),
            active: !!sla.active,
          },
        };
      } else {
        this.slaForm = { show: true, editing: null, data: this.defaultSlaData() };
      }
    },

    async saveSla() {
      try {
        const d = this.slaForm.data;
        const payload = {
          name: (d.name || '').trim(),
          description: (d.description || '').trim(),
          match_module: (d.match_module || '').trim() || null,
          match_severity: (d.match_severity || '').trim() || null,
          time_to_detect_min: Number(d.time_to_detect_min || 0),
          time_to_triage_min: Number(d.time_to_triage_min || 240),
          time_to_takedown_min: Number(d.time_to_takedown_min || 1440),
          time_to_resolve_min: Number(d.time_to_resolve_min || 4320),
          active: !!d.active,
        };
        if (!payload.name) { showToast('Name is required.', 'error'); return; }
        if (this.slaForm.editing) {
          await api.put(`/impersonation/slas/${this.slaForm.editing.id}`, payload);
          showToast('SLA updated', 'success');
        } else {
          await api.post('/impersonation/slas', payload);
          showToast('SLA created', 'success');
        }
        this.resetSlaForm();
        await this.loadSlas();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async deleteSla(sla) {
      if (!confirm(`Delete SLA "${sla.name}"?`)) return;
      try {
        await api.delete(`/impersonation/slas/${sla.id}`);
        showToast('SLA deleted', 'success');
        await this.loadSlas();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    slaMinutesToLabel(minutes) {
      const m = Number(minutes || 0);
      if (m >= 1440) return `${Math.round(m / 1440)}d`;
      if (m >= 60) return `${Math.round(m / 60)}h`;
      return `${m}m`;
    },
  }));
});
