/**
 * Zircon FRT — Monitoring page
 */
const MONITORING_CTX_MENU_WIDTH = 220;
const MONITORING_CTX_MENU_HEIGHT = 160;
const MONITORING_TARGET_TYPES = ['keyword', 'domain', 'account', 'email', 'url'];

document.addEventListener('alpine:init', () => {
  Alpine.data('monitoringPage', () => ({
    jobs: [],
    runs: [],
    findings: [],
    options: {
      storage_sources: [],
      integrations: [],
      watchlist_items: [],
      brands: [],
    },
    loading: false,
    loadingDetails: false,
    showModal: false,
    modalMode: 'create',
    triggerResult: null,
    activeJobId: null,

    commonSchedules: [
      { label: 'Manual only', value: 'manual' },
      { label: 'Hourly', value: 'hourly' },
      { label: 'Daily', value: 'daily' },
    ],

    ctxMenu: { show: false, x: 0, y: 0, job: null },

    newJob: {},

    async init() {
      this.resetJobForm();
      await Promise.all([
        this.loadOptions(),
        this.loadJobs(),
      ]);
      if (this.jobs.length) {
        await this.selectJob(this.jobs[0]);
      }
      document.addEventListener('click', () => { this.ctxMenu.show = false; });
      document.addEventListener('keydown', e => { if (e.key === 'Escape') this.ctxMenu.show = false; });
    },

    resetJobForm() {
      this.newJob = {
        id: null,
        name: '',
        schedule: 'manual',
        is_active: true,
        targetsText: '',
        exclusionsText: '',
        checks: {
          folder_scan: {
            enabled: true,
            storage_source_ids: [],
            path_prefixesText: '',
          },
          osint_check: {
            enabled: false,
            integration_ids: [],
            advanced_options: {},
          },
          watchlist_check: {
            enabled: false,
            watchlist_item_ids: [],
            matching_mode: 'contains',
          },
          brand_scan: {
            enabled: false,
            brand_ids: [],
          },
        },
      };
    },

    async loadOptions() {
      try {
        this.options = await api.get('/monitoring/options');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async loadJobs() {
      this.loading = true;
      try {
        this.jobs = await api.get('/monitoring/');
        if (this.activeJobId && !this.jobs.find(j => j.id === this.activeJobId)) {
          this.activeJobId = null;
        }
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.loading = false;
      }
    },

    async loadRuns(jobId = this.activeJobId) {
      if (!jobId) {
        this.runs = [];
        return;
      }
      this.loadingDetails = true;
      try {
        this.runs = await api.get(`/monitoring/runs?job_id=${jobId}`);
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.loadingDetails = false;
      }
    },

    async loadFindings(jobId = this.activeJobId) {
      if (!jobId) {
        this.findings = [];
        return;
      }
      this.loadingDetails = true;
      try {
        this.findings = await api.get(`/monitoring/findings?job_id=${jobId}`);
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.loadingDetails = false;
      }
    },

    async selectJob(job) {
      this.activeJobId = job && job.id;
      await Promise.all([
        this.loadRuns(this.activeJobId),
        this.loadFindings(this.activeJobId),
      ]);
    },

    showCtxMenu(e, job) {
      e.preventDefault();
      e.stopPropagation();
      const x = Math.min(e.clientX, window.innerWidth - MONITORING_CTX_MENU_WIDTH);
      const y = Math.min(e.clientY, window.innerHeight - MONITORING_CTX_MENU_HEIGHT);
      this.ctxMenu = { show: true, x, y, job };
    },

    ctxOpenNewWindow() {
      this.ctxMenu.show = false;
      window.open('/?page=monitoring', '_blank');
    },

    openCreateModal() {
      this.modalMode = 'create';
      this.resetJobForm();
      this.showModal = true;
    },

    openEditModal(job) {
      const config = this.normalizeConfig(job);
      this.modalMode = 'edit';
      this.newJob = {
        id: job.id,
        name: job.name || '',
        schedule: job.schedule || 'manual',
        is_active: !!job.is_active,
        targetsText: (config.targets || [])
          .map(target => `${target.type}:${target.value}`)
          .join('\n'),
        exclusionsText: (config.exclusions || []).join('\n'),
        checks: {
          folder_scan: {
            enabled: !!config.checks.folder_scan.enabled,
            storage_source_ids: [...(config.checks.folder_scan.storage_source_ids || [])],
            path_prefixesText: (config.checks.folder_scan.path_prefixes || []).join('\n'),
          },
          osint_check: {
            enabled: !!config.checks.osint_check.enabled,
            integration_ids: [...(config.checks.osint_check.integration_ids || [])],
            advanced_options: this.normalizeAdvancedOptions(config.checks.osint_check.advanced_options || {}),
          },
          watchlist_check: {
            enabled: !!config.checks.watchlist_check.enabled,
            watchlist_item_ids: [...(config.checks.watchlist_check.watchlist_item_ids || [])],
            matching_mode: config.checks.watchlist_check.matching_mode || 'contains',
          },
          brand_scan: {
            enabled: !!config.checks.brand_scan.enabled,
            brand_ids: [...(config.checks.brand_scan.brand_ids || [])],
          },
        },
      };
      this.showModal = true;
    },

    normalizeAdvancedOptions(options) {
      const normalized = {};
      Object.entries(options || {}).forEach(([key, value]) => {
        normalized[key] = JSON.stringify(value, null, 2);
      });
      return normalized;
    },

    normalizeConfig(job) {
      let raw = {};
      try {
        raw = JSON.parse(job.config_json || '{}');
      } catch (_) {
        raw = {};
      }

      const defaults = {
        targets: [],
        exclusions: [],
        checks: {
          folder_scan: { enabled: false, storage_source_ids: [], path_prefixes: [] },
          osint_check: { enabled: false, integration_ids: [], advanced_options: {} },
          watchlist_check: { enabled: false, watchlist_item_ids: [], matching_mode: 'contains' },
          brand_scan: { enabled: false, brand_ids: [] },
        },
      };

      if (!raw.checks) {
        if (job.type === 'folder_scan') {
          defaults.checks.folder_scan.enabled = true;
          defaults.checks.folder_scan.path_prefixes = raw.path_prefixes || [];
          if (raw.folder) defaults.checks.folder_scan.legacy_folder = raw.folder;
          if (raw.query) defaults.targets = [{ type: 'keyword', value: raw.query }];
        } else if (job.type === 'osint_check') {
          defaults.checks.osint_check.enabled = true;
          defaults.checks.osint_check.integration_ids = raw.integration_ids || raw.integrations || [];
          if (raw.query) defaults.targets = [{ type: 'keyword', value: raw.query }];
        } else if (job.type === 'watchlist_check') {
          defaults.checks.watchlist_check.enabled = true;
          defaults.checks.watchlist_check.watchlist_item_ids = raw.watchlist_item_ids || [];
          defaults.checks.watchlist_check.matching_mode = raw.matching_mode || 'contains';
        } else if (job.type === 'brand_scan') {
          defaults.checks.brand_scan.enabled = true;
          defaults.checks.brand_scan.brand_ids = raw.brand_ids || [];
        }
      }

      return {
        ...defaults,
        ...raw,
        checks: {
          ...defaults.checks,
          ...(raw.checks || {}),
          folder_scan: { ...defaults.checks.folder_scan, ...((raw.checks || {}).folder_scan || {}) },
          osint_check: { ...defaults.checks.osint_check, ...((raw.checks || {}).osint_check || {}) },
          watchlist_check: { ...defaults.checks.watchlist_check, ...((raw.checks || {}).watchlist_check || {}) },
          brand_scan: { ...defaults.checks.brand_scan, ...((raw.checks || {}).brand_scan || {}) },
        },
      };
    },

    inferTargetType(value) {
      const text = (value || '').trim();
      if (!text) return 'keyword';
      if (text.startsWith('@')) return 'account';
      if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/i.test(text)) return 'email';
      if (/^https?:\/\//i.test(text)) return 'url';
      if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(text)) return 'domain';
      return 'keyword';
    },

    parseTargets(text) {
      return (text || '')
        .split('\n')
        .map(line => line.trim())
        .filter(Boolean)
        .map(line => {
          const match = line.match(/^([a-z_]+):(.*)$/i);
          if (match && MONITORING_TARGET_TYPES.includes(match[1].toLowerCase())) {
            const value = match[2].trim();
            return value ? { type: match[1].toLowerCase(), value } : null;
          }
          return { type: this.inferTargetType(line), value: line };
        })
        .filter(Boolean);
    },

    parseSimpleLines(text) {
      return (text || '')
        .split('\n')
        .map(line => line.trim())
        .filter(Boolean);
    },

    buildAdvancedOptions() {
      const options = {};
      Object.entries(this.newJob.checks.osint_check.advanced_options || {}).forEach(([key, value]) => {
        const trimmed = (value || '').trim();
        if (!trimmed) return;
        try {
          options[key] = JSON.parse(trimmed);
        } catch (_) {
          options[key] = { note: trimmed };
        }
      });
      return options;
    },

    buildPayload() {
      return {
        name: this.newJob.name.trim(),
        type: 'unified',
        schedule: this.newJob.schedule,
        is_active: !!this.newJob.is_active,
        config_json: {
          schema_version: 2,
          targets: this.parseTargets(this.newJob.targetsText),
          exclusions: this.parseSimpleLines(this.newJob.exclusionsText),
          checks: {
            folder_scan: {
              enabled: !!this.newJob.checks.folder_scan.enabled,
              storage_source_ids: this.newJob.checks.folder_scan.storage_source_ids || [],
              path_prefixes: this.parseSimpleLines(this.newJob.checks.folder_scan.path_prefixesText),
            },
            osint_check: {
              enabled: !!this.newJob.checks.osint_check.enabled,
              integration_ids: this.newJob.checks.osint_check.integration_ids || [],
              advanced_options: this.buildAdvancedOptions(),
            },
            watchlist_check: {
              enabled: !!this.newJob.checks.watchlist_check.enabled,
              watchlist_item_ids: this.newJob.checks.watchlist_check.watchlist_item_ids || [],
              matching_mode: this.newJob.checks.watchlist_check.matching_mode || 'contains',
            },
            brand_scan: {
              enabled: !!this.newJob.checks.brand_scan.enabled,
              brand_ids: this.newJob.checks.brand_scan.brand_ids || [],
            },
          },
        },
      };
    },

    validatePayload(payload) {
      if (!payload.name) {
        showToast('Job name is required', 'error');
        return false;
      }
      const checks = payload.config_json.checks;
      if (!checks.folder_scan.enabled && !checks.osint_check.enabled && !checks.watchlist_check.enabled && !checks.brand_scan.enabled) {
        showToast('Enable at least one check', 'error');
        return false;
      }
      if ((checks.folder_scan.enabled || checks.osint_check.enabled) && payload.config_json.targets.length === 0 && (!checks.watchlist_check.enabled || checks.watchlist_check.watchlist_item_ids.length === 0)) {
        showToast('Add at least one target or select watchlist items', 'error');
        return false;
      }
      return true;
    },

    async saveJob() {
      const payload = this.buildPayload();
      if (!this.validatePayload(payload)) return;
      const targetJobId = this.modalMode === 'edit' ? this.newJob.id : null;
      try {
        if (this.modalMode === 'edit' && this.newJob.id) {
          await api.patch(`/monitoring/${this.newJob.id}`, payload);
          showToast('Job updated', 'success');
        } else {
          await api.post('/monitoring/', payload);
          showToast('Job created', 'success');
        }
        this.showModal = false;
        await this.loadJobs();
        if (!this.activeJobId && this.jobs.length) {
          this.activeJobId = this.jobs[0].id;
        }
        const active = this.jobs.find(j => j.id === (targetJobId || this.jobs[0]?.id || this.activeJobId));
        if (active) await this.selectJob(active);
        this.resetJobForm();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async triggerJob(id) {
      try {
        const result = await api.post(`/monitoring/${id}/trigger`);
        this.triggerResult = result;
        await this.loadJobs();
        const selected = this.jobs.find(job => job.id === id);
        if (selected) await this.selectJob(selected);
        showToast('Job executed', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async toggleJob(job) {
      try {
        await api.patch(`/monitoring/${job.id}`, { is_active: !job.is_active });
        await this.loadJobs();
        const selected = this.jobs.find(item => item.id === job.id);
        if (selected) await this.selectJob(selected);
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async deleteJob(id) {
      if (!confirm(t('confirm_delete'))) return;
      try {
        await api.delete(`/monitoring/${id}`);
        this.jobs = this.jobs.filter(j => j.id !== id);
        if (this.activeJobId === id) {
          this.activeJobId = this.jobs[0] ? this.jobs[0].id : null;
          if (this.activeJobId) {
            const selected = this.jobs.find(job => job.id === this.activeJobId);
            if (selected) await this.selectJob(selected);
          } else {
            this.runs = [];
            this.findings = [];
          }
        }
        showToast('Deleted', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    selectedJob() {
      return this.jobs.find(job => job.id === this.activeJobId) || null;
    },

    enabledChecks(job) {
      const config = this.normalizeConfig(job);
      return Object.entries(config.checks)
        .filter(([, cfg]) => cfg.enabled)
        .map(([name]) => name.replaceAll('_', ' '));
    },

    badgeClassForCheck(type) {
      if (type === 'folder_scan') return 'badge badge-blue';
      if (type === 'osint_check') return 'badge badge-green';
      if (type === 'watchlist_check') return 'badge badge-yellow';
      return 'badge badge-purple';
    },

    evidence(finding) {
      try {
        return JSON.parse(finding.evidence_json || '{}');
      } catch (_) {
        return {};
      }
    },

    findingSummary(finding) {
      const evidence = this.evidence(finding);
      return evidence.summary || evidence.snippet || evidence.path || evidence.object || evidence.domain || '—';
    },

    previewEvidence(preview) {
      const evidence = this.evidence(preview);
      return evidence.snippet || evidence.summary || evidence.path || evidence.object || evidence.domain || '—';
    },

    ensureAdvancedOption(id) {
      if (!this.newJob.checks.osint_check.advanced_options[id]) {
        this.newJob.checks.osint_check.advanced_options[id] = '';
      }
      return true;
    },
  }));
});
