/**
 * Zircon FRT — Vulnerability Scanner page
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('vulnscanApp', () => ({
    activeTab: 'dashboard',
    dashboardStats: null,

    targets: [],
    targetForm: {
      name: '',
      target_type: 'web',
      target_value: '',
      scope: 'SELF',
      default_profile: 'standard',
      tags: '',
      schedule_cron: '',
    },
    targetFormVisible: false,
    editingTarget: null,

    scans: [],
    selectedScan: null,
    scanFindings: [],
    scanReports: [],
    reportFormat: 'json',
    reportGenerating: false,
    scanDrawerVisible: false,
    activeScanTab: 'overview',
    findingsFilter: { severity: '', status: '', scanner: '' },
    pollingTimer: null,

    allFindings: [],
    allFindingsFilter: { severity: '', status: '', scanner: '' },
    selectedFinding: null,
    findingDrawerVisible: false,

    launchModal: {
      visible: false,
      targetId: null,
      targetName: '',
      profile: 'standard',
      scope: 'SELF',
      comment: '',
      reportFormats: ['json'],
    },
    launchSubmitting: false,

    templates: [],
    templateForm: {
      name: '',
      template_id: '',
      yaml_content: '',
      severity: 'medium',
      tags: '',
    },
    templateFormVisible: false,
    editingTemplate: null,

    async init() {
      await Promise.all([
        this.loadDashboard(),
        this.loadTargets(),
        this.loadScans(),
        this.loadTemplates(),
      ]);
      await this.loadAllFindings();
    },

    async loadDashboard() {
      try {
        this.dashboardStats = await api.get('/vulnscan/dashboard/summary');
      } catch (e) {
        this.dashboardStats = null;
        showToast(e.message, 'error');
      }
    },

    async loadTargets() {
      try {
        this.targets = await api.get('/vulnscan/targets?limit=100');
      } catch (e) {
        this.targets = [];
        showToast(e.message, 'error');
      }
    },

    openCreateTarget() {
      this.editingTarget = null;
      this.targetForm = {
        name: '',
        target_type: 'web',
        target_value: '',
        scope: 'SELF',
        default_profile: 'standard',
        tags: '',
        schedule_cron: '',
      };
      this.targetFormVisible = true;
    },

    openEditTarget(t) {
      this.editingTarget = t;
      this.targetForm = {
        name: t.name || '',
        target_type: t.target_type || 'web',
        target_value: t.target_value || '',
        scope: t.scope || 'SELF',
        default_profile: t.default_profile || 'standard',
        tags: Array.isArray(t.tags) ? t.tags.join(', ') : '',
        schedule_cron: t.schedule_cron || '',
      };
      this.targetFormVisible = true;
    },

    async saveTarget() {
      if (!this.targetForm.name.trim() || !this.targetForm.target_value.trim()) {
        showToast('Name and target value are required', 'error');
        return;
      }
      const payload = {
        name: this.targetForm.name.trim(),
        target_type: this.targetForm.target_type,
        target_value: this.targetForm.target_value.trim(),
        scope: this.targetForm.scope,
        default_profile: this.targetForm.default_profile,
        tags: this.targetForm.tags
          .split(',')
          .map(s => s.trim())
          .filter(Boolean),
        schedule_cron: this.targetForm.schedule_cron.trim() || null,
      };
      try {
        if (this.editingTarget && this.editingTarget.id) {
          await api.patch(`/vulnscan/targets/${this.editingTarget.id}`, payload);
          showToast('Target updated', 'success');
        } else {
          await api.post('/vulnscan/targets', payload);
          showToast('Target created', 'success');
        }
        this.targetFormVisible = false;
        await this.loadTargets();
        await this.loadDashboard();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async deleteTarget(id) {
      if (!confirm(t('confirm_delete'))) return;
      try {
        await api.delete(`/vulnscan/targets/${id}`);
        showToast('Target deleted', 'success');
        await this.loadTargets();
        await this.loadDashboard();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async loadScans() {
      try {
        this.scans = await api.get('/vulnscan/scans?limit=30');
      } catch (e) {
        this.scans = [];
        showToast(e.message, 'error');
      }
    },

    async openScanDetail(scan) {
      try {
        this.selectedScan = await api.get(`/vulnscan/scans/${scan.id}`);
        this.scanFindings = await api.get(`/vulnscan/scans/${scan.id}/findings?limit=500`);
        await this.loadScanReports(scan.id);
        this.scanDrawerVisible = true;
        this.activeScanTab = 'overview';
        if (this.selectedScan.status === 'pending' || this.selectedScan.status === 'running') {
          this.startPolling(scan.id);
        } else {
          this.stopPolling();
        }
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    closeScanDrawer() {
      this.scanDrawerVisible = false;
      this.selectedScan = null;
      this.scanFindings = [];
      this.scanReports = [];
      this.stopPolling();
    },

    async cancelScan(id) {
      if (!confirm('Cancel this scan?')) return;
      try {
        await api.delete(`/vulnscan/scans/${id}`);
        showToast('Scan cancelled', 'success');
        await this.loadScans();
        await this.loadDashboard();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    startPolling(id) {
      this.stopPolling();
      this.pollingTimer = setInterval(async () => {
        try {
          const current = await api.get(`/vulnscan/scans/${id}`);
          this.selectedScan = current;
          this.scanFindings = await api.get(`/vulnscan/scans/${id}/findings?limit=500`);
          await this.loadScans();
          await this.loadDashboard();
          if (current.status === 'completed' || current.status === 'failed' || current.status === 'cancelled') {
            this.stopPolling();
            await this.loadAllFindings();
            await this.loadScanReports(id);
          }
        } catch (_) {
          this.stopPolling();
        }
      }, 5000);
    },

    async loadScanReports(scanId) {
      try {
        this.scanReports = await api.get(`/vulnscan/scans/${scanId}/reports`);
      } catch (e) {
        this.scanReports = [];
      }
    },

    async generateReport() {
      if (!this.selectedScan) return;
      this.reportGenerating = true;
      try {
        await api.post(`/vulnscan/scans/${this.selectedScan.id}/reports`, { format: this.reportFormat });
        showToast('Report generated', 'success');
        await this.loadScanReports(this.selectedScan.id);
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.reportGenerating = false;
      }
    },

    downloadReport(report) {
      const token = localStorage.getItem('zircon_token') || sessionStorage.getItem('zircon_token') || '';
      const url = `/api/v1/vulnscan/reports/${report.id}/download`;
      // Use fetch to include the auth header, then trigger a client-side download.
      fetch(url, { headers: { 'Authorization': `Bearer ${token}` } })
        .then(r => {
          if (!r.ok) throw new Error(`Download failed: ${r.status}`);
          return r.blob();
        })
        .then(blob => {
          const a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = `vulnscan_scan_${report.scan_id}_report.${report.format}`;
          a.click();
          URL.revokeObjectURL(a.href);
        })
        .catch(e => showToast(e.message, 'error'));
    },

    async deleteReport(report) {
      if (!confirm(t('confirm_delete'))) return;
      try {
        await api.delete(`/vulnscan/reports/${report.id}`);
        showToast('Report deleted', 'success');
        await this.loadScanReports(report.scan_id);
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    stopPolling() {
      if (this.pollingTimer) {
        clearInterval(this.pollingTimer);
        this.pollingTimer = null;
      }
    },

    openLaunchScan(target) {
      this.launchModal = {
        visible: true,
        targetId: target.id,
        targetName: target.name,
        profile: target.default_profile || 'standard',
        scope: target.scope || 'SELF',
        comment: '',
        reportFormats: ['json'],
      };
    },

    async submitLaunchScan() {
      if (!this.launchModal.targetId) return;
      this.launchSubmitting = true;
      try {
        await api.post(`/vulnscan/targets/${this.launchModal.targetId}/scan`, {
          profile: this.launchModal.profile,
          scope: this.launchModal.scope,
          comment: this.launchModal.comment,
          report_formats: this.launchModal.reportFormats || [],
        });
        showToast('Scan launched', 'success');
        this.launchModal.visible = false;
        await this.loadScans();
        await this.loadDashboard();
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.launchSubmitting = false;
      }
    },

    async loadAllFindings() {
      this.allFindings = [];
      const recent = this.scans && this.scans.length ? this.scans[0] : null;
      if (!recent) return;
      try {
        this.allFindings = await api.get(`/vulnscan/scans/${recent.id}/findings?limit=500`);
      } catch (e) {
        this.allFindings = [];
        showToast(e.message, 'error');
      }
    },

    async openFindingDetail(finding) {
      try {
        this.selectedFinding = await api.get(`/vulnscan/findings/${finding.id}`);
        this.findingDrawerVisible = true;
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    closeFindingDrawer() {
      this.findingDrawerVisible = false;
      this.selectedFinding = null;
    },

    async updateFindingStatus(id, status, reason = '') {
      const payload = { status };
      if (status === 'false_positive') payload.false_positive_reason = reason || null;
      if (status === 'accepted_risk') payload.accepted_risk_reason = reason || null;
      try {
        await api.patch(`/vulnscan/findings/${id}/status`, payload);
        showToast('Finding status updated', 'success');
        if (this.selectedFinding && this.selectedFinding.id === id) {
          this.selectedFinding.status = status;
          this.selectedFinding.false_positive_reason = payload.false_positive_reason || null;
          this.selectedFinding.accepted_risk_reason = payload.accepted_risk_reason || null;
        }
        if (this.selectedScan && this.selectedScan.id) {
          this.scanFindings = await api.get(`/vulnscan/scans/${this.selectedScan.id}/findings?limit=500`);
        }
        await this.loadAllFindings();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async loadTemplates() {
      try {
        this.templates = await api.get('/vulnscan/templates?limit=100');
      } catch (e) {
        this.templates = [];
        showToast(e.message, 'error');
      }
    },

    openCreateTemplate() {
      this.editingTemplate = null;
      this.templateForm = {
        name: '',
        template_id: '',
        yaml_content: '',
        severity: 'medium',
        tags: '',
      };
      this.templateFormVisible = true;
    },

    async openEditTemplate(template) {
      try {
        const detail = await api.get(`/vulnscan/templates/${template.id}`);
        this.editingTemplate = template;
        this.templateForm = {
          name: detail.name || '',
          template_id: detail.template_id || '',
          yaml_content: detail.yaml_content || '',
          severity: detail.severity || 'medium',
          tags: Array.isArray(detail.tags) ? detail.tags.join(', ') : '',
        };
        this.templateFormVisible = true;
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async saveTemplate() {
      if (!this.templateForm.name.trim() || !this.templateForm.template_id.trim() || !this.templateForm.yaml_content.trim()) {
        showToast('Name, template ID, and YAML content are required', 'error');
        return;
      }
      const payload = {
        name: this.templateForm.name.trim(),
        template_id: this.templateForm.template_id.trim(),
        yaml_content: this.templateForm.yaml_content,
        severity: this.templateForm.severity,
        tags: this.templateForm.tags
          .split(',')
          .map(s => s.trim())
          .filter(Boolean),
      };
      try {
        if (this.editingTemplate && this.editingTemplate.id) {
          await api.patch(`/vulnscan/templates/${this.editingTemplate.id}`, {
            name: payload.name,
            yaml_content: payload.yaml_content,
            severity: payload.severity,
            tags: payload.tags,
          });
          showToast('Template updated', 'success');
        } else {
          await api.post('/vulnscan/templates', payload);
          showToast('Template created', 'success');
        }
        this.templateFormVisible = false;
        await this.loadTemplates();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async deleteTemplate(id) {
      if (!confirm(t('confirm_delete'))) return;
      try {
        await api.delete(`/vulnscan/templates/${id}`);
        showToast('Template deleted', 'success');
        await this.loadTemplates();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    severityBadgeClass(severity) {
      const value = (severity || '').toUpperCase();
      if (value === 'CRITICAL') return 'inline-flex items-center rounded-full px-2 py-1 text-xs font-semibold bg-red-100 text-red-800';
      if (value === 'HIGH') return 'inline-flex items-center rounded-full px-2 py-1 text-xs font-semibold bg-orange-100 text-orange-800';
      if (value === 'MEDIUM') return 'inline-flex items-center rounded-full px-2 py-1 text-xs font-semibold bg-yellow-100 text-yellow-800';
      if (value === 'LOW') return 'inline-flex items-center rounded-full px-2 py-1 text-xs font-semibold bg-blue-100 text-blue-800';
      return 'inline-flex items-center rounded-full px-2 py-1 text-xs font-semibold bg-gray-100 text-gray-800';
    },

    statusBadgeClass(status) {
      if (status === 'completed' || status === 'remediated') return 'badge badge-green';
      if (status === 'running' || status === 'pending' || status === 'new') return 'badge badge-blue';
      if (status === 'failed' || status === 'cancelled') return 'badge badge-red';
      return 'badge badge-gray';
    },

    formatDate(s) {
      return window.formatDate(s);
    },

    filteredScanFindings() {
      return (this.scanFindings || []).filter(f => {
        if (this.findingsFilter.severity && (f.severity || '').toUpperCase() !== this.findingsFilter.severity.toUpperCase()) return false;
        if (this.findingsFilter.status && f.status !== this.findingsFilter.status) return false;
        if (this.findingsFilter.scanner && f.scanner_source !== this.findingsFilter.scanner) return false;
        return true;
      });
    },

    filteredAllFindings() {
      return (this.allFindings || []).filter(f => {
        if (this.allFindingsFilter.severity && (f.severity || '').toUpperCase() !== this.allFindingsFilter.severity.toUpperCase()) return false;
        if (this.allFindingsFilter.status && f.status !== this.allFindingsFilter.status) return false;
        if (this.allFindingsFilter.scanner && f.scanner_source !== this.allFindingsFilter.scanner) return false;
        return true;
      });
    },

    formatDuration(ms) {
      if (!ms || ms < 1000) return '—';
      const totalSeconds = Math.floor(ms / 1000);
      const mins = Math.floor(totalSeconds / 60);
      const secs = totalSeconds % 60;
      return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
    },

    profileLabel(profile) {
      return ({ quick: 'Quick', standard: 'Standard', deep: 'Deep' })[profile] || profile || '—';
    },

    scannerLabel(scanner) {
      return ({
        header_scanner: 'Header Scanner',
        dnssec_scanner: 'DNSSEC Scanner',
        testssl_scanner: 'testssl.sh',
        nuclei: 'Nuclei',
        nikto: 'Nikto',
        nmap: 'Nmap',
        zap_passive: 'ZAP Passive',
        openvas: 'OpenVAS',
      })[scanner] || scanner || '—';
    },

    reportFormatLabel(format) {
      return ({ json: 'JSON', csv: 'CSV', html: 'HTML', kql: 'KQL', pdf: 'PDF' })[format] || (format || '').toUpperCase();
    },
  }));
});
