/**
 * Zircon FRT — Storage Sources page
 * System → Storage Sources
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('storageSourcesPage', () => ({
    sources: [],
    loading: false,
    showCreateModal: false,
    showEditModal: false,
    showCatalogModal: false,
    catalogLoading: false,
    catalogEntries: [],
    catalogSourceId: null,
    catalogFilter: '',

    newSource: {
      name: '',
      source_type: 's3',
      is_enabled: true,
      schedule: '@hourly',
      max_file_size_mb: 25,
      recursive: true,
      config: {},
    },
    editSource: { name: '', schedule: '@hourly', max_file_size_mb: 25, recursive: true },
    editConfig: {},

    indexingStatus: {},  // source_id → {loading, result}

    scheduleOptions: [
      { value: '@hourly', label: 'Every hour' },
      { value: '@daily',  label: 'Every day' },
      { value: '*/30 * * * *', label: 'Every 30 min' },
      { value: '*/15 * * * *', label: 'Every 15 min' },
      { value: 'disabled', label: 'Disabled (manual only)' },
    ],

    sourceTypes: [
      { value: 's3',     label: 'S3 / S3-compatible' },
      { value: 'sftp',   label: 'SFTP' },
      { value: 'webdav', label: 'WebDAV' },
    ],

    async init() {
      await this.loadSources();
    },

    async loadSources() {
      this.loading = true;
      try {
        this.sources = await api.get('/storage-sources/');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.loading = false;
      }
    },

    openCreate() {
      this.newSource = {
        name: '',
        source_type: 's3',
        is_enabled: true,
        schedule: '@hourly',
        max_file_size_mb: 25,
        recursive: true,
        config: {},
      };
      this.showCreateModal = true;
    },

    s3Fields() {
      return [
        { key: 'bucket',       label: 'Bucket',        type: 'text',     required: true,  placeholder: 'my-bucket' },
        { key: 'region',       label: 'Region',        type: 'text',     required: false, placeholder: 'us-east-1' },
        { key: 'endpoint_url', label: 'Endpoint URL',  type: 'text',     required: false, placeholder: 'https://minio.example.com (optional)' },
        { key: 'access_key',   label: 'Access Key ID', type: 'text',     required: true,  placeholder: 'AKIAIOSFODNN7EXAMPLE' },
        { key: 'secret_key',   label: 'Secret Key',    type: 'password', required: true,  placeholder: '••••••••' },
        { key: 'prefix',       label: 'Prefix',        type: 'text',     required: false, placeholder: 'logs/ (optional)' },
      ];
    },

    sftpFields() {
      return [
        { key: 'host',        label: 'Host',        type: 'text',     required: true,  placeholder: 'sftp.example.com' },
        { key: 'port',        label: 'Port',        type: 'number',   required: false, placeholder: '22' },
        { key: 'username',    label: 'Username',    type: 'text',     required: true,  placeholder: 'sftp_user' },
        { key: 'auth_type',   label: 'Auth Type',   type: 'select',   required: true,  options: ['password', 'key'] },
        { key: 'password',    label: 'Password',    type: 'password', required: false, placeholder: '••••••••' },
        { key: 'private_key', label: 'Private Key (PEM)', type: 'textarea', required: false, placeholder: '-----BEGIN RSA PRIVATE KEY-----' },
        { key: 'base_path',   label: 'Base Path',   type: 'text',     required: false, placeholder: '/files' },
      ];
    },

    webdavFields() {
      return [
        { key: 'base_url',  label: 'Base URL',  type: 'text',     required: true,  placeholder: 'https://dav.example.com/files' },
        { key: 'username',  label: 'Username',  type: 'text',     required: false, placeholder: 'user' },
        { key: 'password',  label: 'Password',  type: 'password', required: false, placeholder: '••••••••' },
        { key: 'token',     label: 'Bearer Token', type: 'password', required: false, placeholder: 'Optional alternative to password' },
        { key: 'base_path', label: 'Base Path', type: 'text',     required: false, placeholder: '/ (default)' },
      ];
    },

    configFields(sourceType) {
      if (sourceType === 's3')     return this.s3Fields();
      if (sourceType === 'sftp')   return this.sftpFields();
      if (sourceType === 'webdav') return this.webdavFields();
      return [];
    },

    async createSource() {
      if (!this.newSource.name.trim()) {
        showToast('Name is required', 'error');
        return;
      }
      try {
        await api.post('/storage-sources/', this.newSource);
        await this.loadSources();
        this.showCreateModal = false;
        showToast('Storage source created', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async openEdit(source) {
      this.editSource = { ...source };
      // Load masked config from server
      try {
        const data = await api.get(`/storage-sources/${source.id}/config`);
        this.editConfig = data.config || {};
      } catch (e) {
        this.editConfig = {};
      }
      this.showEditModal = true;
    },

    async saveEdit() {
      if (!this.editSource) return;
      try {
        await api.put(`/storage-sources/${this.editSource.id}`, {
          name: this.editSource.name,
          is_enabled: this.editSource.is_enabled,
          schedule: this.editSource.schedule,
          max_file_size_mb: this.editSource.max_file_size_mb,
          recursive: this.editSource.recursive,
          config: this.editConfig,
        });
        await this.loadSources();
        this.showEditModal = false;
        showToast('Saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async toggleEnabled(source) {
      try {
        await api.put(`/storage-sources/${source.id}`, { is_enabled: !source.is_enabled });
        await this.loadSources();
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async deleteSource(id) {
      if (!confirm(t('confirm_delete'))) return;
      try {
        await api.delete(`/storage-sources/${id}`);
        await this.loadSources();
        showToast('Deleted', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async testSource(id) {
      this.indexingStatus[id] = { loading: true, result: null, type: 'test' };
      try {
        const result = await api.post(`/storage-sources/${id}/test`);
        this.indexingStatus[id] = { loading: false, result, type: 'test' };
        if (result.ok) {
          showToast('Connection successful ✓', 'success');
        } else {
          showToast('Connection failed: ' + (result.message || 'unknown error'), 'error');
        }
      } catch (e) {
        this.indexingStatus[id] = { loading: false, result: { ok: false, message: e.message }, type: 'test' };
        showToast(e.message, 'error');
      }
    },

    async indexNow(id) {
      this.indexingStatus[id] = { loading: true, result: null, type: 'index' };
      try {
        const result = await api.post(`/storage-sources/${id}/index`);
        this.indexingStatus[id] = { loading: false, result, type: 'index' };
        showToast('Indexing started in background', 'success');
        // Refresh status after a short delay
        setTimeout(() => this.loadSources(), 3000);
      } catch (e) {
        this.indexingStatus[id] = { loading: false, result: { ok: false, message: e.message }, type: 'index' };
        showToast(e.message, 'error');
      }
    },

    async openCatalog(source) {
      this.catalogSourceId = source.id;
      this.catalogFilter = '';
      this.showCatalogModal = true;
      await this.loadCatalog();
    },

    async loadCatalog() {
      if (!this.catalogSourceId) return;
      this.catalogLoading = true;
      try {
        const params = this.catalogFilter ? `?status=${this.catalogFilter}&limit=200` : '?limit=200';
        this.catalogEntries = await api.get(`/storage-sources/${this.catalogSourceId}/catalog${params}`);
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.catalogLoading = false;
      }
    },

    sourceTypeLabel(type) {
      const t = this.sourceTypes.find(s => s.value === type);
      return t ? t.label : type;
    },

    scheduleLabel(value) {
      const opt = this.scheduleOptions.find(o => o.value === value);
      return opt ? opt.label : value || '—';
    },

    statusBadgeClass(status) {
      if (status === 'ok') return 'badge badge-green';
      if (status === 'error') return 'badge badge-red';
      if (status === 'running') return 'badge badge-blue';
      return 'badge badge-gray';
    },

    catalogStatusClass(status) {
      if (status === 'indexed')  return 'badge badge-green';
      if (status === 'error')    return 'badge badge-red';
      if (status === 'skipped')  return 'badge badge-gray';
      return 'badge badge-gray';
    },

    formatFileSize(bytes) {
      if (!bytes) return '0 B';
      const units = ['B', 'KB', 'MB', 'GB'];
      let i = 0;
      let size = bytes;
      while (size >= 1024 && i < units.length - 1) {
        size /= 1024;
        i++;
      }
      return size.toFixed(1) + ' ' + units[i];
    },
  }));
});
