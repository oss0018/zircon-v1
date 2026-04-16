/**
 * Zircon FRT — Files page
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('filesPage', () => ({
    files: [],
    projects: [],
    loading: false,
    dragging: false,
    uploading: false,
    selectedProject: null,
    tags: '',
    stats: null,
    page: 0,
    limit: 20,
    editModal: false,
    editFile: null,
    projectModal: false,
    newProjectName: '',
    newProjectDesc: '',

    async init() {
      await Promise.all([this.loadFiles(), this.loadProjects(), this.loadStats()]);
    },

    async loadFiles() {
      this.loading = true;
      try {
        const qs = `?skip=${this.page * this.limit}&limit=${this.limit}` +
          (this.selectedProject ? `&project_id=${this.selectedProject}` : '');
        this.files = await api.get('/files/' + qs);
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.loading = false;
      }
    },

    async loadProjects() {
      try {
        this.projects = await api.get('/files/projects');
      } catch (e) {}
    },

    async loadStats() {
      try {
        this.stats = await api.get('/files/stats');
      } catch (e) {}
    },

    async createProject() {
      if (!this.newProjectName) return;
      try {
        await api.post('/files/projects', { name: this.newProjectName, description: this.newProjectDesc });
        await this.loadProjects();
        this.projectModal = false;
        this.newProjectName = '';
        this.newProjectDesc = '';
        showToast('Project created', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    onDrop(e) {
      this.dragging = false;
      const files = Array.from(e.dataTransfer.files);
      files.forEach(f => this.uploadFile(f));
    },

    onFileSelect(e) {
      const files = Array.from(e.target.files);
      files.forEach(f => this.uploadFile(f));
      e.target.value = '';
    },

    async uploadFile(file) {
      this.uploading = true;
      try {
        const fd = new FormData();
        fd.append('file', file);
        if (this.selectedProject) fd.append('project_id', this.selectedProject);
        if (this.tags) fd.append('tags', this.tags);
        await api.upload('/files/upload', fd);
        await this.loadFiles();
        await this.loadStats();
        showToast(`${file.name} uploaded and indexed`, 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.uploading = false;
      }
    },

    openEdit(file) {
      this.editFile = { ...file };
      this.editModal = true;
    },

    async saveEdit() {
      try {
        await api.patch(`/files/${this.editFile.id}`, {
          name: this.editFile.name,
          tags: this.editFile.tags,
          project_id: this.editFile.project_id,
        });
        await this.loadFiles();
        this.editModal = false;
        showToast('Saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async reindex(id) {
      try {
        await api.post(`/files/${id}/reindex`);
        await this.loadFiles();
        showToast('Reindexed', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    download(id) {
      const token = localStorage.getItem('zircon_token');
      window.open(`/api/v1/files/${id}/download?token=${token}`, '_blank');
    },

    async deleteFile(id) {
      if (!confirm(t('confirm_delete'))) return;
      try {
        await api.delete(`/files/${id}`);
        this.files = this.files.filter(f => f.id !== id);
        await this.loadStats();
        showToast('Deleted', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    projectName(id) {
      const p = this.projects.find(p => p.id === id);
      return p ? p.name : '—';
    },

    fileExt(name) {
      const ext = name.split('.').pop();
      return ext ? ext.toUpperCase() : 'FILE';
    },
  }));
});
