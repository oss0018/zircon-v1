/**
 * Zircon FRT — Deep Search module
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('deepSearchPage', () => ({
    // Tabs
    activeTab: 'tree',   // 'tree' | 'search' | 'viewer'

    // File tree
    treeData: null,
    treeLoading: false,
    collapsedNodes: {},

    // Upload
    uploadFolderName: '',
    uploadLoading: false,

    // Folder list
    folders: [],

    // Deep search
    searchQuery: '',
    searchFolder: '',
    searchLoading: false,
    searchResults: [],
    searchStats: null,
    expandedResults: {},

    // File viewer
    viewerFile: null,
    viewerLoading: false,
    viewerCopied: false,

    async init() {
      await this.loadFolders();
      await this.loadTree();
    },

    // ── Tree ──────────────────────────────────────────────────────────────

    async loadTree() {
      this.treeLoading = true;
      try {
        this.treeData = await api.get('/deep-search/tree');
      } catch (e) {
        showToast('Failed to load tree: ' + e.message, 'error');
      } finally {
        this.treeLoading = false;
      }
    },

    toggleNode(path) {
      this.collapsedNodes[path] = !this.collapsedNodes[path];
    },

    isCollapsed(path) {
      return !!this.collapsedNodes[path];
    },

    fileIcon(node) {
      if (node.type === 'directory') return '📁';
      const name = node.name.toLowerCase();
      if (name.includes('cookie')) return '🍪';
      if (name.includes('password') || name.includes('pass')) return '🔑';
      const ext = node.ext || '';
      if (ext === '.csv') return '📊';
      if (ext === '.sql') return '💾';
      if (ext === '.json') return '📋';
      return '📄';
    },

    async openFile(filePath) {
      this.activeTab = 'viewer';
      this.viewerLoading = true;
      this.viewerFile = null;
      try {
        const data = await api.get('/deep-search/file?path=' + encodeURIComponent(filePath));
        this.viewerFile = data;
      } catch (e) {
        showToast('Failed to open file: ' + e.message, 'error');
      } finally {
        this.viewerLoading = false;
      }
    },

    // ── Upload ────────────────────────────────────────────────────────────

    triggerFolderUpload() {
      document.getElementById('ds-folder-input').click();
    },

    async uploadFolder() {
      const input = document.getElementById('ds-folder-input');
      if (!input.files.length) return;
      if (!this.uploadFolderName.trim()) {
        showToast('Enter a folder name', 'error');
        return;
      }

      this.uploadLoading = true;
      const formData = new FormData();
      formData.append('folder_name', this.uploadFolderName.trim());
      for (const file of input.files) {
        formData.append('files', file, file.webkitRelativePath || file.name);
      }

      try {
        const res = await api.upload('/deep-search/upload-folder', formData);
        showToast(`Uploaded ${res.files_count} files to "${res.folder}"`, 'success');
        this.uploadFolderName = '';
        input.value = '';
        await this.loadTree();
        await this.loadFolders();
      } catch (e) {
        showToast('Upload failed: ' + e.message, 'error');
      } finally {
        this.uploadLoading = false;
      }
    },

    // ── Folders ───────────────────────────────────────────────────────────

    async loadFolders() {
      try {
        this.folders = await api.get('/deep-search/folders');
      } catch (e) {}
    },

    async deleteFolder(name) {
      if (!confirm(`Delete folder "${name}" and all its contents?`)) return;
      try {
        await api.delete(`/deep-search/folder/${encodeURIComponent(name)}`);
        showToast(`Folder "${name}" deleted`, 'success');
        await this.loadTree();
        await this.loadFolders();
      } catch (e) {
        showToast('Delete failed: ' + e.message, 'error');
      }
    },

    // ── Search ────────────────────────────────────────────────────────────

    async runSearch() {
      if (!this.searchQuery.trim()) return;
      this.searchLoading = true;
      this.searchResults = [];
      this.searchStats = null;
      this.expandedResults = {};

      try {
        const data = await api.post('/deep-search/search', {
          query: this.searchQuery.trim(),
          folder: this.searchFolder || null,
        });
        this.searchResults = data.results || [];
        this.searchStats = {
          total_matches: data.total_matches,
          total_files: data.results.length,
        };
        showToast(`Found ${data.total_matches} matches in ${data.results.length} files`, 'success');
      } catch (e) {
        showToast('Search failed: ' + e.message, 'error');
      } finally {
        this.searchLoading = false;
      }
    },

    toggleResultExpand(filePath) {
      this.expandedResults[filePath] = !this.expandedResults[filePath];
    },

    isResultExpanded(filePath) {
      return !!this.expandedResults[filePath];
    },

    highlightMatch(text) {
      if (!text || !this.searchQuery) return escapeHtml(text || '');
      const safeText = escapeHtml(text);
      const q = this.searchQuery.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      return safeText.replace(new RegExp(q, 'gi'), m => `<mark class="highlight">${m}</mark>`);
    },

    openFileFromSearch(filePath) {
      this.openFile(filePath);
    },

    // ── File Viewer ───────────────────────────────────────────────────────

    viewerBreadcrumbs() {
      if (!this.viewerFile) return [];
      const parts = this.viewerFile.path.replace(/\\/g, '/').split('/');
      return ['deep_search_data', ...parts];
    },

    renderFileContent() {
      if (!this.viewerFile) return '';
      if (this.viewerFile.binary) return '[Binary file — preview not available]';
      return this.viewerFile.content || '';
    },

    isCSV() {
      return this.viewerFile && this.viewerFile.ext === '.csv';
    },

    csvRows() {
      if (!this.viewerFile || !this.viewerFile.content) return [];
      return this.viewerFile.content.split('\n').slice(0, 200).map(r => r.split(','));
    },

    async copyViewerContent() {
      if (!this.viewerFile || !this.viewerFile.content) return;
      await navigator.clipboard.writeText(this.viewerFile.content);
      this.viewerCopied = true;
      setTimeout(() => { this.viewerCopied = false; }, 2000);
    },

    searchInThisFile() {
      if (!this.viewerFile) return;
      this.searchFolder = this.viewerFile.path.split('/')[0] || '';
      this.activeTab = 'search';
    },

    formatSize(bytes) {
      return formatBytes(bytes || 0);
    },
  }));
});
