/**
 * Zircon FRT — Deep Search module
 */

const DS_CSV_PREVIEW_ROWS = 200;
const DS_VISIBLE_INCREMENT = 100;
const DS_CACHE_SIZE = 20;

document.addEventListener('alpine:init', () => {
  Alpine.data('deepSearchPage', () => ({
    // Tabs
    activeTab: 'tree',   // 'tree' | 'search' | 'viewer'
    isAdminUser: false,
    foldersCollapsed: false,
    folderTreeCollapsed: false,

    // File tree
    treeData: null,
    treeLoading: false,
    _collapseVersion: 0,  // bumped on toggle to force Alpine reactivity

    // Navigation (back stack)
    navigationStack: [],      // [{treeData, breadcrumbs}]
    navBreadcrumbParts: [],   // ['folder', 'subfolder', ...]

    // Upload
    uploadFolderName: '',
    uploadLoading: false,

    // Folder list
    folders: [],

    // Deep search — raw results from API
    _allResults: [],
    searchQuery: '',
    searchFolder: '',
    searchLoading: false,
    searchStats: null,
    expandedResults: {},

    // Virtual list
    _visibleCount: DS_VISIBLE_INCREMENT,

    // Client-side filters
    filterExt: '',
    filterFolder: '',

    // Internal: debounce / cache / abort
    _searchDebounceTimer: null,
    _searchCache: null,
    _abortController: null,
    _sentinelObserver: null,

    // File viewer
    viewerFile: null,
    viewerLoading: false,
    viewerCopied: false,

    // Context menu
    ctxMenu: { show: false, x: 0, y: 0, item: null },

    async init() {
      this.isAdminUser = window._currentUser?.role === 'admin';
      this.foldersCollapsed = localStorage.getItem('dsf_collapsed') === 'true';
      this.folderTreeCollapsed = localStorage.getItem('dstree_collapsed') === 'true';
      if (!this.isAdminUser) {
        this.activeTab = 'search';
      }
      this._searchCache = new Map();
      await this.loadFolders();
      if (this.isAdminUser) {
        await this.loadTree();
      }
      this._setupSentinel();

      // Global listeners for context menu dismissal
      document.addEventListener('click', () => this.closeContextMenu());
      document.addEventListener('scroll', () => this.closeContextMenu(), true);
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') this.closeContextMenu();
      });
    },

    // ── Tree ──────────────────────────────────────────────────────────────

    async loadTree() {
      if (!this.isAdminUser) return;
      this.treeLoading = true;
      try {
        this.treeData = await api.get('/deep-search/tree');
        this.navBreadcrumbParts = [];
        this.navigationStack = [];
      } catch (e) {
        showToast('Failed to load tree: ' + e.message, 'error');
      } finally {
        this.treeLoading = false;
      }
    },

    // Toggle collapse state and persist to localStorage
    toggleNode(path) {
      const key = 'filetree_collapsed_' + path;
      const current = this._readCollapse(path);
      localStorage.setItem(key, current ? 'false' : 'true');
      this._collapseVersion++;   // trigger Alpine re-render
    },

    // Read collapse state from localStorage; defaultCollapsed used when no entry yet
    _readCollapse(path, defaultCollapsed) {
      const stored = localStorage.getItem('filetree_collapsed_' + path);
      if (stored !== null) return stored === 'true';
      return !!defaultCollapsed;
    },

    // isCollapsed(path, isTopLevel):
    //   top-level folders default to expanded (defaultCollapsed=false)
    //   nested folders default to collapsed (defaultCollapsed=true)
    isCollapsed(path, isTopLevel) {
      void this._collapseVersion;  // ensure reactive dependency
      return this._readCollapse(path, !isTopLevel);
    },

    // ── Navigation / Breadcrumbs ──────────────────────────────────────────

    navigateToFolder(node) {
      // Save current state
      this.navigationStack.push({
        treeData: this.treeData,
        breadcrumbs: [...this.navBreadcrumbParts],
      });
      // Enter folder
      this.treeData = { name: node.name, type: 'directory', children: node.children || [] };
      this.navBreadcrumbParts = [...this.navBreadcrumbParts, node.name];
    },

    navBack() {
      if (this.navigationStack.length === 0) return;
      const prev = this.navigationStack.pop();
      this.treeData = prev.treeData;
      this.navBreadcrumbParts = prev.breadcrumbs;
    },

    navToIndex(idx) {
      // idx === -1 → root, idx >= 0 → specific breadcrumb level
      if (idx < 0) {
        this.navigationStack = [];
        this.navBreadcrumbParts = [];
        this.loadTree();
        return;
      }
      // Pop stack down to the entry that represents the state AFTER idx
      while (this.navigationStack.length > idx + 1) {
        this.navigationStack.pop();
      }
      if (this.navigationStack.length > 0) {
        const target = this.navigationStack.pop();
        this.treeData = target.treeData;
        this.navBreadcrumbParts = target.breadcrumbs;
      }
    },

    fileIcon(node) {
      if (node.type === 'directory') return '📁';
      const name = (node.name || '').toLowerCase();
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
      if (!this.isAdminUser) return;
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
      if (!this.isAdminUser) return;
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

    debouncedSearch() {
      clearTimeout(this._searchDebounceTimer);
      this._searchDebounceTimer = setTimeout(() => this.runSearch(), 300);
    },

    async runSearch() {
      if (!this.searchQuery.trim()) return;

      const cacheKey = JSON.stringify({ q: this.searchQuery.trim(), f: this.searchFolder || '' });

      // Return cached result without HTTP request
      if (this._searchCache && this._searchCache.has(cacheKey)) {
        const cached = this._searchCache.get(cacheKey);
        this._allResults = cached.results;
        this.searchStats = cached.stats;
        this.expandedResults = {};
        this._visibleCount = DS_VISIBLE_INCREMENT;
        return;
      }

      // Abort previous in-flight request
      if (this._abortController) {
        this._abortController.abort();
      }
      this._abortController = new AbortController();

      this.searchLoading = true;
      this._allResults = [];
      this.searchStats = null;
      this.expandedResults = {};
      this._visibleCount = DS_VISIBLE_INCREMENT;

      try {
        const data = await api.post('/deep-search/search', {
          query: this.searchQuery.trim(),
          folder: this.searchFolder || null,
        }, this._abortController.signal);

        // Sort by match_count descending (higher = more relevant)
        const sorted = (data.results || []).slice().sort((a, b) => b.match_count - a.match_count);
        this._allResults = sorted;

        const stats = {
          total_matches: data.total_matches,
          total_files: data.results.length,
        };
        this.searchStats = stats;

        // Store in cache (evict oldest if at capacity)
        if (this._searchCache) {
          if (this._searchCache.size >= DS_CACHE_SIZE) {
            const firstKey = this._searchCache.keys().next().value;
            this._searchCache.delete(firstKey);
          }
          this._searchCache.set(cacheKey, { results: sorted, stats });
        }

        showToast(`Found ${data.total_matches} matches in ${data.results.length} files`, 'success');
      } catch (e) {
        if (e.name === 'AbortError') return;
        showToast('Search failed: ' + e.message, 'error');
      } finally {
        this.searchLoading = false;
      }
    },

    // ── Filters ───────────────────────────────────────────────────────────

    filteredResults() {
      let results = this._allResults;
      if (this.filterExt) {
        results = results.filter(r => {
          const dot = r.file_name.lastIndexOf('.');
          const ext = dot >= 0 ? r.file_name.slice(dot).toLowerCase() : '';
          return ext === this.filterExt;
        });
      }
      if (this.filterFolder) {
        results = results.filter(r => {
          const folder = r.file_path.split('/')[0] || '';
          return folder === this.filterFolder;
        });
      }
      return results;
    },

    visibleResults() {
      return this.filteredResults().slice(0, this._visibleCount);
    },

    filteredCount() {
      return this.filteredResults().length;
    },

    totalCount() {
      return this._allResults.length;
    },

    availableExtensions() {
      const exts = new Set();
      for (const r of this._allResults) {
        const dot = r.file_name.lastIndexOf('.');
        if (dot >= 0) exts.add(r.file_name.slice(dot).toLowerCase());
      }
      return Array.from(exts).sort();
    },

    availableFolders() {
      const seen = new Set();
      for (const r of this._allResults) {
        const folder = r.file_path.split('/')[0] || '';
        if (folder) seen.add(folder);
      }
      return Array.from(seen).sort();
    },

    clearFilters() {
      this.filterExt = '';
      this.filterFolder = '';
      this._visibleCount = DS_VISIBLE_INCREMENT;
    },

    _setupSentinel() {
      const sentinel = document.getElementById('ds-results-sentinel');
      if (!sentinel) return;
      if (this._sentinelObserver) this._sentinelObserver.disconnect();
      this._sentinelObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            const total = this.filteredCount();
            if (this._visibleCount < total) {
              this._visibleCount += DS_VISIBLE_INCREMENT;
            }
          }
        });
      });
      this._sentinelObserver.observe(sentinel);
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

    highlightFileName(name) {
      return this.highlightMatch(name);
    },

    openFileFromSearch(filePath) {
      this.openFile(filePath);
    },

    toggleFoldersPanel() {
      this.foldersCollapsed = !this.foldersCollapsed;
      localStorage.setItem('dsf_collapsed', this.foldersCollapsed ? 'true' : 'false');
    },

    toggleFolderTreePanel() {
      this.folderTreeCollapsed = !this.folderTreeCollapsed;
      localStorage.setItem('dstree_collapsed', this.folderTreeCollapsed ? 'true' : 'false');
    },

    async _downloadPath(filePath, useWatermark) {
      const token = localStorage.getItem('zircon_token');
      const endpoint = useWatermark ? '/deep-search/download-watermark' : '/deep-search/download';
      const resp = await fetch(`/api/v1${endpoint}?path=${encodeURIComponent(filePath)}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!resp.ok) {
        let message = 'Download failed';
        try {
          const err = await resp.json();
          message = err.detail || message;
        } catch {}
        throw new Error(message);
      }
      const blob = await resp.blob();
      const fileName = filePath.split('/').pop() || 'download';
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = useWatermark ? `[REVIEW_ONLY]_${fileName}` : fileName;
      document.body.appendChild(a);
      a.click();
      URL.revokeObjectURL(a.href);
      document.body.removeChild(a);
    },

    async downloadSearchResult(filePath) {
      try {
        await this._downloadPath(filePath, !this.isAdminUser);
      } catch (e) {
        showToast(e.message || 'Download failed', 'error');
      }
    },

    // ── Context Menu ──────────────────────────────────────────────────────

    showContextMenu(event, item) {
      event.preventDefault();
      event.stopPropagation();
      const margin = 8;
      const menuW = 200;
      const menuH = 210;
      let x = event.clientX;
      let y = event.clientY;
      if (x + menuW > window.innerWidth - margin) x = window.innerWidth - menuW - margin;
      if (y + menuH > window.innerHeight - margin) y = window.innerHeight - menuH - margin;
      this.ctxMenu = { show: true, x, y, item };
    },

    closeContextMenu() {
      if (this.ctxMenu.show) this.ctxMenu = { show: false, x: 0, y: 0, item: null };
    },

    ctxOpen() {
      const item = this.ctxMenu.item;
      this.closeContextMenu();
      if (!item) return;
      if (item.type === 'file') this.openFile(item.path);
      else if (item.type === 'directory') this.navigateToFolder(item);
    },

    ctxOpenNewTab() {
      const item = this.ctxMenu.item;
      this.closeContextMenu();
      if (!item || item.type !== 'file') return;
      const token = localStorage.getItem('zircon_token');
      window.open(`/api/v1/deep-search/file?path=${encodeURIComponent(item.path)}&token=${encodeURIComponent(token || '')}`, '_blank');
    },

    async ctxCopyPath() {
      const item = this.ctxMenu.item;
      this.closeContextMenu();
      if (!item) return;
      try {
        await navigator.clipboard.writeText(item.path || item.name);
        showToast('Path copied to clipboard', 'success');
      } catch {
        showToast('Failed to copy path', 'error');
      }
    },

    async ctxDownload() {
      const item = this.ctxMenu.item;
      this.closeContextMenu();
      if (!item || item.type !== 'file') return;
      await this._downloadPath(item.path, !this.isAdminUser);
    },

    async ctxDelete() {
      if (!this.isAdminUser) return;
      const item = this.ctxMenu.item;
      this.closeContextMenu();
      if (!item) return;
      if (item.type === 'directory') {
        await this.deleteFolder(item.name);
      } else {
        showToast('Individual file deletion is not supported — delete the parent folder', 'info');
      }
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
      return this.viewerFile.content.split('\n').slice(0, DS_CSV_PREVIEW_ROWS).map(r => r.split(','));
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
