/**
 * Zircon FRT — Deep Search module
 */

const DS_CSV_PREVIEW_ROWS = 200;
const DS_VISIBLE_INCREMENT = 100;
const DS_CACHE_SIZE = 20;

document.addEventListener('alpine:init', () => {
  Alpine.data('deepSearchPage', () => ({
    // Tabs
    activeTab: 'search',   // 'tree' | 'search' | 'leaks' | 'file' | 'viewer'
    useApiMode: true,
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

    // Query API mode
    query: '',
    results: [],
    resultsTotal: 0,
    resultsPage: 1,
    resultsPageSize: 25,
    resultsHasNext: false,

    leaks: [],
    leaksTotal: 0,
    leaksPage: 1,
    leaksPageSize: 25,
    leaksHasNext: false,

    selectedFile: null,
    selectedFileChunks: [],
    selectedFileChunksTotal: 0,
    selectedFileChunksOffset: 0,
    selectedFileChunksLimit: 50,
    selectedFileChunksHasNext: false,

    loading: false,
    error: '',

    filterSourceIds: '',
    filterSeverityMin: '',
    filterSeverityMax: '',
    filterHasCredentials: '',
    filterHasPii: '',
    filterHasApiKeys: '',
    filterPatternNames: '',
    filterParseMode: '',
    filterIndexedAfter: '',
    filterIndexedBefore: '',
    filterFilePathPrefix: '',

    leakCategory: '',
    leakDetectedAfter: '',
    leakDetectedBefore: '',

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
      const storedApiMode = localStorage.getItem('deep_search_use_api_mode');
      this.useApiMode = storedApiMode === null || storedApiMode === 'true';
      this.foldersCollapsed = localStorage.getItem('dsf_collapsed') === 'true';
      this.folderTreeCollapsed = localStorage.getItem('dstree_collapsed') === 'true';
      if (this.useApiMode || !this.isAdminUser) {
        this.activeTab = 'search';
      } else {
        this.activeTab = 'tree';
      }
      this._searchCache = new Map();
      await this.loadFolders();
      if (!this.useApiMode && this.isAdminUser) {
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

    async openFile(fileRef) {
      if (this.useApiMode || typeof fileRef === 'number') {
        const fileId = Number(fileRef);
        if (!Number.isFinite(fileId)) {
          this.error = 'Invalid file ID';
          showToast(this.error, 'error');
          return;
        }

        this.loading = true;
        this.error = '';
        this.selectedFile = null;
        this.selectedFileChunks = [];
        this.activeTab = 'file';
        try {
          this.selectedFile = await api.get(`/deep-search/files/${fileId}`);
          await this.loadFileChunks(fileId, 0);
        } catch (e) {
          this.error = e.message || 'Failed to load file details';
          showToast('Failed to open file: ' + this.error, 'error');
        } finally {
          this.loading = false;
        }
        return;
      }

      this.activeTab = 'viewer';
      this.viewerLoading = true;
      this.viewerFile = null;
      try {
        const data = await api.get('/deep-search/file?path=' + encodeURIComponent(fileRef));
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

    _splitFilterValues(value) {
      if (Array.isArray(value)) {
        return value.map(v => String(v).trim()).filter(Boolean);
      }
      return String(value || '')
        .split(',')
        .map(v => v.trim())
        .filter(Boolean);
    },

    _normalizeDateTimeFilter(value) {
      if (!value) return '';
      const parsedDate = new Date(value);
      return Number.isNaN(parsedDate.getTime()) ? String(value) : parsedDate.toISOString();
    },

    _normalizeBooleanFilter(value) {
      if (value === true || value === 'true') return 'true';
      if (value === false || value === 'false') return 'false';
      return '';
    },

    _buildSearchParams(page = 1, pageSize = this.resultsPageSize) {
      const params = new URLSearchParams();
      params.set('q', this.query.trim());
      params.set('page', String(page));
      params.set('page_size', String(pageSize));

      this._splitFilterValues(this.filterSourceIds).forEach(value => params.append('source_id', value));
      this._splitFilterValues(this.filterPatternNames).forEach(value => params.append('pattern_names', value));
      this._splitFilterValues(this.filterParseMode).forEach(value => params.append('parse_mode', value));

      if (this.filterSeverityMin !== '') params.set('severity_min', String(this.filterSeverityMin));
      if (this.filterSeverityMax !== '') params.set('severity_max', String(this.filterSeverityMax));
      if (this.filterFilePathPrefix) params.set('file_path_prefix', this.filterFilePathPrefix.trim());

      const hasCredentials = this._normalizeBooleanFilter(this.filterHasCredentials);
      const hasPii = this._normalizeBooleanFilter(this.filterHasPii);
      const hasApiKeys = this._normalizeBooleanFilter(this.filterHasApiKeys);
      if (hasCredentials) params.set('has_credentials', hasCredentials);
      if (hasPii) params.set('has_pii', hasPii);
      if (hasApiKeys) params.set('has_api_keys', hasApiKeys);

      const indexedAfter = this._normalizeDateTimeFilter(this.filterIndexedAfter);
      const indexedBefore = this._normalizeDateTimeFilter(this.filterIndexedBefore);
      if (indexedAfter) params.set('indexed_after', indexedAfter);
      if (indexedBefore) params.set('indexed_before', indexedBefore);

      return params;
    },

    _buildLeakParams(page = 1, pageSize = this.leaksPageSize) {
      const params = new URLSearchParams();
      params.set('page', String(page));
      params.set('page_size', String(pageSize));

      this._splitFilterValues(this.filterSourceIds).forEach(value => params.append('source_id', value));
      this._splitFilterValues(this.filterPatternNames).forEach(value => params.append('pattern_names', value));

      if (this.leakCategory) params.set('category', this.leakCategory.trim());
      if (this.filterSeverityMin !== '') params.set('severity_min', String(this.filterSeverityMin));
      if (this.filterFilePathPrefix) params.set('file_path_prefix', this.filterFilePathPrefix.trim());

      const hasCredentials = this._normalizeBooleanFilter(this.filterHasCredentials);
      const hasPii = this._normalizeBooleanFilter(this.filterHasPii);
      const hasApiKeys = this._normalizeBooleanFilter(this.filterHasApiKeys);
      if (hasCredentials) params.set('has_credentials', hasCredentials);
      if (hasPii) params.set('has_pii', hasPii);
      if (hasApiKeys) params.set('has_api_keys', hasApiKeys);

      const detectedAfter = this._normalizeDateTimeFilter(this.leakDetectedAfter);
      const detectedBefore = this._normalizeDateTimeFilter(this.leakDetectedBefore);
      if (detectedAfter) params.set('detected_after', detectedAfter);
      if (detectedBefore) params.set('detected_before', detectedBefore);

      return params;
    },

    async runQuery(page = 1) {
      const trimmed = this.query.trim();
      if (!trimmed) {
        this.error = 'Enter a search query';
        this.results = [];
        this.resultsTotal = 0;
        return;
      }

      this.loading = true;
      this.error = '';
      try {
        const params = this._buildSearchParams(page);
        const data = await api.get(`/deep-search/query?${params.toString()}`);
        this.results = Array.isArray(data.items) ? data.items : [];
        this.resultsTotal = Number(data.total || 0);
        this.resultsPage = Number(data.page || page);
        this.resultsPageSize = Number(data.page_size || this.resultsPageSize);
        this.resultsHasNext = !!data.has_next;
      } catch (e) {
        this.error = e.message || 'Failed to run deep search query';
        this.results = [];
        this.resultsTotal = 0;
        showToast('Deep Search query failed: ' + this.error, 'error');
      } finally {
        this.loading = false;
      }
    },

    async loadLeaks(page = 1) {
      this.loading = true;
      this.error = '';
      this.activeTab = 'leaks';
      try {
        const params = this._buildLeakParams(page);
        const data = await api.get(`/deep-search/leaks?${params.toString()}`);
        this.leaks = Array.isArray(data.items) ? data.items : [];
        this.leaksTotal = Number(data.total || 0);
        this.leaksPage = Number(data.page || page);
        this.leaksPageSize = Number(data.page_size || this.leaksPageSize);
        this.leaksHasNext = !!data.has_next;
      } catch (e) {
        this.error = e.message || 'Failed to load leaks';
        this.leaks = [];
        this.leaksTotal = 0;
        showToast('Leak listing failed: ' + this.error, 'error');
      } finally {
        this.loading = false;
      }
    },

    async loadFileChunks(fileId, offset = 0) {
      const numericFileId = Number(fileId);
      if (!Number.isFinite(numericFileId)) return;

      this.loading = true;
      this.error = '';
      try {
        const data = await api.get(
          `/deep-search/files/${numericFileId}/chunks?offset=${offset}&limit=${this.selectedFileChunksLimit}`
        );
        const items = Array.isArray(data.items) ? data.items : [];
        this.selectedFileChunks = offset > 0 ? [...this.selectedFileChunks, ...items] : items;
        this.selectedFileChunksTotal = Number(data.total || 0);
        this.selectedFileChunksOffset = offset + items.length;
        this.selectedFileChunksHasNext = !!data.has_next;
      } catch (e) {
        this.error = e.message || 'Failed to load file chunks';
        showToast('Failed to load file chunks: ' + this.error, 'error');
      } finally {
        this.loading = false;
      }
    },

    resetSearchFilters() {
      this.filterSourceIds = '';
      this.filterSeverityMin = '';
      this.filterSeverityMax = '';
      this.filterHasCredentials = '';
      this.filterHasPii = '';
      this.filterHasApiKeys = '';
      this.filterPatternNames = '';
      this.filterParseMode = '';
      this.filterIndexedAfter = '';
      this.filterIndexedBefore = '';
      this.filterFilePathPrefix = '';
    },

    resetLeakFilters() {
      this.filterSourceIds = '';
      this.filterSeverityMin = '';
      this.filterFilePathPrefix = '';
      this.filterPatternNames = '';
      this.filterHasCredentials = '';
      this.filterHasPii = '';
      this.filterHasApiKeys = '';
      this.leakCategory = '';
      this.leakDetectedAfter = '';
      this.leakDetectedBefore = '';
    },

    async copySnippet(text) {
      try {
        await navigator.clipboard.writeText(String(text || ''));
        showToast('Snippet copied', 'success');
      } catch (_) {
        showToast('Failed to copy snippet', 'error');
      }
    },

    async copyMaskedValue(text) {
      try {
        await navigator.clipboard.writeText(String(text || ''));
        showToast('Masked value copied', 'success');
      } catch (_) {
        showToast('Failed to copy masked value', 'error');
      }
    },

    formatDateTime(value) {
      if (!value) return '—';
      try {
        return new Date(value).toLocaleString();
      } catch (_) {
        return value;
      }
    },

    severityBadgeClass(value) {
      const numeric = Number(value);
      if (!Number.isFinite(numeric)) return 'badge badge-gray';
      if (numeric >= 80) return 'badge badge-red';
      if (numeric >= 60) return 'badge badge-yellow';
      if (numeric >= 40) return 'badge badge-blue';
      if (numeric > 0) return 'badge badge-green';
      return 'badge badge-gray';
    },

    boolBadgeClass(value) {
      return value ? 'badge badge-green' : 'badge badge-gray';
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
        let message = `Download failed (${resp.status})`;
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
