/**
 * Zircon FRT — Settings Page
 */
document.addEventListener('alpine:init', () => {
  Alpine.data('settingsPage', () => ({
    activeTab: 'profile',

    // Profile / Change Password
    profileForm: { current_password: '', new_password: '', confirm_password: '' },
    profileLoading: false,

    // Users (admin)
    users: [],
    usersLoading: false,
    showCreateUserModal: false,
    newUser: { username: '', password: '', role: 'user' },
    createUserLoading: false,
    showResetModal: false,
    resetTarget: null,
    resetPassword: '',
    resetLoading: false,

    // Watched Folders
    folders: [],
    foldersLoading: false,
    newFolderPath: '',
    addFolderLoading: false,

    // Notifications
    notifSettings: {
      smtp_host: '', smtp_port: 587, smtp_user: '', smtp_password: '',
      telegram_token: '', telegram_chat_id: '',
    },
    notifLoading: false,
    notifSaveLoading: false,

    // System
    systemInfo: null,
    systemLoading: false,
    reindexLoading: false,
    clearCacheLoading: false,

    isAdmin() {
      return window._currentUser?.role === 'admin';
    },

    async init() {
      await this.loadNotifSettings();
    },

    async switchTab(tab) {
      this.activeTab = tab;
      if (tab === 'users' && this.isAdmin()) await this.loadUsers();
      if (tab === 'watched_folders') await this.loadFolders();
      if (tab === 'system') await this.loadSystemInfo();
    },

    // ── Profile ───────────────────────────────────────────────────────────
    async changePassword() {
      if (this.profileForm.new_password !== this.profileForm.confirm_password) {
        showToast(t('passwords_no_match'), 'error');
        return;
      }
      this.profileLoading = true;
      try {
        await api.post('/auth/change-password', {
          current_password: this.profileForm.current_password,
          new_password: this.profileForm.new_password,
        });
        this.profileForm = { current_password: '', new_password: '', confirm_password: '' };
        showToast(t('success'), 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.profileLoading = false;
      }
    },

    // ── Users ─────────────────────────────────────────────────────────────
    async loadUsers() {
      this.usersLoading = true;
      try {
        this.users = await api.get('/auth/users');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.usersLoading = false;
      }
    },

    async createUser() {
      this.createUserLoading = true;
      try {
        await api.post('/auth/register', this.newUser);
        this.newUser = { username: '', password: '', role: 'user' };
        this.showCreateUserModal = false;
        await this.loadUsers();
        showToast(t('success'), 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.createUserLoading = false;
      }
    },

    openResetModal(user) {
      this.resetTarget = user;
      this.resetPassword = '';
      this.showResetModal = true;
    },

    async doResetPassword() {
      if (!this.resetPassword) {
        showToast(t('field_required'), 'error');
        return;
      }
      this.resetLoading = true;
      try {
        await api.post(`/auth/users/${this.resetTarget.id}/reset-password`, {
          new_password: this.resetPassword,
        });
        this.showResetModal = false;
        showToast(t('success'), 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.resetLoading = false;
      }
    },

    async deleteUser(id) {
      if (!confirm(t('confirm_delete'))) return;
      try {
        await api.delete(`/auth/users/${id}`);
        await this.loadUsers();
        showToast(t('success'), 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    // ── Watched Folders ───────────────────────────────────────────────────
    async loadFolders() {
      this.foldersLoading = true;
      try {
        this.folders = await api.get('/files/watched-folders');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.foldersLoading = false;
      }
    },

    async addFolder() {
      if (!this.newFolderPath.trim()) {
        showToast(t('field_required'), 'error');
        return;
      }
      this.addFolderLoading = true;
      try {
        await api.post('/files/watched-folders', { path: this.newFolderPath.trim() });
        this.newFolderPath = '';
        await this.loadFolders();
        showToast(t('success'), 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.addFolderLoading = false;
      }
    },

    async removeFolder(id) {
      if (!confirm(t('confirm_delete'))) return;
      try {
        await api.delete(`/files/watched-folders/${id}`);
        await this.loadFolders();
        showToast(t('success'), 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    async scanFolder(id) {
      try {
        const res = await api.post(`/files/watched-folders/${id}/scan`);
        await this.loadFolders();
        showToast(`${t('success')}: ${res.indexed} indexed`, 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    },

    // ── Notifications ─────────────────────────────────────────────────────
    async loadNotifSettings() {
      this.notifLoading = true;
      try {
        const data = await api.get('/dashboard/settings');
        if (data && typeof data === 'object') {
          Object.assign(this.notifSettings, data);
        }
      } catch (e) {
        // settings endpoint may return empty; ignore
      } finally {
        this.notifLoading = false;
      }
    },

    async saveNotifSettings() {
      this.notifSaveLoading = true;
      try {
        await api.post('/dashboard/settings', this.notifSettings);
        showToast(t('success'), 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.notifSaveLoading = false;
      }
    },

    // ── System ────────────────────────────────────────────────────────────
    async loadSystemInfo() {
      this.systemLoading = true;
      try {
        this.systemInfo = await api.get('/dashboard/system');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.systemLoading = false;
      }
    },

    async reindexAll() {
      if (!confirm(t('reindex_all') + '?')) return;
      this.reindexLoading = true;
      try {
        const res = await api.post('/files/reindex-all');
        showToast(`${t('success')}: ${res.indexed} indexed`, 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.reindexLoading = false;
      }
    },

    async clearCache() {
      this.clearCacheLoading = true;
      try {
        await api.post('/dashboard/clear-cache');
        showToast(t('success'), 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        this.clearCacheLoading = false;
      }
    },
  }));
});
