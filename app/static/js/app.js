/**
 * Zircon FRT — Main Application
 */

const API_BASE = '/api/v1';

// ── API Client ────────────────────────────────────────────────────────────
const api = {
  _token() { return localStorage.getItem('zircon_token'); },

  async request(method, path, body = null, isFormData = false) {
    const headers = {};
    if (this._token()) headers['Authorization'] = `Bearer ${this._token()}`;
    if (body && !isFormData) headers['Content-Type'] = 'application/json';

    const opts = { method, headers };
    if (body) opts.body = isFormData ? body : JSON.stringify(body);

    const resp = await fetch(API_BASE + path, opts);
    if (resp.status === 401) {
      localStorage.removeItem('zircon_token');
      window.location.reload();
      return null;
    }
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: resp.statusText }));
      throw new Error(err.detail || 'Request failed');
    }
    if (resp.status === 204) return null;
    return resp.json();
  },

  get(path) { return this.request('GET', path); },
  post(path, body) { return this.request('POST', path, body); },
  put(path, body) { return this.request('PUT', path, body); },
  patch(path, body) { return this.request('PATCH', path, body); },
  delete(path) { return this.request('DELETE', path); },
  upload(path, formData) { return this.request('POST', path, formData, true); },
};

window.api = api;

// ── Toast Notifications ───────────────────────────────────────────────────
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  const icon = type === 'success' ? '✅' : type === 'error' ? '❌' : 'ℹ️';
  toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}
window.showToast = showToast;

// ── Format helpers ────────────────────────────────────────────────────────
function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + sizes[i];
}

function formatDate(dateStr) {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatJSON(data) {
  return JSON.stringify(data, null, 2);
}

window.formatBytes = formatBytes;
window.formatDate = formatDate;
window.formatJSON = formatJSON;

// ── Alpine.js App ─────────────────────────────────────────────────────────
document.addEventListener('alpine:init', () => {
  Alpine.data('zirconApp', () => ({
    // Auth
    authenticated: false,
    currentUser: null,
    loginLoading: false,
    loginError: '',
    loginForm: { username: '', password: '' },

    // Navigation
    page: 'dashboard',
    lang: localStorage.getItem('zircon_lang') || 'en',

    // Stats
    stats: null,
    statsLoading: false,

    // Notifications badge
    unreadCount: 0,

    t(key) { return t(key); },

    async init() {
      window._lang = this.lang;
      const token = localStorage.getItem('zircon_token');
      if (token) {
        try {
          this.currentUser = await api.get('/auth/me');
          this.authenticated = true;
          this.loadStats();
        } catch {
          localStorage.removeItem('zircon_token');
        }
      }
    },

    setLang(l) {
      this.lang = l;
      window._lang = l;
      localStorage.setItem('zircon_lang', l);
    },

    async login() {
      this.loginLoading = true;
      this.loginError = '';
      try {
        const data = await api.post('/auth/login', this.loginForm);
        localStorage.setItem('zircon_token', data.access_token);
        this.currentUser = await api.get('/auth/me');
        this.authenticated = true;
        this.loadStats();
      } catch (e) {
        this.loginError = this.t('login_error');
      } finally {
        this.loginLoading = false;
      }
    },

    logout() {
      localStorage.removeItem('zircon_token');
      this.authenticated = false;
      this.currentUser = null;
      this.page = 'dashboard';
    },

    navigate(p) {
      this.page = p;
    },

    async loadStats() {
      this.statsLoading = true;
      try {
        this.stats = await api.get('/dashboard/stats');
        this.unreadCount = this.stats.unread_notifications || 0;
      } catch (e) {
        console.error('Stats error:', e);
      } finally {
        this.statsLoading = false;
      }
    },

    userInitials() {
      if (!this.currentUser) return '?';
      return this.currentUser.username.substring(0, 2).toUpperCase();
    },
  }));
});
