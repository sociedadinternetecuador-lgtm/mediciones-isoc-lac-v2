/* ═══════════════════════════════════════════════════════════
   api.js — Cliente API centralizado
   API_BASE usa window.location.origin para llamar API en el mismo origen.
   Token en localStorage key 'obs_token'.
   ═══════════════════════════════════════════════════════════ */

const API = (() => {
  const API_BASE = window.location.origin;
  const _TOKEN = 'obs_token';
  const ANALYZE_START_TIMEOUT_MS = 30000;
  const ANALYZE_TOTAL_TIMEOUT_MS = 600000;
  const ANALYZE_POLL_MS = 2500;

  // ── Token ────────────────────────────────────────────────
  function getToken()        { return localStorage.getItem(_TOKEN); }
  function setToken(t)       { localStorage.setItem(_TOKEN, t); }
  function clearToken()      { localStorage.removeItem(_TOKEN); localStorage.removeItem('obs_role'); }
  function getRole()         { return localStorage.getItem('obs_role'); }
  function setRole(r)        { localStorage.setItem('obs_role', r); }
  function isLoggedIn()      { return !!getToken(); }

  // ── Cabeceras ────────────────────────────────────────────
  function _headers(auth = false) {
    const h = { 'Content-Type': 'application/json' };
    if (auth) {
      const tok = getToken();
      if (tok) h['Authorization'] = `Bearer ${tok}`;
    }
    return h;
  }

  // ── Fetch base ───────────────────────────────────────────
  async function _req(method, path, body = null, auth = false, options = {}) {
    const url = `${API_BASE}${path}`;
    const timeoutMs = options.timeoutMs || 0;
    const controller = timeoutMs ? new AbortController() : null;
    let timeoutId = null;
    const opts = {
      method,
      headers: _headers(auth),
      signal: controller?.signal,
    };
    if (body !== null) opts.body = JSON.stringify(body);

    let res;
    try {
      if (timeoutMs) timeoutId = setTimeout(() => controller.abort(), timeoutMs);
      console.info('[Observatorio DNSSEC] API request', { url, method });
      res = await fetch(url, opts);
      console.info('[Observatorio DNSSEC] API status', { url, status: res.status });
    } catch (e) {
      console.error('[Observatorio DNSSEC] API error', { url, error: e });
      if (e?.name === 'AbortError') {
        throw { error: 'timeout', message: 'El análisis está tardando más de lo esperado.' };
      }
      throw { error: 'network', message: 'No se pudo conectar con el servidor.' };
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
    }

    // Token expirado → limpiar y redirigir al login
    if (res.status === 401) {
      clearToken();
      if (window.location.pathname !== '/admin/login') {
        window.location.href = '/admin/login';
      }
      throw { error: 'unauthorized', message: 'Sesión expirada' };
    }

    let data;
    try {
      data = await res.json();
    } catch {
      throw { error: 'parse_error', message: 'Respuesta inválida del servidor' };
    }

    if (!res.ok) {
      throw {
        error: data?.error || `http_${res.status}`,
        message: data?.message || `Error del servidor (${res.status})`,
        status: res.status,
      };
    }

    return data;
  }

  // ── Auth ─────────────────────────────────────────────────
  async function login(email, password) {
    const data = await _req('POST', '/auth/login', { email, password });
    setToken(data.token);
    setRole(data.role);
    return data;
  }

  async function logout() {
    clearToken();
  }

  async function me() {
    return _req('GET', '/auth/me', null, true);
  }

  async function recover(email) {
    return _req('POST', '/auth/recover', { email });
  }

  // ── Análisis ─────────────────────────────────────────────
  function _sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async function analyze(domain, onStatus = null) {
    const started = Date.now();
    const job = await _req('POST', '/analyze', { domain }, false, { timeoutMs: ANALYZE_START_TIMEOUT_MS });

    if (job && job.structured_view) return job;
    if (!job?.id || !job?.status_url) {
      throw { error: 'analysis_failed', message: 'Respuesta inválida del servidor' };
    }
    if (typeof onStatus === 'function') onStatus(job);

    while (Date.now() - started < ANALYZE_TOTAL_TIMEOUT_MS) {
      const status = await _req('GET', job.status_url, null, false, { timeoutMs: ANALYZE_START_TIMEOUT_MS });
      if (typeof onStatus === 'function') onStatus(status);

      if (status.status === 'done') {
        const resultUrl = status.public_result_url || job.public_result_url || `/analyze/${encodeURIComponent(job.id)}/public.json`;
        return _req('GET', resultUrl, null, false, { timeoutMs: ANALYZE_START_TIMEOUT_MS });
      }

      if (status.status === 'error') {
        throw {
          error: status.error || 'analysis_failed',
          message: status.message || 'No se pudo completar el análisis.',
        };
      }

      await _sleep(ANALYZE_POLL_MS);
    }

    throw { error: 'timeout', message: 'El análisis está tardando más de lo esperado.' };
  }

  async function analyzeStatus(id) {
    return _req('GET', `/analyze/${encodeURIComponent(id)}/status`);
  }

  // ── Admin: stats ─────────────────────────────────────────
  async function stats() {
    return _req('GET', '/admin/stats', null, true);
  }

  // ── Admin: historial ─────────────────────────────────────
  async function history(page = 1, q = '') {
    const qs = new URLSearchParams({ page, q }).toString();
    return _req('GET', `/admin/history?${qs}`, null, true);
  }

  async function historyGet(id) {
    return _req('GET', `/admin/history/${id}`, null, true);
  }

  async function historyDelete(id) {
    return _req('DELETE', `/admin/history/${id}`, null, true);
  }

  // ── Admin: usuarios ──────────────────────────────────────
  async function usersList() {
    return _req('GET', '/admin/users', null, true);
  }

  async function usersCreate(email, password, role) {
    return _req('POST', '/admin/users', { email, password, role }, true);
  }

  async function usersToggle(id, active) {
    return _req('POST', `/admin/users/${id}/toggle`, { active }, true);
  }

  async function usersDelete(id) {
    return _req('DELETE', `/admin/users/${id}`, null, true);
  }

  async function usersChangePassword(id, password) {
    return _req('POST', `/admin/users/${id}/password`, { password }, true);
  }

  // ── Admin: dominios ──────────────────────────────────────
  async function domainsList() {
    return _req('GET', '/admin/domains', null, true);
  }

  async function domainsAdd(domain) {
    return _req('POST', '/admin/domains', { domain }, true);
  }

  async function domainsDelete(id) {
    return _req('DELETE', `/admin/domains/${id}`, null, true);
  }

  // ── Admin: capas ─────────────────────────────────────────
  async function layersInfo() {
    return _req('GET', '/admin/layers/info', null, true);
  }

  async function layersUpdate() {
    return _req('POST', '/admin/layers/update', {}, true);
  }

  // ── Admin: textos del reporte ─────────────────
  async function reportTextsList() {
    return _req('GET', '/admin/report-texts', null, true);
  }

  async function reportTextGet(code) {
    return _req('GET', `/admin/report-texts/${encodeURIComponent(code)}`, null, true);
  }

  async function reportTextCreate(item) {
    return _req('POST', '/admin/report-texts', item, true);
  }

  async function reportTextUpdate(code, item) {
    return _req('PUT', `/admin/report-texts/${encodeURIComponent(code)}`, item, true);
  }

  async function reportTextDelete(code) {
    return _req('DELETE', `/admin/report-texts/${encodeURIComponent(code)}`, null, true);
  }

  // ── Admin: logs ──────────────────────────────────────────
  async function logs(limit = 200) {
    return _req('GET', `/admin/logs?limit=${limit}`, null, true);
  }

  // ── Health ───────────────────────────────────────────────
  async function health() {
    return _req('GET', '/health');
  }

  return {
    // token
    getToken, setToken, clearToken, getRole, isLoggedIn,
    // auth
    login, logout, me, recover,
    // análisis
    analyze, analyzeStatus,
    // admin
    stats, history, historyGet, historyDelete,
    usersList, usersCreate, usersToggle, usersDelete, usersChangePassword,
    domainsList, domainsAdd, domainsDelete,
    layersInfo, layersUpdate,
    reportTextsList, reportTextGet, reportTextCreate, reportTextUpdate, reportTextDelete,
    logs, health,
  };
})();
