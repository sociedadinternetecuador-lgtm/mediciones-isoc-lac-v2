/* ═══════════════════════════════════════════════════════════
   admin.js — Dashboard admin
   Usa clases CSS del diseño original (style.css v1)
   ═══════════════════════════════════════════════════════════ */

const Admin = (() => {

  let _section  = 'stats';
  let _histPage = 1;
  let _histQ    = '';
  let _reportTexts = [];
  let _reportTextQ = '';
  let _reportTextVisibility = 'all';

  // ── Toast ────────────────────────────────────────────────
  function toast(msg, type = 'info') {
    const c = document.getElementById('toast-container');
    if (!c) return;
    const el = document.createElement('div');
    el.className = `alert alert-${type === 'ok' ? 'success' : type === 'err' ? 'error' : 'info'}`;
    el.style.cssText = 'pointer-events:auto;min-width:220px;box-shadow:var(--shadow-md)';
    el.textContent = msg;
    c.appendChild(el);
    setTimeout(() => el.remove(), 3500);
  }

  // ── Init ─────────────────────────────────────────────────
  async function init() {
    await I18n.init();

    if (!API.isLoggedIn()) { location.href = '/admin/login'; return; }

    let me;
    try { me = await API.me(); }
    catch { API.clearToken(); location.href = '/admin/login'; return; }

    const emailEl = document.getElementById('sidebar-email');
    if (emailEl) emailEl.textContent = me.email || '';

    if (me.role !== 'admin') {
      document.querySelectorAll('[data-admin-only]').forEach(el => el.remove());
    }

    // Menu móvil
    document.getElementById('menu-toggle')
      ?.addEventListener('click', () =>
        document.getElementById('mobile-nav')?.classList.toggle('open'));

    // Sidebar clicks (desktop) + mobile nav
    document.querySelectorAll('.admin-menu-item[data-section], .admin-mobile-nav button[data-section]').forEach(btn => {
      btn.addEventListener('click', () => {
        navigate(btn.getAttribute('data-section'));
        // Cerrar mobile nav al seleccionar
        document.getElementById('mobile-nav')?.classList.remove('open');
      });
    });

    // Hamburguesa
    document.getElementById('menu-toggle')
      ?.addEventListener('click', () =>
        document.getElementById('mobile-nav')?.classList.toggle('open'));

    document.addEventListener('langchange', () => {
      I18n.init().then(() => navigate(_section));
    });

    navigate('stats');
  }

  // ── Navegación ───────────────────────────────────────────
  function navigate(section) {
    _section = section;

    document.querySelectorAll('.admin-menu-item[data-section], .admin-mobile-nav button[data-section]').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-section') === section);
    });

    const titleEl = document.getElementById('section-title');
    if (titleEl) titleEl.textContent = I18n.get(`admin.nav_${section}`) || section;
    if (titleEl && section === 'report_texts') titleEl.textContent = 'Textos del reporte';

    const panel = document.getElementById('main-panel');
    if (panel) panel.innerHTML = `<div class="loader-wrap visible"><div class="spinner"></div></div>`;

    switch (section) {
      case 'stats':   loadStats();   break;
      case 'history': loadHistory(); break;
      case 'domains': loadDomains(); break;
      case 'users':   loadUsers();   break;
      case 'layers':  loadLayers();  break;
      case 'report_texts': loadReportTexts(); break;
      case 'logs':    loadLogs();    break;
    }
  }

  // ── STATS ────────────────────────────────────────────────
  async function loadStats() {
    const panel = document.getElementById('main-panel');
    try {
      const d = await API.stats();
      panel.innerHTML = `
        <div class="metrics-grid" style="margin-bottom:1.5rem">
          <div class="metric-card">
            <div class="metric-number">${d.total_analyses}</div>
            <div class="metric-label">${I18n.get('admin.stat_total')}</div>
          </div>
          <div class="metric-card">
            <div class="metric-number">${d.unique_domains}</div>
            <div class="metric-label">${I18n.get('admin.stat_unique')}</div>
          </div>
          <div class="metric-card metric-success">
            <div class="metric-number">${d.secure_domains || 0}</div>
            <div class="metric-label">${I18n.get('admin.stat_secure')}</div>
          </div>
          <div class="metric-card metric-high">
            <div class="metric-number">${d.insecure_domains || 0}</div>
            <div class="metric-label">${I18n.get('admin.stat_insecure')}</div>
          </div>
          <div class="metric-card metric-critical">
            <div class="metric-number">${d.bogus_domains}</div>
            <div class="metric-label">${I18n.get('admin.stat_bogus')}</div>
          </div>
          <div class="metric-card">
            <div class="metric-number">${d.active_users}</div>
            <div class="metric-label">${I18n.get('admin.stat_users')}</div>
          </div>
        </div>
        ${d.recent?.length ? `
        <div class="card">
          <div class="card-title">${I18n.get('admin.history_title')}</div>
          <div class="table-wrap">${_histTable(d.recent, false)}</div>
        </div>` : ''}
      `;
    } catch (e) { panel.innerHTML = _errPanel(e.message); }
  }

  // ── HISTORY ──────────────────────────────────────────────
  async function loadHistory(page = 1, q = '') {
    _histPage = page; _histQ = q;
    const panel = document.getElementById('main-panel');
    try {
      const d = await API.history(page, q);
      panel.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem;margin-bottom:1rem">
          <input type="text" class="form-input" id="hist-search" value="${_esc(q)}"
            placeholder="${I18n.get('admin.history_search')}"
            style="max-width:280px"
            oninput="Admin._histSearch(this.value)">
        </div>
        <div class="card">
          <div class="table-wrap">
            ${d.items?.length
              ? _histTable(d.items, true)
              : `<p class="text-muted" style="padding:1.5rem;text-align:center">${I18n.get('admin.history_empty')}</p>`}
          </div>
        </div>
        ${d.pages > 1 ? _pagination(page, d.pages, 'Admin._histGo') : ''}
      `;
    } catch (e) { panel.innerHTML = _errPanel(e.message); }
  }

  function _histSearch(val) {
    clearTimeout(Admin._searchTimer);
    Admin._searchTimer = setTimeout(() => loadHistory(1, val), 350);
  }
  function _histGo(page) { loadHistory(page, _histQ); }

  function _histTable(items, withActions) {
    const rows = items.map(a => {
      const st   = a.status || 'INDETERMINATE';
      const date = a.timestamp ? new Date(a.timestamp).toLocaleString() : '—';
      const acts = withActions ? `
        <td>
          <button class="btn btn-sm" onclick="Admin._histView('${a.id}')">${I18n.get('admin.history_view')}</button>
          <button class="btn btn-sm" style="color:var(--color-critical)" onclick="Admin._histDelete('${a.id}',this)">${I18n.get('admin.history_delete')}</button>
        </td>` : '';
      return `<tr>
        <td class="text-mono">${_esc(a.domain)}</td>
        <td style="font-size:.8rem;color:var(--color-text-muted)">${date}</td>
        <td><span class="status-badge status-${st}">${I18n.get('status.' + st) || st}</span></td>
        <td>${a.error_count ?? '—'}</td>
        ${acts}
      </tr>`;
    }).join('');

    return `<table>
      <thead><tr>
        <th>${I18n.get('admin.history_domain')}</th>
        <th>${I18n.get('admin.history_date')}</th>
        <th>${I18n.get('admin.history_status')}</th>
        <th>${I18n.get('admin.history_errors')}</th>
        ${withActions ? `<th>${I18n.get('admin.history_actions')}</th>` : ''}
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
  }

  async function _histView(id) {
    try {
      const data = await API.historyGet(id);
      sessionStorage.setItem('obs_report', JSON.stringify(data));
      window.open('/report', '_blank');
    } catch (e) { toast(e.message || I18n.get('admin.action_error'), 'err'); }
  }

  async function _histDelete(id, btn) {
    if (!confirm(I18n.get('admin.confirm_delete'))) return;
    btn.disabled = true;
    try {
      await API.historyDelete(id);
      toast(I18n.get('admin.action_ok'), 'ok');
      loadHistory(_histPage, _histQ);
    } catch (e) {
      toast(e.message || I18n.get('admin.action_error'), 'err');
      btn.disabled = false;
    }
  }

  // ── DOMAINS ──────────────────────────────────────────────
  async function loadDomains() {
    const panel = document.getElementById('main-panel');
    try {
      const d = await API.domainsList();
      const rows = (d.domains || []).map(dom => {
        const st   = dom.last_status;
        const date = dom.last_analyzed ? new Date(dom.last_analyzed).toLocaleDateString() : I18n.get('admin.domains_never');
        return `<tr>
          <td class="text-mono">${_esc(dom.domain)}</td>
          <td>${st ? `<span class="status-badge status-${st}">${I18n.get('status.' + st) || st}</span>` : '—'}</td>
          <td style="font-size:.8rem;color:var(--color-text-muted)">${date}</td>
          <td><button class="btn btn-sm" style="color:var(--color-critical)" onclick="Admin._domDelete('${dom.id}',this)">${I18n.get('admin.history_delete')}</button></td>
        </tr>`;
      }).join('');

      panel.innerHTML = `
        <div style="display:flex;justify-content:flex-end;margin-bottom:1rem">
          <button class="btn btn-primary btn-sm" onclick="Admin._domAdd()">+ ${I18n.get('admin.domains_add')}</button>
        </div>
        <div class="card">
          <div class="table-wrap">
            ${d.domains?.length
              ? `<table><thead><tr>
                  <th>${I18n.get('admin.history_domain')}</th>
                  <th>${I18n.get('admin.domains_last_status')}</th>
                  <th>${I18n.get('admin.domains_last_analyzed')}</th>
                  <th></th>
                </tr></thead><tbody>${rows}</tbody></table>`
              : `<p class="text-muted" style="padding:1.5rem;text-align:center">${I18n.get('admin.domains_empty')}</p>`}
          </div>
        </div>
      `;
    } catch (e) { panel.innerHTML = _errPanel(e.message); }
  }

  async function _domAdd() {
    const domain = prompt(I18n.get('admin.domains_add') + ':');
    if (!domain?.trim()) return;
    try {
      await API.domainsAdd(domain.trim());
      toast(I18n.get('admin.action_ok'), 'ok');
      loadDomains();
    } catch (e) { toast(e.message || I18n.get('admin.action_error'), 'err'); }
  }

  async function _domDelete(id, btn) {
    if (!confirm(I18n.get('admin.confirm_delete'))) return;
    btn.disabled = true;
    try {
      await API.domainsDelete(id);
      toast(I18n.get('admin.action_ok'), 'ok');
      loadDomains();
    } catch (e) {
      toast(e.message || I18n.get('admin.action_error'), 'err');
      btn.disabled = false;
    }
  }

  // ── USERS ────────────────────────────────────────────────
  async function loadUsers() {
    const panel = document.getElementById('main-panel');
    try {
      const d = await API.usersList();
      const rows = (d.users || []).map(u => {
        const roleLabel   = u.role === 'admin' ? I18n.get('admin.users_role_admin') : I18n.get('admin.users_role_analyst');
        const statusLabel = u.active ? I18n.get('admin.users_active') : I18n.get('admin.users_inactive');
        const statusClass = u.active ? 'alert-success' : 'alert-error';
        const lastLogin   = u.last_login ? new Date(u.last_login).toLocaleDateString() : I18n.get('admin.users_never');
        return `<tr>
          <td class="text-mono">${_esc(u.email)}</td>
          <td>${roleLabel}</td>
          <td><span class="pill ${u.active ? '' : 'pill-outline'}" style="font-size:.75rem">${statusLabel}</span></td>
          <td style="font-size:.8rem;color:var(--color-text-muted)">${lastLogin}</td>
          <td>
            <button class="btn btn-sm" onclick="Admin._userToggle('${u.id}',${!u.active})">${u.active ? '⏸' : '▶'}</button>
            <button class="btn btn-sm" onclick="Admin._userPwd('${u.id}')">🔑</button>
            <button class="btn btn-sm" style="color:var(--color-critical)" onclick="Admin._userDelete('${u.id}',this)">✕</button>
          </td>
        </tr>`;
      }).join('');

      panel.innerHTML = `
        <div style="display:flex;justify-content:flex-end;margin-bottom:1rem">
          <button class="btn btn-primary btn-sm" onclick="Admin._showUserModal()">+ ${I18n.get('admin.users_add')}</button>
        </div>
        <div class="card">
          <div class="table-wrap">
            ${d.users?.length
              ? `<table><thead><tr>
                  <th>${I18n.get('admin.users_email')}</th>
                  <th>${I18n.get('admin.users_role')}</th>
                  <th>${I18n.get('admin.users_status')}</th>
                  <th>${I18n.get('admin.users_last_login')}</th>
                  <th>${I18n.get('admin.users_actions')}</th>
                </tr></thead><tbody>${rows}</tbody></table>`
              : `<p class="text-muted" style="padding:1.5rem;text-align:center">${I18n.get('admin.users_empty')}</p>`}
          </div>
        </div>

        <!-- Modal nuevo usuario -->
        <div id="user-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:200;align-items:center;justify-content:center;padding:1rem">
          <div class="card" style="width:100%;max-width:420px;position:relative">
            <button onclick="Admin._closeUserModal()" style="position:absolute;top:.75rem;right:.75rem;background:none;border:none;font-size:1.1rem;color:var(--color-text-muted);cursor:pointer">✕</button>
            <div class="card-title">${I18n.get('admin.users_add')}</div>
            <div class="alert alert-error hidden" id="user-modal-error"></div>
            <div class="form-group">
              <label class="form-label">${I18n.get('admin.users_email')}</label>
              <input class="form-input" id="new-user-email" type="email" placeholder="usuario@ejemplo.com">
            </div>
            <div class="form-group">
              <label class="form-label">${I18n.get('admin.password_label')}</label>
              <input class="form-input" id="new-user-pwd" type="password" placeholder="••••••••">
            </div>
            <div class="form-group">
              <label class="form-label">${I18n.get('admin.users_role')}</label>
              <select class="form-input" id="new-user-role">
                <option value="analyst">${I18n.get('admin.users_role_analyst')}</option>
                <option value="admin">${I18n.get('admin.users_role_admin')}</option>
              </select>
            </div>
            <div style="display:flex;gap:.5rem;justify-content:flex-end">
              <button class="btn" onclick="Admin._closeUserModal()">Cancelar</button>
              <button class="btn btn-primary" onclick="Admin._createUser()">${I18n.get('admin.users_add')}</button>
            </div>
          </div>
        </div>
      `;
    } catch (e) { panel.innerHTML = _errPanel(e.message); }
  }

  function _showUserModal() {
    const m = document.getElementById('user-modal');
    if (m) m.style.display = 'flex';
  }
  function _closeUserModal() {
    const m = document.getElementById('user-modal');
    if (m) m.style.display = 'none';
  }

  async function _createUser() {
    const email = document.getElementById('new-user-email')?.value.trim();
    const pwd   = document.getElementById('new-user-pwd')?.value;
    const role  = document.getElementById('new-user-role')?.value;
    const errEl = document.getElementById('user-modal-error');

    errEl?.classList.add('hidden');

    if (!email || !pwd) {
      if (errEl) { errEl.textContent = I18n.get('errors.missing_fields'); errEl.classList.remove('hidden'); }
      return;
    }
    if (pwd.length < 8) {
      if (errEl) { errEl.textContent = I18n.get('errors.password_too_short'); errEl.classList.remove('hidden'); }
      return;
    }
    try {
      await API.usersCreate(email, pwd, role);
      _closeUserModal();
      toast(I18n.get('admin.action_ok'), 'ok');
      loadUsers();
    } catch (e) {
      if (errEl) {
        errEl.textContent = e.error === 'user_exists'
          ? I18n.get('errors.user_exists')
          : (e.message || I18n.get('admin.action_error'));
        errEl.classList.remove('hidden');
      }
    }
  }

  async function _userToggle(id, active) {
    try {
      await API.usersToggle(id, active);
      toast(I18n.get('admin.action_ok'), 'ok');
      loadUsers();
    } catch (e) { toast(e.message || I18n.get('admin.action_error'), 'err'); }
  }

  async function _userPwd(id) {
    const pwd = prompt(I18n.get('admin.users_change_password') + ' (min 8):');
    if (!pwd) return;
    if (pwd.length < 8) { toast(I18n.get('errors.password_too_short'), 'err'); return; }
    try {
      await API.usersChangePassword(id, pwd);
      toast(I18n.get('admin.action_ok'), 'ok');
    } catch (e) { toast(e.message || I18n.get('admin.action_error'), 'err'); }
  }

  async function _userDelete(id, btn) {
    if (!confirm(I18n.get('admin.confirm_delete_user'))) return;
    btn.disabled = true;
    try {
      await API.usersDelete(id);
      toast(I18n.get('admin.action_ok'), 'ok');
      loadUsers();
    } catch (e) {
      toast(e.message || I18n.get('admin.action_error'), 'err');
      btn.disabled = false;
    }
  }

  // ── LAYERS ───────────────────────────────────────────────
  async function loadLayers() {
    const panel = document.getElementById('main-panel');
    try {
      const d = await API.layersInfo();
      const counts = d.layer_counts || {};
      panel.innerHTML = `
        <div class="card">
          <div class="table-wrap">
            <table>
              <tbody>
                <tr><td>${I18n.get('admin.layers_dnsviz')}</td><td class="text-mono">${_esc(d.dnsviz_version)}</td></tr>
                <tr><td>${I18n.get('admin.layers_capa1')}</td><td class="text-mono">${counts['capa1-catalogo-dnsviz'] ?? '—'} ${I18n.get('admin.layers_records')}</td></tr>
                <tr><td>${I18n.get('admin.layers_capa2')}</td><td class="text-mono">${counts['capa2-mapeo-normativo'] ?? '—'} ${I18n.get('admin.layers_records')}</td></tr>
                <tr><td>${I18n.get('admin.layers_capa3')}</td><td class="text-mono">${counts['capa3-explicaciones'] ?? '—'} ${I18n.get('admin.layers_records')}</td></tr>
              </tbody>
            </table>
          </div>
          <div style="margin-top:1rem">
            <button class="btn" id="layers-btn" onclick="Admin._layersUpdate()">
              ${I18n.get('admin.layers_update')}
            </button>
          </div>
        </div>
      `;
    } catch (e) { panel.innerHTML = _errPanel(e.message); }
  }

  async function _layersUpdate() {
    const btn = document.getElementById('layers-btn');
    if (btn) { btn.disabled = true; btn.textContent = I18n.get('admin.layers_updating'); }
    try {
      await API.layersUpdate();
      toast(I18n.get('admin.action_ok'), 'ok');
      loadLayers();
    } catch (e) {
      toast(e.message || I18n.get('admin.action_error'), 'err');
      if (btn) { btn.disabled = false; btn.textContent = I18n.get('admin.layers_update'); }
    }
  }

  // ── LOGS ─────────────────────────────────────────────────
  async function loadReportTexts() {
    const panel = document.getElementById('main-panel');
    try {
      const d = await API.reportTextsList();
      _reportTexts = d.items || [];
      panel.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem;margin-bottom:1rem">
          <div style="display:flex;gap:.5rem;flex-wrap:wrap">
            <input type="text" class="form-input" value="${_esc(_reportTextQ)}" placeholder="Buscar codigo..." style="max-width:240px" oninput="Admin._reportTextSearch(this.value)">
            <select class="form-input" style="max-width:190px" onchange="Admin._reportTextFilter(this.value)">
              <option value="all" ${_reportTextVisibility==='all'?'selected':''}>Todas</option>
              <option value="visible" ${_reportTextVisibility==='visible'?'selected':''}>Visibles</option>
              <option value="hidden" ${_reportTextVisibility==='hidden'?'selected':''}>Ocultas</option>
            </select>
          </div>
          <button class="btn btn-primary btn-sm" onclick="Admin._reportTextNew()">+ Nuevo texto</button>
        </div>
        <div class="card"><div class="table-wrap" id="rt-table"></div></div>
        <div id="rt-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:220;align-items:center;justify-content:center;padding:1rem">
          <div class="card" style="width:100%;max-width:860px;max-height:92vh;overflow:auto;position:relative">
            <button onclick="Admin._reportTextClose()" style="position:absolute;top:.75rem;right:.75rem;background:none;border:none;font-size:1.1rem;color:var(--color-text-muted);cursor:pointer">x</button>
            <div class="card-title" id="rt-modal-title">Texto del reporte</div>
            <div class="alert alert-error hidden" id="rt-modal-error"></div>
            <div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.75rem">
              ${_rtInput('code','Codigo DNSViz','text')}
              <div class="form-group"><label class="form-label">Audiencia</label><select class="form-input" id="rt-audience_level"><option value="both">both</option><option value="executive">executive</option><option value="technical">technical</option></select></div>
            </div>
            <div class="rt-tabs" style="display:flex;gap:.4rem;margin:.6rem 0">
              <button type="button" class="btn btn-sm btn-primary" id="rt-tab-es" onclick="Admin._reportTextLang('es')">Español</button>
              <button type="button" class="btn btn-sm" id="rt-tab-en" onclick="Admin._reportTextLang('en')">English</button>
            </div>
            <div id="rt-lang-es" class="rt-lang-panel">${_rtLangFields('es')}</div>
            <div id="rt-lang-en" class="rt-lang-panel hidden">${_rtLangFields('en')}</div>
            <div class="alert alert-info hidden" id="rt-semantic-warning">Este texto puede contradecir un estado DNSSEC SECURE.</div>
            <label style="display:flex;align-items:center;gap:.5rem;margin:.75rem 0"><input type="checkbox" id="rt-report_visibility" checked> Visible en resumen ejecutivo del reporte</label>
            <div style="display:flex;gap:.5rem;justify-content:flex-end"><button class="btn" onclick="Admin._reportTextClose()">Cancelar</button><button class="btn btn-primary" onclick="Admin._reportTextSave()">Guardar</button></div>
          </div>
        </div>`;
      _renderReportTextsTable();
    } catch (e) { panel.innerHTML = _errPanel(e.message); }
  }

  function _rtInput(id, label, type) {
    return `<div class="form-group"><label class="form-label">${label}</label><input class="form-input" id="rt-${id}" type="${type}"></div>`;
  }

  function _rtArea(id, label) {
    return `<div class="form-group"><label class="form-label">${label}</label><textarea class="form-input" id="rt-${id}" rows="3"></textarea></div>`;
  }

  function _rtLangFields(lang) {
    return `
      ${_rtInput(`${lang}-public_title`,'Titulo publico','text')}
      ${_rtArea(`${lang}-executive_description`,'Descripcion ejecutiva')}
      ${_rtArea(`${lang}-technical_description`,'Descripcion tecnica')}
      <div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.75rem">${_rtArea(`${lang}-dnssec_impact_text`,'Impacto DNSSEC')}${_rtArea(`${lang}-operational_impact_text`,'Impacto operativo')}</div>
      <div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.75rem">
        ${_rtArea(`${lang}-recommended_action_owner`,'Accion owner')}${_rtArea(`${lang}-recommended_action_hosting`,'Accion hosting')}
        ${_rtArea(`${lang}-recommended_action_registrar`,'Accion registrar')}${_rtArea(`${lang}-recommended_action_registry`,'Accion registry')}
      </div>`;
  }

  function _filteredReportTexts() {
    const q = _reportTextQ.trim().toUpperCase();
    return _reportTexts.filter(item => {
      const visible = item.report_visibility !== false;
      return (!q || String(item.code || '').toUpperCase().includes(q))
        && (_reportTextVisibility === 'all' || (_reportTextVisibility === 'visible' && visible) || (_reportTextVisibility === 'hidden' && !visible));
    });
  }

  function _renderReportTextsTable() {
    const el = document.getElementById('rt-table');
    if (!el) return;
    const rows = _filteredReportTexts().map(item => `
      <tr><td class="text-mono">${_esc(item.code)}</td><td>${_esc(item.public_title || '')}</td><td>${_esc(item.audience_level || 'both')}</td><td>${item.report_visibility === false ? 'Oculto' : 'Visible'}</td><td style="font-size:.8rem;color:var(--color-text-muted)">${item.updated_at ? new Date(item.updated_at).toLocaleString() : '-'}</td><td><button class="btn btn-sm" onclick="Admin._reportTextEdit('${_esc(item.code)}')">Editar</button> <button class="btn btn-sm" style="color:var(--color-critical)" onclick="Admin._reportTextDelete('${_esc(item.code)}')">Eliminar</button></td></tr>`).join('');
    el.innerHTML = rows ? `<table><thead><tr><th>Codigo</th><th>Titulo</th><th>Audiencia</th><th>Visibilidad</th><th>Actualizado</th><th></th></tr></thead><tbody>${rows}</tbody></table>` : '<p class="text-muted" style="padding:1.5rem;text-align:center">No hay textos personalizados.</p>';
  }

  function _reportTextSearch(value) { _reportTextQ = value || ''; _renderReportTextsTable(); }
  function _reportTextFilter(value) { _reportTextVisibility = value || 'all'; _renderReportTextsTable(); }
  function _reportTextNew() { _fillReportTextForm({ audience_level:'both', report_visibility:true }); document.getElementById('rt-code').disabled = false; document.getElementById('rt-modal-title').textContent = 'Nuevo texto del reporte'; document.getElementById('rt-modal').style.display = 'flex'; }
  function _reportTextEdit(code) { const item = _reportTexts.find(x => x.code === code); if (!item) return; _fillReportTextForm(item); document.getElementById('rt-code').disabled = true; document.getElementById('rt-modal-title').textContent = `Editar ${code}`; document.getElementById('rt-modal').style.display = 'flex'; }
  function _reportTextClose() { const m = document.getElementById('rt-modal'); if (m) m.style.display = 'none'; }
  function _reportTextLang(lang) {
    ['es','en'].forEach(l => {
      document.getElementById(`rt-lang-${l}`)?.classList.toggle('hidden', l !== lang);
      document.getElementById(`rt-tab-${l}`)?.classList.toggle('btn-primary', l === lang);
    });
  }

  function _fillReportTextForm(item) {
    const texts = item.texts || { es: item, en: {} };
    document.getElementById('rt-code').value = item.code || '';
    ['es','en'].forEach(lang => {
      const langText = texts[lang] || {};
      ['public_title','executive_description','technical_description','dnssec_impact_text','operational_impact_text','recommended_action_owner','recommended_action_hosting','recommended_action_registrar','recommended_action_registry'].forEach(k => {
        const el = document.getElementById(`rt-${lang}-${k}`);
        if (el) {
          el.value = langText[k] || '';
          el.oninput = _reportTextSemanticWarning;
        }
      });
    });
    const aud = document.getElementById('rt-audience_level'); if (aud) aud.value = item.audience_level || 'both';
    const vis = document.getElementById('rt-report_visibility'); if (vis) vis.checked = item.report_visibility !== false;
    _reportTextLang('es');
    _reportTextSemanticWarning();
    document.getElementById('rt-modal-error')?.classList.add('hidden');
  }

  function _readReportTextForm() {
    const item = { texts: { es: {}, en: {} } };
    item.code = document.getElementById('rt-code')?.value || '';
    ['es','en'].forEach(lang => {
      ['public_title','executive_description','technical_description','dnssec_impact_text','operational_impact_text','recommended_action_owner','recommended_action_hosting','recommended_action_registrar','recommended_action_registry'].forEach(k => {
        item.texts[lang][k] = document.getElementById(`rt-${lang}-${k}`)?.value || '';
      });
    });
    item.code = item.code.trim().toUpperCase();
    item.audience_level = document.getElementById('rt-audience_level')?.value || 'both';
    item.report_visibility = !!document.getElementById('rt-report_visibility')?.checked;
    return item;
  }

  function _reportTextSemanticWarning() {
    const text = ['es','en'].flatMap(lang =>
      ['public_title','executive_description','technical_description','dnssec_impact_text','operational_impact_text'].map(k =>
        document.getElementById(`rt-${lang}-${k}`)?.value || ''
      )
    ).join(' ').toLowerCase();
    const risky = ['dnssec roto', 'validacion dnssec fallida', 'validación dnssec fallida', 'firma invalida', 'firma inválida', 'dominio comprometido', 'broken dnssec', 'dnssec validation failed', 'invalid signature', 'compromised domain'];
    document.getElementById('rt-semantic-warning')?.classList.toggle('hidden', !risky.some(p => text.includes(p)));
  }

  async function _reportTextSave() {
    const item = _readReportTextForm();
    const errEl = document.getElementById('rt-modal-error');
    if (!item.code) { if (errEl) { errEl.textContent = 'Codigo requerido'; errEl.classList.remove('hidden'); } return; }
    try {
      const exists = _reportTexts.some(x => x.code === item.code);
      if (exists) await API.reportTextUpdate(item.code, item); else await API.reportTextCreate(item);
      toast(I18n.get('admin.action_ok'), 'ok'); _reportTextClose(); await loadReportTexts();
    } catch (e) { if (errEl) { errEl.textContent = e.message || I18n.get('admin.action_error'); errEl.classList.remove('hidden'); } }
  }

  async function _reportTextDelete(code) {
    if (!confirm(`Eliminar texto personalizado ${code}?`)) return;
    try { await API.reportTextDelete(code); toast(I18n.get('admin.action_ok'), 'ok'); await loadReportTexts(); }
    catch (e) { toast(e.message || I18n.get('admin.action_error'), 'err'); }
  }

  async function loadLogs() {
    const panel = document.getElementById('main-panel');
    try {
      const d = await API.logs(200);
      panel.innerHTML = `
        <div style="display:flex;justify-content:flex-end;margin-bottom:.75rem">
          <button class="btn btn-sm" onclick="Admin.navigate('logs')">↻ ${I18n.get('admin.logs_refresh')}</button>
        </div>
        <div class="card" style="padding:0">
          <div style="background:var(--color-text);color:#e2e8f0;border-radius:var(--radius-lg);padding:1rem;max-height:480px;overflow-y:auto;font-family:var(--font-mono);font-size:.75rem;line-height:1.7">
            ${d.lines?.length
              ? d.lines.map(l => `<div>${_esc(l)}</div>`).join('')
              : `<div style="color:#888">${I18n.get('admin.logs_empty')}</div>`}
          </div>
        </div>
      `;
    } catch (e) { panel.innerHTML = _errPanel(e.message); }
  }

  // ── Logout ───────────────────────────────────────────────
  async function logout() {
    await API.logout();
    location.href = '/admin/login';
  }

  // ── Helpers ──────────────────────────────────────────────
  function _pagination(current, total, fn) {
    let html = '<div style="display:flex;justify-content:center;gap:.4rem;margin-top:1rem">';
    html += `<button class="btn btn-sm" ${current<=1?'disabled':''} onclick="${fn}(${current-1})">‹</button>`;
    for (let p = 1; p <= total; p++) {
      if (total > 7 && Math.abs(p - current) > 2 && p !== 1 && p !== total) {
        if (p === current-3 || p === current+3) html += '<span style="padding:0 4px;color:var(--color-text-muted)">…</span>';
        continue;
      }
      html += `<button class="btn btn-sm${p===current?' btn-primary':''}" onclick="${fn}(${p})">${p}</button>`;
    }
    html += `<button class="btn btn-sm" ${current>=total?'disabled':''} onclick="${fn}(${current+1})">›</button>`;
    return html + '</div>';
  }

  function _errPanel(msg) {
    return `<div class="alert alert-error">Error: ${_esc(msg || 'unknown')}</div>`;
  }

  function _esc(str) {
    if (!str) return '';
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  return {
    init, navigate, logout, toast,
    _histSearch, _histGo, _histView, _histDelete,
    _domAdd, _domDelete,
    _showUserModal, _closeUserModal, _createUser,
    _userToggle, _userPwd, _userDelete,
    _layersUpdate,
    _reportTextSearch, _reportTextFilter, _reportTextNew, _reportTextEdit,
    _reportTextClose, _reportTextLang, _reportTextSave, _reportTextDelete,
  };
})();
