/* ═══════════════════════════════════════════════════════════
   admin-data.js — Editor de capas y textos del Observatorio.
   Edita: capa1b, capa2, capa3, ui-texts, report-texts.
   capa1a (catálogo DNSViz) NO es editable — soberanía DNSViz.
   ═══════════════════════════════════════════════════════════ */

const AdminData = (() => {
  // ─── State ─────────────────────────────────────────────────
  let _index    = [];     // /admin/data items
  let _current  = null;   // current layer key (snake_case)
  let _data     = null;   // current working copy
  let _original = null;   // pristine snapshot for dirty check
  let _filter   = { q: '', cat: '', lang: '' };
  let _editingRow = null; // index in _data for tabular edits
  let _newRowMode = false;

  const LAYER_DEF = {
    capa1b:       { title: 'Capa 1B — Semántica visual DNSViz', kind: 'tabular',  filename: 'capa1b-semantica-dnsviz.json' },
    capa2:        { title: 'Capa 2 — Contexto normativo',       kind: 'tabular',  filename: 'capa2-contexto-normativo.json' },
    capa3:        { title: 'Capa 3 — Explicaciones humanas',    kind: 'tabular',  filename: 'capa3-explicaciones.json' },
    ui_texts:     { title: 'Textos de interfaz (ui-texts)',     kind: 'document', filename: 'ui-texts.json' },
    report_texts: { title: 'Textos del reporte (report-texts)', kind: 'document', filename: 'report-texts.json' },
  };

  // ─── Boot ──────────────────────────────────────────────────
  async function init() {
    if (!API.getToken()) {
      location.href = '/admin/login';
      return;
    }
    bindHeader();
    bindGlobalActions();
    bindModals();
    try {
      const me = await API.me();
      if (me.role !== 'admin') {
        showToast('Necesitas rol admin para editar capas.', 'error');
        setTimeout(() => location.href = '/admin/dashboard', 1500);
        return;
      }
    } catch (e) {
      location.href = '/admin/login';
      return;
    }
    await loadIndex();
  }

  function bindHeader() {
    document.getElementById('menu-toggle')?.addEventListener('click', () => {
      document.getElementById('mobile-nav')?.classList.toggle('open');
    });
    document.getElementById('btn-logout')?.addEventListener('click', () => {
      API.clearToken();
      location.href = '/admin/login';
    });
    document.querySelectorAll('[data-lang-toggle]').forEach(el => {
      el.addEventListener('click', () => {
        const cur = localStorage.getItem('obs_lang') || 'es';
        localStorage.setItem('obs_lang', cur === 'es' ? 'en' : 'es');
        showToast('Idioma del UI cambiado. Recarga el editor para ver los textos cargados.');
      });
    });
  }

  function bindGlobalActions() {
    document.getElementById('btn-reload')?.addEventListener('click', () => {
      if (_current) selectLayer(_current, /*force*/ true);
    });
    document.getElementById('btn-save')?.addEventListener('click', saveCurrent);
    document.getElementById('btn-restore')?.addEventListener('click', openRestoreConfirm);
  }

  function bindModals() {
    // Row modal
    const rm = document.getElementById('row-modal');
    document.getElementById('row-cancel')?.addEventListener('click',   () => rm?.close());
    document.getElementById('row-cancel-2')?.addEventListener('click', () => rm?.close());
    document.getElementById('row-form')?.addEventListener('submit', e => {
      e.preventDefault();
      submitRowForm();
    });

    // Restore modal
    const rsm = document.getElementById('restore-modal');
    document.getElementById('restore-cancel')?.addEventListener('click',   () => rsm?.close());
    document.getElementById('restore-cancel-2')?.addEventListener('click', () => rsm?.close());
    document.getElementById('restore-confirm')?.addEventListener('click', confirmRestore);

    // Raw JSON modal
    const rwm = document.getElementById('raw-modal');
    document.getElementById('raw-cancel')?.addEventListener('click',   () => rwm?.close());
    document.getElementById('raw-cancel-2')?.addEventListener('click', () => rwm?.close());
    document.getElementById('raw-form')?.addEventListener('submit', e => {
      e.preventDefault();
      applyRawJSON();
    });
  }

  // ─── HTTP helpers ──────────────────────────────────────────
  async function _req(method, path, body) {
    const opts = {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${API.getToken()}`,
      },
    };
    if (body !== undefined) opts.body = JSON.stringify(body);
    const r = await fetch(path, opts);
    let data;
    try { data = await r.json(); } catch { data = null; }
    if (!r.ok) {
      const msg = (data && (data.message || data.error)) || `HTTP ${r.status}`;
      throw new Error(msg);
    }
    return data;
  }

  // ─── Index & sidebar ───────────────────────────────────────
  async function loadIndex() {
    try {
      const res = await _req('GET', '/admin/data');
      _index = res.items || [];
      const cap1aFile = res.capa1a_filename;
      if (cap1aFile) document.getElementById('capa1a-filename').textContent = cap1aFile;
      renderSidebar();
      // Auto-select first if none selected
      if (_index[0]) selectLayer(_index[0].key);
    } catch (e) {
      showToast('No se pudo cargar el índice: ' + e.message, 'error');
    }
  }

  function renderSidebar() {
    const root = document.getElementById('layer-list');
    if (!root) return;
    root.innerHTML = _index.map(it => {
      const def = LAYER_DEF[it.key] || {};
      const subParts = [];
      if (it.kind === 'tabular') subParts.push(`${it.count} filas`);
      else subParts.push((it.languages || []).join(' / ').toUpperCase() || 'JSON');
      if (it.modified) subParts.push(formatDate(it.modified));
      return `
        <li>
          <button class="layer-btn ${it.key === _current ? 'active' : ''}" data-layer="${esc(it.key)}">
            <span class="layer-name">${esc(def.title || it.key)}</span>
            <span class="layer-sub">${esc(it.filename)} · ${esc(subParts.join(' · '))}</span>
          </button>
        </li>
      `;
    }).join('');
    root.querySelectorAll('.layer-btn').forEach(btn => {
      btn.addEventListener('click', () => selectLayer(btn.getAttribute('data-layer')));
    });
  }

  // ─── Layer load / save ─────────────────────────────────────
  async function selectLayer(key, force = false) {
    if (!key || !LAYER_DEF[key]) return;
    if (!force && _current === key) return;
    if (isDirty()) {
      if (!confirm('Tienes cambios sin guardar. ¿Descartar y cambiar de capa?')) return;
    }
    _current = key;
    _filter = { q: '', cat: '', lang: '' };
    _editingRow = null;
    _newRowMode = false;
    document.querySelectorAll('.layer-btn').forEach(b => {
      b.classList.toggle('active', b.getAttribute('data-layer') === key);
    });
    const def = LAYER_DEF[key];
    document.getElementById('layer-title').textContent = def.title;
    document.getElementById('layer-meta').textContent = def.filename;
    document.getElementById('btn-save').disabled = true;
    document.getElementById('admin-editor').innerHTML =
      `<p class="empty-state">Cargando…</p>`;

    try {
      const slug = key.replace('_', '-');
      const data = await _req('GET', `/admin/data/${slug}`);
      _data = data;
      _original = JSON.parse(JSON.stringify(data));
      renderEditor();
      updateStatus();
    } catch (e) {
      document.getElementById('admin-editor').innerHTML =
        `<p class="empty-state">No se pudo cargar: ${esc(e.message)}</p>`;
    }
  }

  async function saveCurrent() {
    if (!_current || !_data) return;
    if (!isDirty()) return;
    const slug = _current.replace('_', '-');
    try {
      const res = await _req('PUT', `/admin/data/${slug}`, _data);
      _original = JSON.parse(JSON.stringify(_data));
      document.getElementById('btn-save').disabled = true;
      const bk = res && res.backup ? `Backup: ${res.backup}` : '';
      showToast('Cambios guardados. ' + bk, 'success');
      updateStatus();
      // Refresh sidebar metadata
      try {
        const idx = await _req('GET', '/admin/data');
        _index = idx.items || _index;
        renderSidebar();
      } catch {}
    } catch (e) {
      showToast('Error al guardar: ' + e.message, 'error');
    }
  }

  function openRestoreConfirm() {
    if (!_current) return;
    const def = LAYER_DEF[_current];
    document.getElementById('restore-filename').textContent = def.filename;
    document.getElementById('restore-modal')?.showModal();
  }
  async function confirmRestore() {
    if (!_current) return;
    const slug = _current.replace('_', '-');
    try {
      const res = await _req('POST', `/admin/data/${slug}/restore-defaults`);
      const bk = res && res.backup ? `Backup: ${res.backup}` : '';
      document.getElementById('restore-modal')?.close();
      showToast('Archivo restaurado. ' + bk, 'success');
      await selectLayer(_current, true);
    } catch (e) {
      showToast('Error al restaurar: ' + e.message, 'error');
    }
  }

  // ─── Dirty tracking ────────────────────────────────────────
  function isDirty() {
    if (_data == null || _original == null) return false;
    return JSON.stringify(_data) !== JSON.stringify(_original);
  }
  function updateStatus() {
    const el = document.getElementById('admin-status');
    if (!el) return;
    const dirty = isDirty();
    document.getElementById('btn-save').disabled = !dirty;
    el.innerHTML = dirty
      ? `<span class="changes-pill">Cambios sin guardar</span><span>UTF-8 · ensure_ascii=False</span>`
      : `<span></span><span>Sin cambios pendientes · UTF-8 · ensure_ascii=False</span>`;
  }

  // ─── Editor dispatcher ─────────────────────────────────────
  function renderEditor() {
    const def = LAYER_DEF[_current];
    if (def.kind === 'tabular') renderTabular();
    else renderDocument();
  }

  // ═══════════════════════════════════════════════════════════
  // TABULAR (capa1b, capa2, capa3)
  // ═══════════════════════════════════════════════════════════
  function renderTabular() {
    renderTabularToolbar();
    renderTabularTable();
  }

  function renderTabularToolbar() {
    const root = document.getElementById('admin-toolbar');
    const cats = collectCategories();
    const langs = (_current === 'capa3') ? ['es', 'en'] : null;
    root.innerHTML = `
      <input type="search" id="t-search" placeholder="Buscar por código, RFC o texto…" value="${esc(_filter.q)}">
      ${cats.length ? `
        <select id="t-cat">
          <option value="">— Todas las categorías —</option>
          ${cats.map(c => `<option value="${esc(c)}" ${c === _filter.cat ? 'selected' : ''}>${esc(c)}</option>`).join('')}
        </select>` : ''}
      ${langs ? `
        <select id="t-lang">
          <option value="">— Ambos idiomas —</option>
          ${langs.map(l => `<option value="${l}" ${l === _filter.lang ? 'selected' : ''}>${l.toUpperCase()}</option>`).join('')}
        </select>` : ''}
      <div class="right">
        <button class="btn btn-primary" id="t-add">+ Nueva fila</button>
      </div>
    `;
    document.getElementById('t-search')?.addEventListener('input', e => {
      _filter.q = e.target.value.toLowerCase();
      renderTabularTable();
    });
    document.getElementById('t-cat')?.addEventListener('change', e => {
      _filter.cat = e.target.value;
      renderTabularTable();
    });
    document.getElementById('t-lang')?.addEventListener('change', e => {
      _filter.lang = e.target.value;
      renderTabularTable();
    });
    document.getElementById('t-add')?.addEventListener('click', openNewRowModal);
  }

  function collectCategories() {
    if (!Array.isArray(_data)) return [];
    if (_current === 'capa1b') {
      return uniqueSorted(_data.map(r => r.dnsviz_group || ''));
    }
    if (_current === 'capa2') {
      return uniqueSorted(_data.map(r => r.possible_operational_area || ''));
    }
    if (_current === 'capa3') {
      return uniqueSorted(_data.map(r => r.audience_level || ''));
    }
    return [];
  }
  function uniqueSorted(arr) {
    return [...new Set(arr.filter(Boolean))].sort();
  }

  function filterRows() {
    if (!Array.isArray(_data)) return [];
    const q = _filter.q;
    const cat = _filter.cat;
    const lang = _filter.lang;
    return _data.map((row, idx) => ({ row, idx })).filter(({ row }) => {
      if (q) {
        const hay = JSON.stringify(row).toLowerCase();
        if (!hay.includes(q)) return false;
      }
      if (cat) {
        if (_current === 'capa1b' && row.dnsviz_group !== cat) return false;
        if (_current === 'capa2'  && row.possible_operational_area !== cat) return false;
        if (_current === 'capa3'  && row.audience_level !== cat) return false;
      }
      if (lang && _current === 'capa3' && row.language !== lang) return false;
      return true;
    });
  }

  function renderTabularTable() {
    const root = document.getElementById('admin-editor');
    const items = filterRows();
    if (_current === 'capa3') {
      root.innerHTML = renderCapa3Table(items);
      bindCapa3RowActions();
      return;
    }
    if (_current === 'capa1b') root.innerHTML = renderCapa1bTable(items);
    else                       root.innerHTML = renderCapa2Table(items);
    bindGenericRowActions();
  }

  function renderCapa1bTable(items) {
    return `
      <div class="admin-table-wrap">
        <table class="admin-table">
          <thead><tr>
            <th>Código</th><th>Sección</th><th>Nivel</th><th>Grupo</th><th>Aplica a</th><th>Notas</th><th class="col-actions">Acciones</th>
          </tr></thead>
          <tbody>
            ${items.length ? items.map(({ row, idx }) => `
              <tr data-idx="${idx}">
                <td class="col-code">${esc(row.code)}</td>
                <td>${esc(row.dnsviz_section || '')}</td>
                <td><span class="status-pill ${esc((row.dnsviz_level||'').toUpperCase())}">${esc(row.dnsviz_level || '')}</span></td>
                <td>${esc(row.dnsviz_group || '')}</td>
                <td>${esc((row.applies_to || []).join(', '))}</td>
                <td>${esc(truncate(row.notes || '', 80))}</td>
                <td class="col-actions">
                  <button class="row-action" data-action="edit"   data-idx="${idx}">Editar</button>
                  <button class="row-action danger" data-action="delete" data-idx="${idx}">Borrar</button>
                </td>
              </tr>
            `).join('') : `<tr><td colspan="7" class="empty-state">Sin resultados.</td></tr>`}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderCapa2Table(items) {
    return `
      <div class="admin-table-wrap">
        <table class="admin-table">
          <thead><tr>
            <th>Código</th><th>Área operativa</th><th>NIST</th><th>ISO 27001</th><th>Complejidad</th><th>Esfuerzo</th><th class="col-actions">Acciones</th>
          </tr></thead>
          <tbody>
            ${items.length ? items.map(({ row, idx }) => `
              <tr data-idx="${idx}">
                <td class="col-code">${esc(row.code)}</td>
                <td>${esc(row.possible_operational_area || '')}</td>
                <td>${esc(row.nist_reference || '')}</td>
                <td>${esc(row.iso27001_reference || '')}</td>
                <td>${esc(row.operational_complexity || '')}</td>
                <td>${esc(row.estimated_effort || '')}</td>
                <td class="col-actions">
                  <button class="row-action" data-action="edit"   data-idx="${idx}">Editar</button>
                  <button class="row-action danger" data-action="delete" data-idx="${idx}">Borrar</button>
                </td>
              </tr>
            `).join('') : `<tr><td colspan="7" class="empty-state">Sin resultados.</td></tr>`}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderCapa3Table(items) {
    // Group by code (so we show one row per code; ES + EN combined)
    const byCode = {};
    items.forEach(({ row, idx }) => {
      const c = row.code;
      if (!byCode[c]) byCode[c] = { code: c, idx: { es: -1, en: -1 }, rows: { es: null, en: null }, audience_level: row.audience_level || '' };
      byCode[c].idx[row.language] = idx;
      byCode[c].rows[row.language] = row;
      if (row.audience_level && !byCode[c].audience_level) byCode[c].audience_level = row.audience_level;
    });
    const codes = Object.values(byCode).sort((a, b) => a.code.localeCompare(b.code));
    return `
      <div class="admin-table-wrap">
        <table class="admin-table">
          <thead><tr>
            <th>Código</th><th>Idiomas</th><th>Audiencia</th><th>Título (ES)</th><th>Título (EN)</th><th class="col-actions">Acciones</th>
          </tr></thead>
          <tbody>
            ${codes.length ? codes.map(c => {
              const tEs = (c.rows.es || {}).plain_title || '';
              const tEn = (c.rows.en || {}).plain_title || '';
              const hasEs = !!c.rows.es;
              const hasEn = !!c.rows.en;
              return `
                <tr data-code="${esc(c.code)}">
                  <td class="col-code">${esc(c.code)}</td>
                  <td>
                    ${hasEs ? '<span class="lang-pill lang-es">ES</span>' : ''}
                    ${hasEn ? '<span class="lang-pill lang-en">EN</span>' : ''}
                  </td>
                  <td>${esc(c.audience_level || '')}</td>
                  <td>${esc(truncate(tEs, 60))}</td>
                  <td>${esc(truncate(tEn, 60))}</td>
                  <td class="col-actions">
                    <button class="row-action" data-action="edit-c3" data-code="${esc(c.code)}">Editar</button>
                    <button class="row-action danger" data-action="delete-c3" data-code="${esc(c.code)}">Borrar</button>
                  </td>
                </tr>
              `;
            }).join('') : `<tr><td colspan="6" class="empty-state">Sin resultados.</td></tr>`}
          </tbody>
        </table>
      </div>
    `;
  }

  function bindGenericRowActions() {
    document.querySelectorAll('[data-action="edit"]').forEach(btn => {
      btn.addEventListener('click', () => openRowModal(parseInt(btn.getAttribute('data-idx'), 10), false));
    });
    document.querySelectorAll('[data-action="delete"]').forEach(btn => {
      btn.addEventListener('click', () => deleteRow(parseInt(btn.getAttribute('data-idx'), 10)));
    });
  }

  function bindCapa3RowActions() {
    document.querySelectorAll('[data-action="edit-c3"]').forEach(btn => {
      btn.addEventListener('click', () => openCapa3Modal(btn.getAttribute('data-code'), false));
    });
    document.querySelectorAll('[data-action="delete-c3"]').forEach(btn => {
      btn.addEventListener('click', () => deleteCapa3(btn.getAttribute('data-code')));
    });
  }

  function deleteRow(idx) {
    if (!Array.isArray(_data) || idx < 0 || idx >= _data.length) return;
    const code = _data[idx].code;
    if (!confirm(`¿Borrar la fila ${code}?`)) return;
    _data.splice(idx, 1);
    renderTabularTable();
    updateStatus();
  }
  function deleteCapa3(code) {
    if (!Array.isArray(_data)) return;
    if (!confirm(`¿Borrar TODAS las explicaciones (ES y EN) del código ${code}?`)) return;
    _data = _data.filter(r => r.code !== code);
    renderTabularTable();
    updateStatus();
  }

  // ─── Generic row modal (capa1b, capa2) ─────────────────────
  function openNewRowModal() {
    if (_current === 'capa3') return openCapa3Modal('', true);
    openRowModal(-1, true);
  }

  function openRowModal(idx, isNew) {
    _editingRow = idx;
    _newRowMode = isNew;
    const row = isNew ? blankRow(_current) : _data[idx];
    document.getElementById('row-modal-title').textContent =
      `${isNew ? 'Nueva fila' : 'Editar fila'} — ${LAYER_DEF[_current].title.split('—')[0].trim()}`;
    const fields = renderRowFormFields(_current, row);
    document.getElementById('row-form-fields').innerHTML = fields;
    document.getElementById('row-modal').showModal();
  }

  function blankRow(key) {
    if (key === 'capa1b') return { code: '', dnsviz_section: 'Notices', dnsviz_level: 'Warning', dnsviz_group: '', visual_status_relation: 'does_not_override_visual_status', applies_to: [], notes: '' };
    if (key === 'capa2')  return { code: '', nist_reference: '', iso27001_reference: '', possible_operational_area: 'hosting', operational_complexity: 'SIMPLE', estimated_effort: '' };
    return { code: '' };
  }

  function renderRowFormFields(key, row) {
    if (key === 'capa1b') {
      return [
        field('code',  'Código',  row.code,  { mono: true, required: true, disabled: !_newRowMode }),
        field('dnsviz_section', 'Sección DNSViz', row.dnsviz_section, { select: ['Notices','Status','Other'] }),
        field('dnsviz_level',   'Nivel',          row.dnsviz_level,   { select: ['Error','Warning','Info'] }),
        field('dnsviz_group',   'Grupo',          row.dnsviz_group),
        field('visual_status_relation', 'Relación con estado visual', row.visual_status_relation, { select: ['does_not_override_visual_status','may_cause_bogus','may_cause_insecure','informational_only'] }),
        fieldList('applies_to', 'Aplica a (lista separada por comas)', row.applies_to || []),
        fieldText('notes', 'Notas', row.notes || ''),
      ].join('');
    }
    if (key === 'capa2') {
      return [
        field('code', 'Código', row.code, { mono: true, required: true, disabled: !_newRowMode }),
        field('possible_operational_area', 'Área operativa posible', row.possible_operational_area, { select: ['hosting','registrar','registry','owner','other'] }),
        field('nist_reference',     'NIST',                  row.nist_reference || ''),
        field('iso27001_reference', 'ISO 27001',             row.iso27001_reference || ''),
        field('operational_complexity', 'Complejidad operativa', row.operational_complexity, { select: ['SIMPLE','MODERATE','COMPLEX'] }),
        field('estimated_effort',  'Esfuerzo estimado',     row.estimated_effort || ''),
      ].join('');
    }
    return '';
  }

  function field(name, label, value, opts) {
    opts = opts || {};
    if (opts.select) {
      const opts2 = opts.select.map(o => `<option value="${esc(o)}" ${o === value ? 'selected' : ''}>${esc(o)}</option>`).join('');
      return `
        <div class="field-group">
          <label class="field-label" for="f-${esc(name)}">${esc(label)}</label>
          <select id="f-${esc(name)}" name="${esc(name)}">${opts2}</select>
        </div>`;
    }
    return `
      <div class="field-group">
        <label class="field-label" for="f-${esc(name)}">${esc(label)}</label>
        <input id="f-${esc(name)}" name="${esc(name)}" type="text" value="${esc(value || '')}"
          ${opts.required ? 'required' : ''} ${opts.disabled ? 'disabled' : ''}
          style="${opts.mono ? 'font-family:ui-monospace,monospace' : ''}">
      </div>`;
  }
  function fieldText(name, label, value) {
    return `
      <div class="field-group">
        <label class="field-label" for="f-${esc(name)}">${esc(label)}</label>
        <textarea id="f-${esc(name)}" name="${esc(name)}" rows="3">${esc(value || '')}</textarea>
      </div>`;
  }
  function fieldList(name, label, value) {
    return `
      <div class="field-group">
        <label class="field-label" for="f-${esc(name)}">${esc(label)}</label>
        <input id="f-${esc(name)}" name="${esc(name)}" type="text" value="${esc((value || []).join(', '))}">
      </div>`;
  }

  function submitRowForm() {
    if (_current === 'capa3') return submitCapa3Form();
    const form = document.getElementById('row-form');
    const fd = new FormData(form);
    const update = {};
    fd.forEach((v, k) => { update[k] = v; });
    if (Array.isArray(blankRow(_current).applies_to) && update.applies_to !== undefined) {
      update.applies_to = String(update.applies_to).split(',').map(s => s.trim()).filter(Boolean);
    }
    const code = (update.code || '').trim();
    if (!code) { showToast('El campo "code" es obligatorio.', 'error'); return; }

    if (_newRowMode) {
      if (_data.some(r => r.code === code)) {
        showToast(`Ya existe una fila con code=${code}.`, 'error');
        return;
      }
      _data.push(update);
    } else {
      const idx = _editingRow;
      if (idx >= 0 && idx < _data.length) {
        _data[idx] = { ..._data[idx], ...update };
      }
    }
    document.getElementById('row-modal').close();
    renderTabularTable();
    updateStatus();
  }

  // ─── Capa 3 bilingual modal ────────────────────────────────
  function openCapa3Modal(code, isNew) {
    _newRowMode = isNew;
    _editingRow = code;  // we'll match by code
    const es = _data.find(r => r.code === code && r.language === 'es') || blankCapa3(code, 'es');
    const en = _data.find(r => r.code === code && r.language === 'en') || blankCapa3(code, 'en');
    document.getElementById('row-modal-title').textContent =
      `${isNew ? 'Nueva explicación humana (ES + EN)' : `Editar explicación — ${code}`}`;
    document.getElementById('row-form-fields').innerHTML = renderCapa3Form(es, en, isNew);
    document.getElementById('row-modal').showModal();
    // Bind add/remove for actions per language column
    bindActionsEditor('es');
    bindActionsEditor('en');
  }

  function blankCapa3(code, lang) {
    return {
      code: code || '',
      language: lang,
      audience_level: 'both',
      plain_title: '',
      plain_description: '',
      what_it_means: '',
      possible_actions: [],
      suggested_review: '',
    };
  }

  function renderCapa3Form(es, en, isNew) {
    const codeVal = es.code || en.code || '';
    return `
      <div class="field-group">
        <label class="field-label" for="f-code">Código</label>
        <input id="f-code" name="code" type="text" value="${esc(codeVal)}"
          required ${isNew ? '' : 'disabled'}
          style="font-family:ui-monospace,monospace">
      </div>
      <div class="field-group">
        <label class="field-label" for="f-aud">Audiencia (ES y EN comparten)</label>
        <select id="f-aud" name="audience_level">
          <option value="both"      ${es.audience_level==='both'?'selected':''}>both</option>
          <option value="general"   ${es.audience_level==='general'?'selected':''}>general</option>
          <option value="technical" ${es.audience_level==='technical'?'selected':''}>technical</option>
        </select>
      </div>
      <div class="bilingual-grid">
        ${capa3LangColumn('es', es)}
        ${capa3LangColumn('en', en)}
      </div>
    `;
  }

  function capa3LangColumn(lang, row) {
    const upper = lang.toUpperCase();
    return `
      <div class="lang-col" data-lang="${lang}">
        <h4>
          <span>${upper}</span>
          <label style="font-size:.7rem;color:var(--v2-text-muted);font-weight:400">
            <input type="checkbox" data-lang-include="${lang}" ${rowHasContent(row) ? 'checked' : ''}> incluir
          </label>
        </h4>
        <div class="field-group">
          <label class="field-label">Título breve (plain_title)</label>
          <input type="text" data-lang-field="${lang}.plain_title" value="${esc(row.plain_title || '')}">
        </div>
        <div class="field-group">
          <label class="field-label">Descripción (plain_description)</label>
          <textarea data-lang-field="${lang}.plain_description" rows="3">${esc(row.plain_description || '')}</textarea>
        </div>
        <div class="field-group">
          <label class="field-label">Qué significa (what_it_means)</label>
          <textarea data-lang-field="${lang}.what_it_means" rows="3">${esc(row.what_it_means || '')}</textarea>
        </div>
        <div class="field-group">
          <label class="field-label">Acciones posibles</label>
          <div class="actions-editor" data-actions="${lang}">
            ${(row.possible_actions || []).map((a,i) => actionRow(lang, i, a)).join('')}
            <button type="button" class="btn-add-action" data-add-action="${lang}">+ Acción</button>
          </div>
        </div>
        <div class="field-group">
          <label class="field-label">Revisión sugerida (suggested_review)</label>
          <textarea data-lang-field="${lang}.suggested_review" rows="2">${esc(row.suggested_review || '')}</textarea>
        </div>
      </div>
    `;
  }
  function rowHasContent(row) {
    if (!row) return false;
    return !!(row.plain_title || row.plain_description || row.what_it_means || (row.possible_actions||[]).length || row.suggested_review);
  }
  function actionRow(lang, i, a) {
    a = a || {};
    return `
      <div class="action-row" data-action-row="${lang}-${i}">
        <select data-action-audience="${lang}-${i}">
          ${['hosting','registrar','registry','owner','general'].map(o => `<option value="${o}" ${o===a.audience?'selected':''}>${o}</option>`).join('')}
        </select>
        <textarea data-action-text="${lang}-${i}" rows="2">${esc(a.text || '')}</textarea>
        <button type="button" class="btn-remove-action" data-remove-action="${lang}-${i}" aria-label="Eliminar">×</button>
      </div>
    `;
  }
  function bindActionsEditor(lang) {
    const root = document.querySelector(`.actions-editor[data-actions="${lang}"]`);
    if (!root) return;
    root.querySelector(`[data-add-action="${lang}"]`)?.addEventListener('click', () => {
      const i = root.querySelectorAll('.action-row').length;
      const div = document.createElement('div');
      div.innerHTML = actionRow(lang, i, { audience: 'hosting', text: '' });
      root.insertBefore(div.firstElementChild, root.querySelector(`[data-add-action="${lang}"]`));
      bindRemoveActions(root);
    });
    bindRemoveActions(root);
  }
  function bindRemoveActions(root) {
    root.querySelectorAll('[data-remove-action]').forEach(btn => {
      btn.onclick = () => btn.closest('.action-row')?.remove();
    });
  }

  function submitCapa3Form() {
    const codeEl = document.getElementById('f-code');
    const code = (codeEl?.value || '').trim();
    if (!code) { showToast('El campo "code" es obligatorio.', 'error'); return; }
    const audience = document.getElementById('f-aud')?.value || 'both';

    if (_newRowMode && _data.some(r => r.code === code)) {
      showToast(`Ya existe una explicación con code=${code}.`, 'error');
      return;
    }

    ['es','en'].forEach(lang => {
      const include = document.querySelector(`[data-lang-include="${lang}"]`)?.checked;
      // Find or create row for this lang
      let row = _data.find(r => r.code === code && r.language === lang);
      if (!include) {
        if (row) _data = _data.filter(r => !(r.code === code && r.language === lang));
        return;
      }
      if (!row) { row = blankCapa3(code, lang); _data.push(row); }
      row.audience_level = audience;
      row.plain_title       = document.querySelector(`[data-lang-field="${lang}.plain_title"]`)?.value || '';
      row.plain_description = document.querySelector(`[data-lang-field="${lang}.plain_description"]`)?.value || '';
      row.what_it_means     = document.querySelector(`[data-lang-field="${lang}.what_it_means"]`)?.value || '';
      row.suggested_review  = document.querySelector(`[data-lang-field="${lang}.suggested_review"]`)?.value || '';
      const actionRows = document.querySelectorAll(`.actions-editor[data-actions="${lang}"] .action-row`);
      const acts = [];
      actionRows.forEach((ar, i) => {
        const aud  = ar.querySelector(`[data-action-audience]`)?.value || 'general';
        const text = ar.querySelector(`[data-action-text]`)?.value || '';
        if (text.trim()) acts.push({ audience: aud, text: text.trim() });
      });
      row.possible_actions = acts;
    });

    document.getElementById('row-modal').close();
    renderTabularTable();
    updateStatus();
  }

  // ═══════════════════════════════════════════════════════════
  // DOCUMENT (ui-texts, report-texts) — tree editor
  // ═══════════════════════════════════════════════════════════
  function renderDocument() {
    renderDocToolbar();
    renderTree();
  }

  function renderDocToolbar() {
    const langs = (_data && typeof _data === 'object') ? Object.keys(_data) : [];
    const root = document.getElementById('admin-toolbar');
    root.innerHTML = `
      <input type="search" id="d-search" placeholder="Buscar por clave o valor…" value="${esc(_filter.q)}">
      <div class="right">
        <button class="btn" id="d-raw">Modo JSON crudo…</button>
        <button class="btn" id="d-expand">Expandir todo</button>
        <button class="btn" id="d-collapse">Colapsar</button>
      </div>
    `;
    document.getElementById('d-search')?.addEventListener('input', e => {
      _filter.q = e.target.value.toLowerCase();
      renderTree();
    });
    document.getElementById('d-raw')?.addEventListener('click', openRawJSONModal);
    document.getElementById('d-expand')?.addEventListener('click',   () => toggleAllDetails(true));
    document.getElementById('d-collapse')?.addEventListener('click', () => toggleAllDetails(false));
  }

  function toggleAllDetails(open) {
    document.querySelectorAll('#admin-editor details').forEach(d => d.open = open);
  }

  function renderTree() {
    const root = document.getElementById('admin-editor');
    if (!_data || typeof _data !== 'object') {
      root.innerHTML = `<p class="empty-state">El archivo no es un objeto JSON.</p>`;
      return;
    }
    root.innerHTML = `<div class="admin-tree">${renderNode('', _data, [])}</div>`;
    bindTreeInputs();
  }

  function renderNode(name, value, path) {
    const q = _filter.q;
    if (Array.isArray(value)) {
      // Heuristic: array of {term, definition} (glossary) or generic
      const matches = q ? value.some(v => JSON.stringify(v).toLowerCase().includes(q)) : true;
      if (q && !matches) return '';
      const items = value.map((v, i) => {
        if (v && typeof v === 'object') {
          return `
            <details ${q ? 'open' : ''}>
              <summary><span class="key-name">[${i}]</span> <span class="key-meta">${esc(Object.keys(v).join(', '))}</span></summary>
              ${Object.keys(v).map(k => renderNode(k, v[k], path.concat([i, k]))).join('')}
            </details>`;
        }
        return renderLeaf(`[${i}]`, v, path.concat([i]));
      }).join('');
      return `
        <details ${path.length === 0 || q ? 'open' : ''}>
          <summary><span class="key-name">${esc(name || '')}</span> <span class="key-meta">array · ${value.length}</span></summary>
          ${items}
        </details>`;
    }
    if (value && typeof value === 'object') {
      const keys = Object.keys(value);
      const matches = q ? keys.some(k => k.toLowerCase().includes(q) || JSON.stringify(value[k]).toLowerCase().includes(q)) : true;
      if (q && !matches) return '';
      return `
        <details ${path.length === 0 || q ? 'open' : ''}>
          <summary><span class="key-name">${esc(name)}</span> <span class="key-meta">object · ${keys.length}</span></summary>
          ${keys.map(k => renderNode(k, value[k], path.concat([k]))).join('')}
        </details>`;
    }
    return renderLeaf(name, value, path);
  }

  function renderLeaf(name, value, path) {
    const v = value == null ? '' : String(value);
    if (_filter.q) {
      const hay = (name + ' ' + v).toLowerCase();
      if (!hay.includes(_filter.q)) return '';
    }
    const id = 'lv-' + path.join('-').replace(/[^a-z0-9-]/gi, '_');
    const long = v.length > 60 || v.includes('\n');
    const ctrl = long
      ? `<textarea id="${id}" data-path="${esc(JSON.stringify(path))}" rows="3">${esc(v)}</textarea>`
      : `<input id="${id}" data-path="${esc(JSON.stringify(path))}" type="text" value="${esc(v)}">`;
    return `
      <div class="leaf">
        <span class="leaf-key">${esc(name)}</span>
        ${ctrl}
        <span class="leaf-actions">${typeof value}</span>
      </div>
    `;
  }

  function bindTreeInputs() {
    document.querySelectorAll('[data-path]').forEach(el => {
      el.addEventListener('input', () => {
        const path = JSON.parse(el.getAttribute('data-path'));
        let cur = _data;
        for (let i = 0; i < path.length - 1; i++) cur = cur[path[i]];
        const leafKey = path[path.length - 1];
        const newVal = el.value;
        cur[leafKey] = newVal;
        el.closest('.leaf')?.classList.add('dirty');
        updateStatus();
      });
    });
  }

  // Raw JSON modal
  function openRawJSONModal() {
    document.getElementById('raw-textarea').value = JSON.stringify(_data, null, 2);
    document.getElementById('raw-error').hidden = true;
    document.getElementById('raw-modal').showModal();
  }
  function applyRawJSON() {
    const txt = document.getElementById('raw-textarea').value;
    let parsed;
    try {
      parsed = JSON.parse(txt);
    } catch (e) {
      const err = document.getElementById('raw-error');
      err.hidden = false;
      err.textContent = 'JSON inválido: ' + e.message;
      return;
    }
    _data = parsed;
    document.getElementById('raw-modal').close();
    renderTree();
    updateStatus();
  }

  // ─── Helpers ───────────────────────────────────────────────
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
  function truncate(s, n) {
    s = String(s == null ? '' : s);
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }
  function formatDate(iso) {
    if (!iso) return '';
    try {
      const d = new Date(iso);
      if (isNaN(d.getTime())) return iso;
      return d.toLocaleString('es-EC', { year: '2-digit', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
    } catch { return iso; }
  }
  function showToast(msg, kind) {
    const root = document.getElementById('toast-container');
    if (!root) return;
    const div = document.createElement('div');
    div.className = 'toast' + (kind === 'error' ? ' toast-error' : kind === 'success' ? ' toast-success' : '');
    div.textContent = msg;
    root.appendChild(div);
    setTimeout(() => div.remove(), 4000);
  }

  return { init };
})();

document.addEventListener('DOMContentLoaded', () => AdminData.init());
