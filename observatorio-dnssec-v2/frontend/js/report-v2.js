/* ═══════════════════════════════════════════════════════════
   report-v2.js — Renderiza /report-v2

   Reglas no negociables:
   - DNSViz es la fuente soberana. No reinterpretamos estados.
   - No mostramos health score, risk score ni "nivel de riesgo global".
   - Los estados visuales SOLO vienen de result.dnsviz_visual y
     result.structured_view.
   - El idioma se obtiene de /api/ui-texts.json y /api/report-texts.json.
   ═══════════════════════════════════════════════════════════ */

const ReportV2 = (() => {
  const SS_KEY    = 'obs_report';
  const LANG_KEY  = 'obs_lang';
  let _lang       = localStorage.getItem(LANG_KEY) || 'es';
  let _ui         = {};      // ui-texts (current lang)
  let _uiAll      = null;    // full ui-texts.json
  let _rt         = {};      // report-texts (current lang)
  let _rtAll      = null;    // full report-texts.json
  let _result     = null;    // result.json
  let _filter     = 'all';

  // ─── Boot ──────────────────────────────────────────────────
  async function init() {
    bindHeader();
    bindMobileTabs();
    bindNoticesFilter();
    bindActions();

    try {
      await loadTexts();
      applyDOMTexts();

      const id = resolveAnalysisId();
      if (!id) {
        showError(t('errors.unauthorized') || 'No hay análisis para mostrar. Vuelve al inicio y analiza un dominio.');
        return;
      }
      _result = await loadResult(id);
      renderAll();
    } catch (e) {
      console.error('[report-v2] init error', e);
      showError((e && e.message) || 'No se pudo cargar el reporte.');
    }
  }

  // ─── Texts (ui-texts + report-texts) ───────────────────────
  async function loadTexts() {
    if (!_uiAll) {
      const r = await fetch('/api/ui-texts.json', { cache: 'no-store' });
      _uiAll = r.ok ? await r.json() : {};
    }
    if (!_rtAll) {
      const r = await fetch('/api/report-texts.json', { cache: 'no-store' });
      _rtAll = r.ok ? await r.json() : {};
    }
    _ui = _uiAll[_lang] || _uiAll.es || {};
    _rt = _rtAll[_lang] || _rtAll.es || {};
    document.documentElement.lang = _lang;
    syncToggleLabels();
  }

  function t(key, fallback = '') {
    const parts = String(key || '').split('.');
    let cur = _ui;
    for (const p of parts) {
      if (cur && typeof cur === 'object' && p in cur) cur = cur[p];
      else return fallback;
    }
    return (cur == null) ? fallback : String(cur);
  }
  function rt(key, fallback = '') {
    const parts = String(key || '').split('.');
    let cur = _rt;
    for (const p of parts) {
      if (cur && typeof cur === 'object' && p in cur) cur = cur[p];
      else return fallback;
    }
    return (cur == null) ? fallback : (typeof cur === 'string' ? cur : cur);
  }

  function applyDOMTexts() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const val = t(key);
      if (val) {
        if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') el.placeholder = val;
        else el.textContent = val;
      }
    });
    setText('summary-intro',  rt('sections.summary_intro'));
    setText('zones-intro',    rt('sections.zones_intro'));
    setText('notices-intro',  rt('sections.notices_intro'));
    setText('rfc-intro',      rt('sections.rfc_map_intro'));
    setText('glossary-intro', rt('sections.glossary_intro'));
    setText('trace-intro',    rt('sections.traceability_intro'));
  }

  function syncToggleLabels() {
    document.querySelectorAll('[data-lang-toggle]').forEach(el => {
      el.textContent = _lang === 'es' ? 'English' : 'Español';
    });
  }

  async function toggleLang() {
    _lang = _lang === 'es' ? 'en' : 'es';
    localStorage.setItem(LANG_KEY, _lang);
    await loadTexts();
    applyDOMTexts();
    if (_result) renderAll();
  }

  // ─── Resolve id (URL ?id=, then sessionStorage) ────────────
  function resolveAnalysisId() {
    const qs = new URLSearchParams(location.search);
    const fromUrl = qs.get('id');
    if (fromUrl) return fromUrl;
    try {
      const cached = JSON.parse(sessionStorage.getItem(SS_KEY) || 'null');
      if (cached && cached.id) {
        const url = new URL(location.href);
        url.searchParams.set('id', cached.id);
        history.replaceState({}, '', url.toString());
        return cached.id;
      }
    } catch (e) { /* ignore */ }
    return null;
  }

  // ─── Result fetcher ────────────────────────────────────────
  async function loadResult(id) {
    const r = await fetch(`/analyze/${encodeURIComponent(id)}/result.json`, { cache: 'no-store' });
    if (!r.ok) throw new Error(`No se pudo cargar el reporte (${r.status})`);
    return r.json();
  }

  // ─── Header / mobile menu / lang ───────────────────────────
  function bindHeader() {
    document.getElementById('menu-toggle')?.addEventListener('click', () => {
      document.getElementById('mobile-nav')?.classList.toggle('open');
    });
    document.querySelectorAll('[data-lang-toggle]').forEach(el => {
      el.addEventListener('click', e => { e.preventDefault(); toggleLang(); });
    });
  }

  function bindMobileTabs() {
    document.querySelectorAll('.mobile-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        const target = tab.getAttribute('data-tab');
        document.querySelectorAll('.mobile-tab').forEach(t => {
          const active = t === tab;
          t.classList.toggle('active', active);
          t.setAttribute('aria-selected', active ? 'true' : 'false');
        });
        document.querySelectorAll('main.report-layout > .panel').forEach(p => {
          p.classList.toggle('active', p.getAttribute('data-panel') === target);
        });
      });
    });
  }

  function bindNoticesFilter() {
    document.querySelectorAll('.filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        _filter = btn.getAttribute('data-filter') || 'all';
        renderNotices();
      });
    });
  }

  function bindActions() {
    document.getElementById('btn-export-json')?.addEventListener('click', exportJSON);
    document.getElementById('btn-export-csv')?.addEventListener('click', exportCSV);
    document.getElementById('btn-export-pdf')?.addEventListener('click', exportPDF);
  }

  // ─── Render ────────────────────────────────────────────────
  function renderAll() {
    if (!_result) return;
    document.getElementById('report-loader')?.classList.remove('visible');

    renderStatus();
    renderEvidenceLinks();
    renderSummary();
    renderZones();
    renderRFCMap();
    renderGlossary();
    renderTraceability();
    renderNotices();   // last because it depends on _filter
  }

  function renderStatus() {
    const el = document.getElementById('report-status');
    if (!el) return;
    el.hidden = false;
    setText('report-domain', _result.domain || '');
    setText('report-time',   formatDate(_result.generated_at));
    setText('report-id',     _result.id ? `#${_result.id.slice(0, 8)}` : '');
  }

  function renderEvidenceLinks() {
    const id = _result.id;
    const base = `/analyze/${encodeURIComponent(id)}`;
    const pngUrl  = `${base}/graph.png`;
    const htmlUrl = `${base}/graph.html`;

    const img      = document.getElementById('dnsviz-graph-img');
    const link     = document.getElementById('dnsviz-graph-link');
    const fallback = document.getElementById('graph-fallback');

    // result.dnsviz_original.graph_png_available indica si el PNG se generó.
    const pngAvailable = !!(_result.dnsviz_original && _result.dnsviz_original.graph_png_available);

    if (img && link) {
      if (pngAvailable) {
        img.src = pngUrl;
        img.alt = `Grafo DNSViz para ${_result.domain || ''}`;
        link.href = pngUrl;
        link.style.display = '';
        if (fallback) fallback.hidden = true;
        // Si la imagen no carga (404, etc.), caer al fallback automáticamente.
        img.onerror = () => {
          link.style.display = 'none';
          if (fallback) fallback.hidden = false;
        };
      } else {
        link.style.display = 'none';
        if (fallback) fallback.hidden = false;
      }
    }

    setHref('open-graph-tab', htmlUrl);
    setHref('open-graph-png', pngUrl);
    setHref('link-grok',      `${base}/grok.json`);
    setHref('link-probe',     `${base}/probe.json`);
    setHref('link-print',     `${base}/print.txt`);
  }

  function renderSummary() {
    const v = _result.dnsviz_visual || {};
    const notices = v.notices || {};
    const cards = [
      { lbl: t('report.rrset_status'),          num: countItems(v.rrset_status) },
      { lbl: t('report.dnskey_ds_nsec_status'), num: countItems(v.dnskey_ds_nsec_status) },
      { lbl: t('report.delegation_status'),     num: countItems(v.delegation_status) },
      { lbl: t('report.errors'),                num: notices.errors_count   || 0, kind: 'errors' },
      { lbl: t('report.warnings'),              num: notices.warnings_count || 0, kind: 'warns' },
    ];
    const root = document.getElementById('summary-grid');
    if (!root) return;
    root.innerHTML = cards.map(c => `
      <div class="summary-card ${c.kind || ''}">
        <span class="num">${esc(c.num)}</span>
        <span class="lbl">${esc(c.lbl)}</span>
      </div>
    `).join('');
  }

  function countItems(groups) {
    if (!Array.isArray(groups)) return 0;
    return groups.reduce((acc, g) => acc + (Number(g.count) || (Array.isArray(g.items) ? g.items.length : 0)), 0);
  }

  function renderZones() {
    const root = document.getElementById('zones-list');
    if (!root) return;
    const zones = (_result.structured_view && _result.structured_view.zones) || [];
    if (!zones.length) {
      root.innerHTML = `<div class="empty-state">${esc(t('report.no_errors') || '—')}</div>`;
      return;
    }
    root.innerHTML = zones.map(zone => {
      const cls = zone.classification || {};
      const tag = cls.is_root ? 'root'
                : cls.is_tld ? 'TLD'
                : cls.is_target ? 'target'
                : cls.is_intermediate ? 'intermediate' : '';
      const visualPills = renderZoneVisualPills(zone.visual_status);
      const errCount = (zone.errors || []).length;
      const warCount = (zone.warnings || []).length;
      const rfcs = (zone.rfcs || []).map(r => `<span class="notice-rfc">RFC ${esc(r)}</span>`).join(' ');
      const detailsErr = (zone.errors || []).map(n => renderNoticeInline(n, 'error')).join('');
      const detailsWar = (zone.warnings || []).map(n => renderNoticeInline(n, 'warning')).join('');
      const showDetails = (errCount + warCount) > 0;
      return `
        <article class="zone-card">
          <div class="zone-head">
            <span class="zone-name">${esc(zone.name || '.')}</span>
            ${tag ? `<span class="zone-tag">${esc(tag)}</span>` : ''}
            <span class="zone-counts">
              <span title="${esc(t('report.errors'))}">⚠ ${errCount}</span>
              <span title="${esc(t('report.warnings'))}">▲ ${warCount}</span>
            </span>
          </div>
          ${visualPills ? `<div class="zone-visual">${visualPills}</div>` : ''}
          ${rfcs ? `<div class="zone-rfcs">RFC: ${rfcs}</div>` : ''}
          ${showDetails ? `
            <details>
              <summary>${esc(t('report.section_notices'))} (${errCount + warCount})</summary>
              <div style="margin-top:.4rem">${detailsErr}${detailsWar}</div>
            </details>
          ` : ''}
        </article>
      `;
    }).join('');
  }

  function renderZoneVisualPills(visual) {
    if (!visual) return '';
    const sections = ['rrset_status', 'dnskey_ds_nsec_status', 'delegation_status'];
    const parts = [];
    sections.forEach(sec => {
      const groups = visual[sec] || [];
      groups.forEach(g => {
        if (g.count) parts.push(`<span class="status-pill ${esc(g.status)}">${esc(g.status)} · ${esc(sec.replace('_status',''))} (${g.count})</span>`);
      });
    });
    return parts.join(' ');
  }

  function renderNoticeInline(n, kind) {
    const expl = pickExplanation(n);
    return `
      <div class="notice-card ${kind}" style="margin:.35rem 0">
        <div class="notice-head">
          <span class="notice-code">${esc(n.code || '')}</span>
          <span class="notice-zone">${esc(n.zone || '.')}</span>
          ${(n.rfcs || []).slice(0, 2).map(r => `<span class="notice-rfc">RFC ${esc(r)}</span>`).join(' ')}
        </div>
        <div class="notice-body">
          <div class="original-msg">${esc(n.original_message || '')}</div>
          ${expl ? `<div class="explanation">${esc(expl)}</div>` : ''}
        </div>
      </div>
    `;
  }

  function renderNotices() {
    const root = document.getElementById('notices-list');
    if (!root) return;
    const sv = _result.structured_view || {};
    const all = (sv.sections && sv.sections.notices) || { errors: [], warnings: [] };
    const errors = all.errors || [];
    const warnings = all.warnings || [];

    setText('cnt-all',      String(errors.length + warnings.length));
    setText('cnt-errors',   String(errors.length));
    setText('cnt-warnings', String(warnings.length));

    let list = [];
    if (_filter === 'errors')   list = errors.map(n => ({ n, kind: 'error' }));
    else if (_filter === 'warnings') list = warnings.map(n => ({ n, kind: 'warning' }));
    else list = [
      ...errors.map(n => ({ n, kind: 'error' })),
      ...warnings.map(n => ({ n, kind: 'warning' })),
    ];

    if (!list.length) {
      const msg = _filter === 'warnings'
        ? t('report.no_warnings')
        : t('report.no_errors');
      root.innerHTML = `<div class="empty-state">${esc(msg || '—')}</div>`;
      return;
    }

    root.innerHTML = list.map(({ n, kind }) => renderNoticeFull(n, kind)).join('');
  }

  function renderNoticeFull(n, kind) {
    const sem = n.semantica || {};
    const ctx = n.contexto_normativo || {};
    const expl = (n.explanations || {})[_lang] || (n.explanations || {}).es || (n.explanations || {}).en;
    const tr = n.traceability || {};

    const rfcs = (n.rfcs || []).map(r => `<span class="notice-rfc">RFC ${esc(r)}</span>`).join(' ');
    const meta = [];
    if (n.zone) meta.push([t('report.zone'), n.zone]);
    if (n.node && n.node.label) meta.push([t('report.node'), n.node.label]);
    if (n.node && n.node.status) meta.push([t('report.section'), n.node.status]);
    if (sem.dnsviz_section)     meta.push([t('report.section'), sem.dnsviz_section]);
    if (sem.dnsviz_level)       meta.push([t('report.level'),   sem.dnsviz_level]);
    if (sem.dnsviz_group)       meta.push([t('report.group'),   sem.dnsviz_group]);
    if (Array.isArray(sem.applies_to) && sem.applies_to.length)
      meta.push([t('report.applies_to'), sem.applies_to.join(', ')]);
    if ((n.servers || []).length)       meta.push([t('report.server'),       n.servers.join(', ')]);
    if ((n.query_options || []).length) meta.push([t('report.query_options'), n.query_options.join(', ')]);
    if (ctx.nist_reference)             meta.push(['NIST',                   ctx.nist_reference]);
    if (ctx.iso27001_reference)         meta.push(['ISO 27001',              ctx.iso27001_reference]);
    if (ctx.possible_operational_area)  meta.push([_lang === 'en' ? 'Operational area' : 'Área operativa', t('audience.' + ctx.possible_operational_area) || ctx.possible_operational_area]);
    if (ctx.operational_complexity)     meta.push([_lang === 'en' ? 'Complexity' : 'Complejidad', ctx.operational_complexity]);
    if (ctx.estimated_effort)           meta.push([_lang === 'en' ? 'Estimated effort' : 'Esfuerzo estimado', ctx.estimated_effort]);

    const actions = (expl && Array.isArray(expl.possible_actions))
      ? expl.possible_actions.map(a => `
          <li>
            ${a.audience ? `<span class="audience-tag">${esc(t('audience.' + a.audience) || a.audience)}</span>` : ''}
            ${esc(a.text || '')}
          </li>`).join('')
      : '';

    const traceMeta = [];
    if (tr.source)    traceMeta.push(`${esc(t('report.trace_source') || 'Fuente')}: ${esc(tr.source)}`);
    if (tr.zone)      traceMeta.push(`${esc(t('report.zone'))}: ${esc(tr.zone)}`);
    if (tr.node_key)  traceMeta.push(`${esc(t('report.node'))}: ${esc(tr.node_key)}`);
    if (tr.layers_used && tr.layers_used.length)
      traceMeta.push(`${esc(t('report.trace_layer') || 'Capa')}: ${esc(tr.layers_used.join(' / '))}`);

    return `
      <article class="notice-card ${kind}">
        <div class="notice-head">
          <span class="notice-code">${esc(n.code || '')}</span>
          <span class="status-pill ${esc((sem.dnsviz_level || (kind === 'error' ? 'ERROR' : 'WARNING')).toUpperCase())}">${esc(sem.dnsviz_level || (kind === 'error' ? 'Error' : 'Warning'))}</span>
          <span class="notice-zone">${esc(n.zone || '.')}</span>
          ${rfcs}
        </div>
        <div class="notice-body">
          ${expl && expl.plain_title ? `<div style="font-weight:600;margin-bottom:.25rem">${esc(expl.plain_title)}</div>` : ''}
          <div class="original-msg">${esc(n.original_message || '')}</div>
          ${expl && expl.plain_description ? `<div class="explanation">${esc(expl.plain_description)}</div>` : ''}
          ${expl && expl.what_it_means ? `<div class="explanation"><em>${esc(expl.what_it_means)}</em></div>` : ''}
          <dl class="meta-grid">
            ${meta.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}
          </dl>
          ${actions ? `
            <details>
              <summary>${esc(t('report.possible_action') || 'Acciones posibles')}</summary>
              <ul class="actions-list">${actions}</ul>
            </details>
          ` : ''}
          ${expl && expl.suggested_review ? `
            <details>
              <summary>${esc(_lang === 'en' ? 'Suggested review' : 'Revisión sugerida')}</summary>
              <div style="font-size:.82rem;margin-top:.3rem">${esc(expl.suggested_review)}</div>
            </details>
          ` : ''}
          <div class="trace-meta" style="margin-top:.4rem;font-size:.7rem;color:var(--v2-text-muted)">
            ${traceMeta.join(' · ')}
          </div>
        </div>
      </article>
    `;
  }

  function renderRFCMap() {
    const tbody = document.getElementById('rfc-tbody');
    if (!tbody) return;
    const sv = _result.structured_view || {};
    const byCode = sv.notices_by_code || [];

    if (!byCode.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-state">${esc(t('report.no_errors'))}</td></tr>`;
      return;
    }

    const rows = byCode.map(c => {
      const occ = (c.occurrences || [])[0] || {};
      const expl = pickExplanationByCode(c.code) || {};
      const rfcs = (c.rfcs || []).map(r => `RFC ${esc(r)}`).join(', ');
      return `
        <tr>
          <td class="col-code">${esc(c.code)}</td>
          <td class="col-rfc">${rfcs || '—'}</td>
          <td><span class="status-pill ${esc(String(c.level).toUpperCase())}">${esc(c.level)}</span></td>
          <td class="col-msg">${esc(occ.message || '')}</td>
          <td>${esc(expl.plain_title || expl.plain_description || '')}</td>
        </tr>
      `;
    });
    tbody.innerHTML = rows.join('');
  }

  function renderGlossary() {
    const root = document.getElementById('glossary-list');
    if (!root) return;
    const items = (_rt && Array.isArray(_rt.glossary)) ? _rt.glossary : [];
    if (!items.length) {
      root.innerHTML = '';
      return;
    }
    root.innerHTML = items.map(g => `
      <div class="glossary-item">
        <dt>${esc(g.term || '')}</dt>
        <dd>${esc(g.definition || '')}</dd>
      </div>
    `).join('');
  }

  function renderTraceability() {
    const root = document.getElementById('trace-list');
    if (!root) return;
    const sv = _result.structured_view || {};
    const all = [
      ...((sv.sections && sv.sections.notices && sv.sections.notices.errors)   || []),
      ...((sv.sections && sv.sections.notices && sv.sections.notices.warnings) || []),
    ];
    if (!all.length) {
      root.innerHTML = `<div class="empty-state">${esc(t('report.no_errors'))}</div>`;
      return;
    }
    root.innerHTML = all.map(n => {
      const tr = n.traceability || {};
      const rfcs = (n.rfcs || []).map(r => `RFC ${esc(r)}`).join(', ');
      return `
        <div class="trace-item">
          <span class="trace-code">${esc(n.code)}</span>
          <span> · ${esc(t('report.zone'))}: ${esc(tr.zone || '.')}</span>
          <span> · ${esc(t('report.node'))}: ${esc(tr.node_key || '—')}</span>
          <div class="trace-meta">
            <span>${esc(t('report.trace_source') || 'Fuente')}: ${esc(tr.source || 'DNSViz')}</span>
            <span>${esc(t('report.trace_layer') || 'Capa')}: ${esc((tr.layers_used || []).join(' / '))}</span>
            ${rfcs ? `<span>${rfcs}</span>` : ''}
          </div>
        </div>
      `;
    }).join('');
  }

  // ─── Helpers ───────────────────────────────────────────────
  function pickExplanation(notice) {
    const e = notice && notice.explanations;
    if (!e) return '';
    const row = e[_lang] || e.es || e.en;
    if (!row) return '';
    return row.plain_description || row.plain_title || '';
  }
  function pickExplanationByCode(code) {
    const layers = _result && _result.layers;
    if (!layers || !layers.capa3) return null;
    const row = layers.capa3[code];
    if (!row) return null;
    return row[_lang] || row.es || row.en || null;
  }

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
  function setText(id, txt) {
    const el = document.getElementById(id);
    if (el) el.textContent = txt == null ? '' : String(txt);
  }
  function setHref(id, href) {
    const el = document.getElementById(id);
    if (el) el.setAttribute('href', href);
  }
  function formatDate(iso) {
    if (!iso) return '';
    try {
      const d = new Date(iso);
      if (isNaN(d.getTime())) return iso;
      return d.toLocaleString(_lang === 'en' ? 'en-US' : 'es-EC', {
        year: 'numeric', month: 'short', day: '2-digit',
        hour: '2-digit', minute: '2-digit', timeZoneName: 'short'
      });
    } catch { return iso; }
  }
  function showError(msg) {
    document.getElementById('report-loader')?.classList.remove('visible');
    const el = document.getElementById('report-error');
    if (!el) return;
    el.textContent = msg;
    el.classList.remove('hidden');
  }

  // ─── Exports ───────────────────────────────────────────────
  function exportJSON() {
    if (!_result) return;
    const blob = new Blob([JSON.stringify(_result, null, 2)], { type: 'application/json' });
    triggerDownload(blob, `${safeFilename(_result.domain)}-${shortId()}.json`);
  }
  function exportCSV() {
    if (!_result) return;
    const sv = _result.structured_view || {};
    const all = [
      ...((sv.sections && sv.sections.notices && sv.sections.notices.errors)   || []).map(n => ({ ...n, _kind: 'Error' })),
      ...((sv.sections && sv.sections.notices && sv.sections.notices.warnings) || []).map(n => ({ ...n, _kind: 'Warning' })),
    ];
    const rows = [['zone', 'type', 'code', 'rfcs', 'original_message', 'explanation_es', 'explanation_en']];
    all.forEach(n => {
      const expls = n.explanations || {};
      const es = (expls.es || {});
      const en = (expls.en || {});
      rows.push([
        n.zone || '',
        n._kind,
        n.code || '',
        (n.rfcs || []).join(' '),
        n.original_message || '',
        es.plain_description || es.plain_title || '',
        en.plain_description || en.plain_title || '',
      ]);
    });
    const csv = rows.map(r => r.map(csvCell).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    triggerDownload(blob, `${safeFilename(_result.domain)}-${shortId()}.csv`);
  }
  async function exportPDF() {
    if (!_result || !_result.id) {
      showError('No se pudo iniciar el PDF: falta id de análisis.');
      return;
    }
    const url = `/analyze/${encodeURIComponent(_result.id)}/report.pdf?lang=${encodeURIComponent(_lang)}`;
    try {
      const r = await fetch(url, { method: 'GET' });
      if (!r.ok) {
        let msg = `PDF no disponible (${r.status})`;
        try { const data = await r.json(); if (data && data.message) msg = data.message; } catch {}
        throw new Error(msg);
      }
      const blob = await r.blob();
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = `${safeFilename(_result.domain)}-${shortId()}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(blobUrl), 60_000);
    } catch (e) {
      alert((e && e.message) || 'No se pudo generar el PDF.');
    }
  }

  function csvCell(v) {
    const s = String(v == null ? '' : v);
    if (/[",\n;]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }
  function triggerDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
  }
  function safeFilename(s) {
    return String(s || 'report').replace(/[^a-z0-9.-]/gi, '_').slice(0, 64);
  }
  function shortId() {
    return (_result && _result.id) ? _result.id.slice(0, 8) : 'noid';
  }

  // Public API (mostly for debugging from console)
  return { init, toggleLang };
})();

document.addEventListener('DOMContentLoaded', () => ReportV2.init());
