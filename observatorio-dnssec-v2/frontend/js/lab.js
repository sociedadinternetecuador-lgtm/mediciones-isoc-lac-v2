const Lab = (() => {
  let lastUser = null;
  let lastStatus = null;
  let lastNormalization = null;
  let activeSelection = null;
  let activeReviewDomains = [];

  async function init() {
    await I18n.init();
    document.getElementById('menu-toggle')
      ?.addEventListener('click', () =>
        document.getElementById('mobile-nav')?.classList.toggle('open'));
    document.addEventListener('langchange', () => {
      if (lastStatus) render(lastUser, lastStatus);
      if (lastNormalization) renderNormalization(lastNormalization);
    });

    if (!API.isLoggedIn()) {
      location.href = '/admin/login';
      return;
    }

    try {
      const me = await API.me();
      const status = await fetchStatus();
      lastUser = me;
      lastStatus = status;
      render(me, status);
    } catch {
      API.clearToken();
      location.href = '/admin/login';
    }
  }

  async function fetchStatus() {
    const res = await fetch('/lab/status', {
      headers: { Authorization: `Bearer ${API.getToken()}` },
      cache: 'no-store',
    });
    if (!res.ok) throw new Error('lab_status_failed');
    return res.json();
  }

  async function normalizeDomains() {
    const input = document.getElementById('lab-bulk-input');
    const text = input?.value || '';
    const summary = document.getElementById('lab-bulk-summary');
    const table = document.getElementById('lab-bulk-table');
    if (summary) {
      summary.classList.remove('hidden');
      summary.textContent = t('lab.preparing', 'Preparando...');
    }
    if (table) {
      table.classList.add('hidden');
      table.innerHTML = '';
    }
    document.getElementById('lab-bulk-groups')?.classList.add('hidden');
    document.getElementById('lab-selection')?.classList.add('hidden');
    document.getElementById('lab-review')?.classList.add('hidden');
    activeSelection = null;
    activeReviewDomains = [];

    try {
      const res = await fetch('/lab/domains/normalize', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${API.getToken()}`,
        },
        body: JSON.stringify({ text }),
      });
      const data = await res.json();
      if (!res.ok) throw data;
      renderNormalization(data);
    } catch (err) {
      if (summary) summary.textContent = err?.message || t('lab.prepare_failed', 'No se pudo preparar el lote.');
    }
  }

  function clearDomains() {
    const input = document.getElementById('lab-bulk-input');
    const file = document.getElementById('lab-bulk-file');
    const fileStatus = document.getElementById('lab-file-status');
    if (input) input.value = '';
    if (file) file.value = '';
    if (fileStatus) fileStatus.textContent = t('lab.import_hint', 'Tambien puedes pegar manualmente.');
    lastNormalization = null;
    activeSelection = null;
    document.getElementById('lab-bulk-summary')?.classList.add('hidden');
    document.getElementById('lab-bulk-table')?.classList.add('hidden');
    document.getElementById('lab-bulk-groups')?.classList.add('hidden');
    document.getElementById('lab-selection')?.classList.add('hidden');
    document.getElementById('lab-review')?.classList.add('hidden');
    activeReviewDomains = [];
  }

  function importDomainFile(event) {
    const file = event?.target?.files?.[0];
    if (!file) return;
    const status = document.getElementById('lab-file-status');
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['csv', 'txt'].includes(ext)) {
      if (status) status.textContent = t('lab.import_invalid_type', 'Usa un archivo .csv o .txt.');
      event.target.value = '';
      return;
    }
    if (file.size > 1024 * 1024) {
      if (status) status.textContent = t('lab.import_too_large', 'El archivo debe pesar hasta 1 MB.');
      event.target.value = '';
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const content = String(reader.result || '');
      const domains = ext === 'csv' ? parseCsvDomains(content) : parseTextDomains(content);
      const input = document.getElementById('lab-bulk-input');
      if (input) input.value = domains.join('\n');
      if (status) {
        const overLimit = domains.length > 100 ? ` ${t('lab.import_over_100', 'La preparacion marcara lotes de 100 para el analisis.')}` : '';
        status.textContent = `${file.name}: ${num(domains.length)} ${t('lab.import_loaded', 'entradas cargadas')}.${overLimit}`;
      }
      lastNormalization = null;
      activeSelection = null;
      document.getElementById('lab-bulk-summary')?.classList.add('hidden');
      document.getElementById('lab-bulk-table')?.classList.add('hidden');
      document.getElementById('lab-bulk-groups')?.classList.add('hidden');
      document.getElementById('lab-selection')?.classList.add('hidden');
      document.getElementById('lab-review')?.classList.add('hidden');
      activeReviewDomains = [];
    };
    reader.onerror = () => {
      if (status) status.textContent = t('lab.import_failed', 'No se pudo leer el archivo.');
    };
    reader.readAsText(file, 'utf-8');
  }

  function parseTextDomains(content) {
    return content
      .replace(/\r/g, '\n')
      .split(/[\n,;]+/)
      .map(value => value.trim())
      .filter(Boolean);
  }

  function parseCsvDomains(content) {
    const rows = content
      .replace(/\r/g, '\n')
      .split('\n')
      .map(parseCsvRow)
      .filter(row => row.some(cell => cell.trim()));
    if (!rows.length) return [];

    const headers = rows[0].map(cell => cell.trim().toLowerCase());
    const domainColumn = headers.findIndex(header =>
      ['domain', 'dominio', 'url', 'host', 'hostname', 'fqdn'].includes(header));
    const start = domainColumn >= 0 ? 1 : 0;
    const column = domainColumn >= 0 ? domainColumn : firstUsefulColumn(rows);
    return rows
      .slice(start)
      .map(row => (row[column] || '').trim())
      .filter(Boolean);
  }

  function firstUsefulColumn(rows) {
    const limit = Math.min(rows.length, 10);
    let bestColumn = 0;
    let bestScore = -1;
    for (let column = 0; column < Math.max(...rows.slice(0, limit).map(row => row.length)); column++) {
      let score = 0;
      for (let row = 0; row < limit; row++) {
        const value = (rows[row][column] || '').trim();
        if (value.includes('.') || value.includes('://')) score++;
      }
      if (score > bestScore) {
        bestScore = score;
        bestColumn = column;
      }
    }
    return bestColumn;
  }

  function parseCsvRow(line) {
    const cells = [];
    let cell = '';
    let quoted = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"' && line[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (ch === '"') {
        quoted = !quoted;
      } else if (ch === ',' && !quoted) {
        cells.push(cell);
        cell = '';
      } else {
        cell += ch;
      }
    }
    cells.push(cell);
    return cells;
  }

  function renderNormalization(data) {
    lastNormalization = data;
    const summary = document.getElementById('lab-bulk-summary');
    const groups = document.getElementById('lab-bulk-groups');
    const s = data.summary || {};
    if (summary) {
      summary.classList.remove('hidden');
      summary.innerHTML = `
        <span>${t('lab.received', 'Recibidos')}: <strong>${num(s.received)}</strong></span>
        <span>${t('lab.valid', 'Validos')}: <strong>${num(s.valid)}</strong></span>
        <span>${t('lab.selected_for_batch', 'Lote 1')}: <strong>${num(s.analysis_selected)}</strong>/${num(s.analysis_batch_limit)}</span>
        <span>${t('lab.remaining', 'Pendientes')}: <strong>${num(s.analysis_remaining)}</strong></span>
        <span>${t('lab.unique_analysis_domains', 'Dominios a analizar')}: <strong>${num(s.analysis_unique_domains)}</strong></span>
        <span>${t('lab.subdomains', 'Subdominios')}: <strong>${num(s.subdomains)}</strong></span>
        <span>${t('lab.subdomains_pending_review', 'Subdominios por revisar')}: <strong>${num(s.subdomains_pending_review)}</strong></span>
        <span>${t('lab.changed', 'Cambiados')}: <strong>${num(s.changed)}</strong></span>
        <span>${t('lab.duplicates', 'Duplicados')}: <strong>${num(s.duplicates)}</strong></span>
        <span>${t('lab.invalid', 'Invalidos')}: <strong>${num(s.invalid)}</strong></span>
      `;
    }
    renderGroups(groups, data);
    renderSelection();
  }

  function renderGroups(container, data) {
    if (!container) return;
    const summary = data.summary || {};
    const genericTlds = Object.entries(summary.by_generic_tld || {})
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const ccGroups = Object.entries(summary.by_country_code_group || {})
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const types = Object.entries(summary.by_tld_type || {})
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const recommendations = Object.entries(summary.by_analysis_recommendation || {})
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const batches = summary.batches || [];
    container.classList.remove('hidden');
    container.innerHTML = `
      <div class="lab-group-block">
        <strong>${t('lab.groups_generic', 'Genericos')}</strong>
        <div class="lab-chip-row">
          ${genericTlds.map(([group, count]) => `
            <button type="button" class="lab-chip" onclick="Lab.useReportGroup('${escAttr(group)}')">.${esc(group)} (${num(count)})</button>
          `).join('') || `<span class="lab-empty">${t('lab.no_groups', 'Sin grupos')}</span>`}
        </div>
      </div>
      <div class="lab-group-block">
        <strong>${t('lab.groups_country_code', 'Country code')}</strong>
        <div class="lab-chip-row">
          ${ccGroups.map(([group, count]) => `
            <button type="button" class="lab-chip" onclick="Lab.useReportGroup('${escAttr(group)}')">.${esc(group)} (${num(count)})</button>
          `).join('') || `<span class="lab-empty">${t('lab.no_groups', 'Sin grupos')}</span>`}
        </div>
      </div>
      <div class="lab-group-block">
        <strong>${t('lab.groups_by_type', 'Por tipo')}</strong>
        <div class="lab-chip-row">
          ${types.map(([type, count]) => `
            <button type="button" class="lab-chip" onclick="Lab.useType('${escAttr(type)}')">${esc(type)} (${num(count)})</button>
          `).join('') || `<span class="lab-empty">${t('lab.no_groups', 'Sin grupos')}</span>`}
        </div>
      </div>
      <div class="lab-group-block">
        <strong>${t('lab.suggested_batches', 'Lotes sugeridos')}</strong>
        <div class="lab-chip-row">
          ${batches.map(batch => `
            <button type="button" class="lab-chip" onclick="Lab.useBatch(${Number(batch.number)})">
              ${t('lab.batch', 'Lote')} ${num(batch.number)}: ${num(batch.start)}-${num(batch.end)} (${num(batch.count)})
            </button>
          `).join('') || `<span class="lab-empty">${t('lab.no_batches', 'Sin lotes')}</span>`}
        </div>
      </div>
      <div class="lab-group-block">
        <strong>${t('lab.groups_recommendations', 'Recomendaciones')}</strong>
        <div class="lab-chip-row">
          ${recommendations.map(([recommendation, count]) => `
            <button type="button" class="lab-chip" onclick="Lab.useRecommendation('${escAttr(recommendation)}')">${esc(recommendationText(recommendation))} (${num(count)})</button>
          `).join('') || `<span class="lab-empty">${t('lab.no_groups', 'Sin grupos')}</span>`}
        </div>
      </div>
    `;
  }

  function renderSelection() {
    if (!lastNormalization) return;
    const selection = document.getElementById('lab-selection');
    const table = document.getElementById('lab-bulk-table');
    const items = selectedItems();
    const stats = selectionStats(items);
    const title = activeSelection?.label || t('lab.selection_all', 'Inventario completo');
    if (selection) {
      selection.classList.remove('hidden');
      selection.innerHTML = `
        <div>
          <strong>${esc(title)}</strong>
          <span>${t('lab.selection_count', 'Entradas en vista')}: ${num(items.length)}</span>
          <span>${t('lab.unique_analysis_domains', 'Dominios a analizar')}: ${num(stats.uniqueAnalysisDomains)}</span>
          <span>${t('lab.batch_count', 'Lotes')}: ${num(stats.batchCount)}</span>
        </div>
        <div class="lab-actions lab-actions-inline">
          <button type="button" class="btn btn-primary" onclick="Lab.openReview()" data-i18n="lab.review_process">${t('lab.review_process', 'Revisar/procesar')}</button>
          <button type="button" class="btn" onclick="Lab.showAll()" data-i18n="lab.show_all">${t('lab.show_all', 'Ver todo')}</button>
          <button type="button" class="btn" onclick="Lab.downloadSelection('txt')" data-i18n="lab.download_txt">${t('lab.download_txt', 'Descargar TXT')}</button>
          <button type="button" class="btn" onclick="Lab.downloadSelection('csv')" data-i18n="lab.download_csv">${t('lab.download_csv', 'Descargar CSV')}</button>
        </div>
      `;
    }
    renderTable(table, items);
  }

  function renderTable(table, items) {
    if (!table) return;
    table.classList.remove('hidden');
    table.innerHTML = `
      <table class="lab-table">
        <thead>
          <tr>
            <th>#</th>
            <th>${t('lab.input', 'Entrada')}</th>
            <th>${t('lab.normalized_domain', 'Dominio normalizado')}</th>
            <th>${t('lab.type', 'Tipo')}</th>
            <th>${t('lab.family', 'Familia')}</th>
            <th>${t('lab.base_zone', 'Zona base')}</th>
            <th>${t('lab.analysis_domain', 'Dominio a analizar')}</th>
            <th>${t('lab.batch', 'Lote')}</th>
            <th>${t('lab.recommendation', 'Recomendacion')}</th>
            <th>${t('lab.status', 'Estado')}</th>
          </tr>
        </thead>
        <tbody>
          ${items.map(item => `
            <tr class="lab-row-${esc(item.status)}">
              <td>${num(item.index)}</td>
              <td>${esc(item.original)}</td>
              <td>${esc(item.normalized_domain)}</td>
              <td>${esc(item.tld_type)}</td>
              <td>${esc(familyText(item.report_family))}</td>
              <td>${esc(item.registrable_domain)}</td>
              <td>${esc(item.analysis_domain)}</td>
              <td>${batchLabel(item)}</td>
              <td>${esc(recommendationText(item.analysis_recommendation))}</td>
              <td>${esc(statusText(item.status))}${item.warning ? ` - ${esc(warningText(item.warning))}` : ''}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  }

  function selectedItems() {
    const items = lastNormalization?.items || [];
    if (!activeSelection) return items;
    return items.filter(activeSelection.predicate);
  }

  function selectionStats(items) {
    const unique = new Set(items
      .filter(item => item.status === 'accepted' || item.status === 'changed')
      .map(item => item.analysis_domain || item.normalized_domain)
      .filter(Boolean));
    return {
      uniqueAnalysisDomains: unique.size,
      batchCount: unique.size ? Math.ceil(unique.size / 100) : 0,
    };
  }

  function useReportGroup(group) {
    setSelection(`${t('lab.group', 'Grupo')} .${group}`, item => item.report_group === group);
  }

  function useType(type) {
    setSelection(`${t('lab.type', 'Tipo')} ${type}`, item => item.tld_type === type);
  }

  function useBatch(batchNumber) {
    setSelection(`${t('lab.batch', 'Lote')} ${num(batchNumber)}`, item => item.batch_number === Number(batchNumber));
  }

  function useRecommendation(recommendation) {
    setSelection(recommendationText(recommendation), item => item.analysis_recommendation === recommendation);
  }

  function showAll() {
    activeSelection = null;
    renderSelection();
  }

  function setSelection(label, predicate) {
    activeSelection = { label, predicate };
    renderSelection();
  }

  function downloadSelection(format) {
    const items = selectedItems();
    const basename = activeSelection?.label ? slug(activeSelection.label) : 'inventario-completo';
    if (format === 'txt') {
      const lines = uniqueAnalysisDomains(items);
      downloadBlob(`${basename}.txt`, lines.join('\n') + '\n', 'text/plain;charset=utf-8');
      return;
    }
    const header = [
      'index', 'original', 'normalized_domain', 'analysis_domain', 'status',
      'tld_type', 'report_family', 'report_group', 'registrable_domain',
      'batch_number', 'analysis_recommendation',
    ];
    const rows = items.map(item => header.map(key => csvCell(item[key])).join(','));
    downloadBlob(`${basename}.csv`, [header.join(','), ...rows].join('\n') + '\n', 'text/csv;charset=utf-8');
  }

  function openReview() {
    const items = selectedItems();
    const domains = uniqueAnalysisDomains(items).slice(0, 100);
    activeReviewDomains = domains;
    const title = activeSelection?.label || t('lab.selection_all', 'Inventario completo');
    const review = document.getElementById('lab-review');
    const count = document.getElementById('lab-review-count');
    const warning = document.getElementById('lab-review-warning');
    const list = document.getElementById('lab-review-list');
    const status = document.getElementById('lab-process-status');
    if (count) count.textContent = `${num(domains.length)} / 100`;
    if (warning) {
      warning.textContent = t(
        'lab.review_warning',
        'Se va a procesar una lista de hasta 100 dominios del tipo seleccionado. Revise, edite o cancele antes de continuar.'
      ).replace('{type}', title).replace('{count}', num(domains.length));
    }
    if (list) list.value = domains.join('\n');
    if (status) status.textContent = '';
    if (review) review.classList.remove('hidden');
    review?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function applyReviewEdits() {
    const list = document.getElementById('lab-review-list');
    activeReviewDomains = parseTextDomains(list?.value || '').slice(0, 100);
    if (list) list.value = activeReviewDomains.join('\n');
    const count = document.getElementById('lab-review-count');
    if (count) count.textContent = `${num(activeReviewDomains.length)} / 100`;
    const status = document.getElementById('lab-process-status');
    if (status) status.textContent = t('lab.review_edits_applied', 'Lista editada lista para procesar.');
  }

  function cancelReview() {
    activeReviewDomains = [];
    document.getElementById('lab-review')?.classList.add('hidden');
  }

  function processReviewList() {
    applyReviewEdits();
    const status = document.getElementById('lab-process-status');
    if (status) {
      status.textContent = t(
        'lab.process_placeholder',
        'La lista esta lista. El siguiente modulo conectara esta confirmacion con la cola de analisis DNSViz.'
      );
    }
  }

  function uniqueAnalysisDomains(items) {
    return Array.from(new Set(items
      .filter(item => item.status === 'accepted' || item.status === 'changed')
      .map(item => item.analysis_domain || item.normalized_domain)
      .filter(Boolean)));
  }

  function downloadBlob(filename, content, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  function render(me, status) {
    const user = status.user || me || {};
    setText('lab-session', `${user.email || '-'} - ${user.role || '-'}`);

    const worker = status.dnsviz_worker || {};
    setText('lab-worker', worker.runner === 'gcp_ssh_worker'
      ? `${worker.vm} (${worker.project}/${worker.zone})`
      : (worker.runner || '-'));

    const db = status.phase2_database || {};
    setText('lab-db', db.configured ? db.status : 'not_configured');
    setText('lab-analyses', String(status.prototype?.analyses_indexed ?? '-'));
    setText('lab-phase1', (status.phase1?.public_downloads || []).join(' / '));

    const modules = status.modules || [];
    const wrap = document.getElementById('lab-modules');
    if (wrap) {
      wrap.innerHTML = modules.map(mod => `
        <div class="lab-module">
          <strong>${esc(t(`lab.module_${mod.code}`, mod.label || mod.code))}</strong>
          <span>${esc(t(`lab.module_status_${mod.status}`, mod.status || 'planned'))}</span>
        </div>
      `).join('');
    }
  }

  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value || '';
  }

  function statusText(status) {
    return t(`lab.status_${status}`, status || '-');
  }

  function familyText(family) {
    return t(`lab.family_${family}`, family || '-');
  }

  function warningText(warning) {
    return t(`lab.warning_${warning}`, warning || '');
  }

  function recommendationText(recommendation) {
    return t(`lab.recommendation_${recommendation}`, recommendation || '-');
  }

  function batchLabel(item) {
    if (!item.batch_number) return '-';
    const selected = item.analysis_candidate ? t('lab.included', 'incluido') : t('lab.pending', 'pendiente');
    return `${t('lab.batch', 'Lote')} ${num(item.batch_number)} (${selected})`;
  }

  function t(key, fallback) {
    return I18n.get(key, fallback);
  }

  function esc(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function escAttr(value) {
    return esc(value).replace(/'/g, '&#39;');
  }

  function csvCell(value) {
    const text = String(value ?? '');
    return `"${text.replace(/"/g, '""')}"`;
  }

  function slug(value) {
    return String(value || 'seleccion')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '') || 'seleccion';
  }

  function num(value) {
    return Number(value || 0).toLocaleString();
  }

  init();
  return {
    normalizeDomains,
    clearDomains,
    importDomainFile,
    useReportGroup,
    useType,
    useBatch,
    useRecommendation,
    showAll,
    downloadSelection,
    openReview,
    applyReviewEdits,
    cancelReview,
    processReviewList,
  };
})();
