/* DNSViz-like report view. Default report shows DNSViz status panels + graph. */

const Report = (() => {
  let _data = null;
  let _legendTaxonomy = null;

  async function init() {
    await I18n.init();
    document.getElementById('menu-toggle')
      ?.addEventListener('click', () =>
        document.getElementById('mobile-nav')?.classList.toggle('open'));

    const raw = sessionStorage.getItem('obs_report');
    if (!raw) {
      location.href = '/';
      return;
    }
    try {
      _data = JSON.parse(raw);
    } catch {
      location.href = '/';
      return;
    }

    await loadLegendTaxonomy();
    render();
    document.addEventListener('langchange', () => I18n.init().then(render));
  }

  function render() {
    if (!_data) return;

    document.getElementById('loader')?.classList.remove('visible');
    document.getElementById('report-wrap')?.classList.remove('hidden');
    document.title = `${_data.domain || 'DNSViz'} - DNSViz`;

    text('res-domain', _data.domain || '-');
    text('res-date', formatDate(_data.generated_at || _data.timestamp));
    text('res-runner', runnerLabel());

    setArtifactLinks();

    const visual = _data.dnsviz_visual || {};
    const view = visual.default_view || visual;
    renderStatusGroups('rrset-status', view.rrset_status || []);
    renderStatusGroups('dnskey-status', view.dnskey_ds_nsec_status || []);
    renderStatusGroups('delegation-status', view.delegation_status || []);
    renderNotices(visual.notices || {});
    renderLegend();
    renderGraph();
  }

  async function loadLegendTaxonomy() {
    try {
      const res = await fetch('/data/dnsviz/dnsviz-legend-taxonomy.json');
      _legendTaxonomy = await res.json();
    } catch {
      _legendTaxonomy = null;
    }
  }

  function setArtifactLinks() {
    const id = _data.id || _data.analysis_id || _data?.dnsviz?.analysis_id;
    const artifacts = _data.artifacts || _data.source || {};
    const map = {
      'download-png': artifacts.graph_png || (id ? `/analyze/${id}/graph.png` : '#'),
      'download-svg': artifacts.graph_svg || (id ? `/analyze/${id}/graph.svg` : '#'),
      'download-png-top': artifacts.graph_png || (id ? `/analyze/${id}/graph.png` : '#'),
      'download-svg-top': artifacts.graph_svg || (id ? `/analyze/${id}/graph.svg` : '#'),
    };
    Object.entries(map).forEach(([elId, href]) => {
      const el = document.getElementById(elId);
      if (el) {
        el.href = href;
        el.classList.toggle('disabled', href === '#');
      }
    });
  }

  function renderStatusGroups(id, groups) {
    const el = document.getElementById(id);
    if (!el) return;
    if (!groups.length) {
      el.innerHTML = `<div class="dnsviz-muted">${esc(I18n.get('report.no_data', 'No data'))}</div>`;
      return;
    }

    el.innerHTML = groups.map((group, idx) => {
      const status = String(group.status || 'UNKNOWN').toUpperCase();
      const items = group.items || [];
      return `
        <details class="dnsviz-status-group dnsviz-status-${esc(status)}">
          <summary class="dnsviz-status-head">
            <span class="dnsviz-status-dot status-${esc(status)}"></span>
            <strong>${esc(labelStatus(status))}</strong>
            <span>(${Number(group.count || items.length || 0)})</span>
          </summary>
          <ul>
            ${items.map(item => `<li>${esc(item.label || formatItem(item))}</li>`).join('')}
          </ul>
        </details>`;
    }).join('');
  }

  function renderNotices(notices) {
    const el = document.getElementById('notice-status');
    if (!el) return;
    const errors = notices.errors || [];
    const warnings = notices.warnings || [];
    const sections = [
      { label: I18n.get('report.errors_label', 'Errors'), cls: 'error', rows: errors, count: Number(notices.errors_count || errors.length || 0) },
      { label: I18n.get('report.warnings_label', 'Warnings'), cls: 'warning', rows: warnings, count: Number(notices.warnings_count || warnings.length || 0) },
    ];

    if (!errors.length && !warnings.length) {
      el.innerHTML = `<div class="dnsviz-muted">${esc(I18n.get('report.no_notices', 'No notices'))}</div>`;
      return;
    }

    el.innerHTML = sections.filter(section => section.count || section.rows.length).map(section => `
      <details class="dnsviz-notice-group ${section.cls}">
        <summary class="dnsviz-notice-title">
          <strong>${esc(section.label)} (${section.count})</strong>
        </summary>
        <div class="dnsviz-notice-items">
          ${section.rows.map(row => {
            const servers = (row.servers || []).length
              ? `<div class="dnsviz-notice-servers">${esc(row.servers.join(', '))}</div>`
              : '';
            return `
              <article class="dnsviz-notice-item">
                <strong>${esc(row.label || row.node_label || row.code || '')}</strong>
                <div class="dnsviz-notice-text">${esc(row.description || row.code || '')}</div>
                ${servers}
              </article>`;
          }).join('')}
        </div>
      </details>`).join('');
  }

  function renderGraph() {
    const id = _data.id || _data.analysis_id || _data?.dnsviz?.analysis_id;
    const artifacts = _data.artifacts || _data.source || {};
    const htmlSrc = artifacts.graph_html || artifacts.graph || _data?.dnsviz_original?.graph_html_url || (id ? `/analyze/${id}/graph.html` : '');
    const svgSrc = artifacts.graph_svg || (id ? `/analyze/${id}/graph.svg` : '');
    const pngSrc = artifacts.graph_png || (id ? `/analyze/${id}/graph.png` : '');
    const frame = document.getElementById('graph-frame');
    const img = document.getElementById('graph-img');
    const empty = document.getElementById('graph-empty');
    if (!img || !empty) return;
    if (htmlSrc && frame) {
      frame.onload = () => {
        empty.classList.add('hidden');
        img.classList.add('hidden');
        frame.classList.remove('hidden');
      };
      frame.onerror = () => {
        frame.classList.add('hidden');
        renderGraphImage(svgSrc, pngSrc, img, empty);
      };
      frame.src = `${htmlSrc}?t=${Date.now()}`;
      return;
    }
    renderGraphImage(svgSrc, pngSrc, img, empty);
  }

  function renderGraphImage(svgSrc, pngSrc, img, empty) {
    document.getElementById('graph-frame')?.classList.add('hidden');
    if (svgSrc) {
      showGraphImage(svgSrc, pngSrc, img, empty);
      return;
    }
    if (!pngSrc) {
      img.classList.add('hidden');
      empty.classList.remove('hidden');
      return;
    }
    showGraphImage(pngSrc, '', img, empty);
  }

  function showGraphImage(src, fallbackSrc, img, empty) {
    img.onload = () => {
      empty.classList.add('hidden');
      img.classList.remove('hidden');
    };
    img.onerror = () => {
      if (fallbackSrc && src !== fallbackSrc) {
        showGraphImage(fallbackSrc, '', img, empty);
      } else {
        img.classList.add('hidden');
        empty.classList.remove('hidden');
      }
    };
    img.src = `${src}?t=${Date.now()}`;
  }

  function renderLegend() {
    const lang = I18n.lang ? I18n.lang() : 'es';
    text('legend-compact-title', lang === 'en' ? 'DNSKEY legend' : 'Leyenda DNSKEY');
    text('legend-open-link', lang === 'en' ? 'Full legend' : 'Leyenda completa');
    text('legend-modal-title', lang === 'en' ? 'Full legend' : 'Leyenda completa');
    text('legend-close-btn', lang === 'en' ? 'Close' : 'Cerrar');

    const compact = document.getElementById('legend-compact');
    const full = document.getElementById('legend-full');
    const entries = Array.isArray(_legendTaxonomy?.entries) ? _legendTaxonomy.entries : [];
    if (!compact || !full || !entries.length) {
      if (compact) compact.innerHTML = '<div class="dnsviz-muted">No legend</div>';
      return;
    }

    const compactIds = ['dnskey_sep_bit', 'dnskey_revoke_bit', 'dnskey_trust_anchor'];
    compact.innerHTML = compactIds.map(id => {
      const entry = entries.find(item => item.id === id);
      return entry ? legendRow(entry, lang, true) : '';
    }).join('');

    const categoryLabels = {
      zone: ['Zones', 'Zonas'],
      delegation: ['Delegations', 'Delegaciones'],
      rrset: ['RRsets', 'RRsets'],
      negative_response: ['Negative responses', 'Respuestas negativas'],
      dnskey: ['DNSKEY', 'DNSKEY'],
      ds: ['DS relationships', 'Relaciones DS'],
      nsec_nsec3: ['NSEC/NSEC3', 'NSEC/NSEC3'],
      rrsig: ['RRSIG', 'RRSIG'],
      cdnskey_cds: ['CDNSKEY/CDS', 'CDNSKEY/CDS'],
      wildcard: ['Wildcard', 'Wildcard'],
      node_status: ['Node status', 'Estado de nodos'],
      warning_error: ['Warnings and errors', 'Advertencias y errores'],
    };

    const grouped = entries.reduce((acc, entry) => {
      const category = entry.category || 'other';
      acc[category] = acc[category] || [];
      acc[category].push(entry);
      return acc;
    }, {});

    full.innerHTML = Object.entries(grouped).map(([category, rows]) => {
      const labels = categoryLabels[category] || [category, category];
      return `
        <section class="dnsviz-legend-section">
          <h3>${esc(lang === 'en' ? labels[0] : labels[1])}</h3>
          ${rows.map(entry => legendRow(entry, lang, false)).join('')}
        </section>`;
    }).join('');
  }

  function legendRow(entry, lang, compact) {
    const loc = entry.localization?.[lang] || entry.localization?.en || {};
    const label = loc.display_label || entry.canonical_dnsviz_legend?.canonical_label_en || entry.id;
    const meaning = loc.technical_meaning || entry.canonical_dnsviz_legend?.meaning_en || '';
    return `
      <div class="dnsviz-legend-row">
        ${legendSymbol(entry.id)}
        <div>
          <div class="dnsviz-legend-label">${esc(label)}</div>
          ${compact ? '' : `<div class="dnsviz-legend-meaning">${esc(meaning)}</div>`}
        </div>
      </div>`;
  }

  function legendSymbol(id) {
    if (id === 'dnskey_sep_bit') return '<span class="legend-symbol legend-dnskey legend-sep"></span>';
    if (id === 'dnskey_revoke_bit') return '<span class="legend-symbol legend-dnskey legend-revoke"></span>';
    if (id === 'dnskey_trust_anchor') return '<span class="legend-symbol legend-dnskey legend-trust"></span>';
    if (id === 'dnskey_node') return '<span class="legend-symbol legend-dnskey"></span>';
    if (id.startsWith('delegation_')) return `<span class="legend-symbol legend-line ${id.replace('delegation_', 'legend-delegation-')}"></span>`;
    if (id.startsWith('ds_')) return '<span class="legend-symbol legend-line legend-blue"></span>';
    if (id.startsWith('rrsig_')) return '<span class="legend-symbol legend-line legend-blue"></span>';
    if (id.startsWith('nsec') || id.startsWith('negative_')) return '<span class="legend-symbol legend-box legend-dashed"></span>';
    if (id.includes('warning')) return '<span class="legend-symbol legend-icon legend-warning">!</span>';
    if (id.includes('error') || id.includes('bogus')) return '<span class="legend-symbol legend-icon legend-error">!</span>';
    if (id.includes('secure')) return '<span class="legend-symbol legend-box legend-secure"></span>';
    return '<span class="legend-symbol legend-box"></span>';
  }

  function openLegend() {
    document.getElementById('legend-modal')?.classList.remove('hidden');
  }

  function closeLegend() {
    document.getElementById('legend-modal')?.classList.add('hidden');
  }

  function runnerLabel() {
    const runner = _data?.dnsviz?.runner;
    const worker = _data?.dnsviz?.worker;
    if (runner === 'gcp_ssh_worker' && worker?.vm) {
      return `${I18n.get('report.worker', 'Worker')}: ${worker.vm} (${worker.zone})`;
    }
    return `${I18n.get('report.worker', 'Worker')}: ${I18n.get('report.local_worker', 'local')}`;
  }

  function labelStatus(status) {
    const map = {
      SECURE: I18n.get('report.status_secure', 'Secure'),
      VALID: I18n.get('report.status_secure', 'Secure'),
      BOGUS: I18n.get('report.status_bogus', 'Bogus'),
      INSECURE: I18n.get('report.status_insecure', 'Insecure'),
      INDETERMINATE: I18n.get('report.status_indeterminate', 'Indeterminate'),
      ERROR: I18n.get('report.status_error', 'Error'),
      WARNING: I18n.get('report.status_warning', 'Warning'),
      UNKNOWN: I18n.get('report.status_unknown', 'Unknown'),
    };
    return map[status] || status;
  }

  function formatItem(item) {
    if (!item || typeof item !== 'object') return '';
    return item.name && item.type ? `${item.name}/${item.type}` : JSON.stringify(item);
  }

  function formatDate(value) {
    if (!value) return '';
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return value;
    return d.toLocaleString();
  }

  function text(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value || '';
  }

  function esc(value) {
    if (value === null || value === undefined) return '';
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  init();
  return { openLegend, closeLegend };
})();
