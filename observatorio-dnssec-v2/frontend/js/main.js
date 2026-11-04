/* ═══════════════════════════════════════════════════════════
   main.js — Lógica de index.html
   ═══════════════════════════════════════════════════════════ */

const Main = (() => {
  let _analyzing = false;
  const LAST_REPORT_KEY = 'obs_last_report';

  async function init() {
    await I18n.init();

    // Menu móvil
    document.getElementById('menu-toggle')
      ?.addEventListener('click', () =>
        document.getElementById('mobile-nav')?.classList.toggle('open'));

    // Enter en el input
    document.getElementById('domain-input')
      ?.addEventListener('keydown', e => { if (e.key === 'Enter') analyze(); });

    // Limpiar error al escribir
    document.getElementById('domain-input')
      ?.addEventListener('input', () => {
        document.getElementById('search-error')?.classList.add('hidden');
        _renderLastAnalysis();
      });

    document.addEventListener('langchange', () => I18n.init());
    _renderLastAnalysis();
  }

  async function analyze() {
    if (_analyzing) return;

    const input  = document.getElementById('domain-input');
    const errEl  = document.getElementById('search-error');
    const domain = (input?.value || '').trim().toLowerCase().replace(/\s+/g, '');

    errEl?.classList.add('hidden');

    if (!domain) {
      _showError(I18n.get('errors.domain_required'));
      return;
    }
    if (!_validDomain(domain)) {
      _showError(I18n.get('errors.invalid_domain'));
      return;
    }

    _setLoading(true);
    _setProgress({ status: 'queued', progress: 0, message: 'Analisis en cola', domain });

    try {
      const result = await API.analyze(domain, _setProgress);
      sessionStorage.setItem('obs_report', JSON.stringify(result));
      localStorage.setItem(LAST_REPORT_KEY, JSON.stringify(result));
      location.href = '/report';
    } catch (err) {
      _setLoading(false);
      const fallback = err.error === 'timeout'        ? 'El análisis está tardando más de lo esperado.'
                     : err.error === 'network'        ? 'No se pudo conectar con el servidor.'
                     : err.error === 'invalid_domain' ? I18n.get('errors.invalid_domain')
                     : I18n.get('errors.analysis_failed');
      _showError(err.message || fallback || I18n.get('errors.analysis_failed'));
    }
  }

  function _validDomain(d) {
    return /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$/.test(d);
  }

  function _showError(msg) {
    const el = document.getElementById('search-error');
    if (!el) return;
    el.textContent = msg;
    el.classList.remove('hidden');
  }

  function _setLoading(on) {
    _analyzing = on;
    const btn    = document.getElementById('btn-analyze');
    const loader = document.getElementById('loader');
    const hero   = document.querySelector('.hero');
    if (on) {
      if (btn) { btn.disabled = true; btn.querySelector('span').textContent = I18n.get('home.btn_analyzing') || 'Analizando…'; }
      loader?.classList.add('visible');
      document.getElementById('analysis-progress')?.classList.remove('hidden');
      hero?.style.setProperty('padding-bottom', '1rem');
    } else {
      if (btn) { btn.disabled = false; btn.querySelector('span').textContent = I18n.get('home.btn_analyze') || 'Analizar'; }
      loader?.classList.remove('visible');
      document.getElementById('analysis-progress')?.classList.add('hidden');
      hero?.style.removeProperty('padding-bottom');
    }
  }

  init();

  function _setProgress(status = {}) {
    const progress = Math.max(0, Math.min(100, Number(status.progress || 0)));
    const state = String(status.status || 'running');
    const message = status.message || _messageForProgress(progress, state);

    const title = document.getElementById('analysis-progress-title');
    const pct = document.getElementById('analysis-progress-percent');
    const bar = document.getElementById('analysis-progress-bar');
    const steps = document.getElementById('analysis-steps');

    if (title) title.textContent = message;
    if (pct) pct.textContent = `${progress}%`;
    if (bar) bar.style.width = `${progress}%`;
    if (!steps) return;

    const items = [
      { min: 0, label: 'Solicitud recibida' },
      { min: 10, label: 'Preparando DNSViz y cadena de zonas' },
      { min: 35, label: 'Consultando servidores autoritativos' },
      { min: 65, label: 'Generando grafico y reporte DNSViz' },
      { min: 85, label: 'Construyendo reporte DNSViz' },
      { min: 100, label: 'Reporte listo' },
    ];

    steps.innerHTML = items.map(item => {
      const done = progress >= item.min;
      const current = !done && progress < item.min && progress >= Math.max(0, item.min - 25);
      return `<li class="${done ? 'done' : current ? 'current' : ''}">${item.label}</li>`;
    }).join('');
  }

  function _messageForProgress(progress, state) {
    if (state === 'queued') return 'Analisis en cola';
    if (state === 'done') return 'Reporte listo';
    if (state === 'error') return 'No se pudo completar el analisis';
    if (progress >= 85) return 'Construyendo reporte';
    if (progress >= 35) return 'Ejecutando DNSViz';
    return 'Preparando DNSViz';
  }

  function _readLastAnalysis() {
    try {
      return JSON.parse(localStorage.getItem(LAST_REPORT_KEY) || 'null');
    } catch {
      return null;
    }
  }

  function _renderLastAnalysis() {
    const card = document.getElementById('last-analysis-card');
    if (!card) return;
    const last = _readLastAnalysis();
    if (!last?.domain) {
      card.classList.add('hidden');
      return;
    }
    const typed = (document.getElementById('domain-input')?.value || '').trim().toLowerCase();
    const sameDomain = !typed || typed === String(last.domain).toLowerCase();
    card.classList.toggle('hidden', !sameDomain);
    document.getElementById('last-analysis-domain').textContent = `Ultimo analisis: ${last.domain}`;
    document.getElementById('last-analysis-date').textContent =
      last.generated_at || last.timestamp ? `Actualizado: ${_formatDate(last.generated_at || last.timestamp)}` : '';
  }

  function _formatDate(value) {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
  }

  function viewLast() {
    const last = _readLastAnalysis();
    if (!last) return;
    sessionStorage.setItem('obs_report', JSON.stringify(last));
    location.href = '/report';
  }

  function reanalyzeLast() {
    const last = _readLastAnalysis();
    if (!last?.domain) return;
    const input = document.getElementById('domain-input');
    if (input) input.value = last.domain;
    analyze();
  }

  return { analyze, viewLast, reanalyzeLast };
})();
