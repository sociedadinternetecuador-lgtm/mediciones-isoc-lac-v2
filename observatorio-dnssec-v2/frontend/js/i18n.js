/* ═══════════════════════════════════════════════════════════
   i18n.js — Motor de internacionalización
   Carga es.json / en.json, aplica data-i18n en el DOM,
   persiste idioma en localStorage.
   ═══════════════════════════════════════════════════════════ */

const I18n = (() => {
  let _lang   = localStorage.getItem('obs_lang') || 'es';
  let _data   = {};
  let _config = {};

  async function init() {
    // Cargar config primero
    try {
      const r = await fetch('/data/config.json');
      _config = await r.json();
      if (!localStorage.getItem('obs_lang')) {
        _lang = _config.default_lang || 'es';
      }
    } catch (e) {
      console.warn('i18n: no se pudo cargar config.json');
    }

    await _loadLang(_lang);
    _applyDOM();
    _updateToggle();
  }

  async function _loadLang(lang) {
    try {
      const r = await fetch(`/data/${lang}.json`);
      _data = await r.json();
      _lang = lang;
      localStorage.setItem('obs_lang', lang);
    } catch (e) {
      console.error(`i18n: no se pudo cargar ${lang}.json`);
    }
  }

  async function toggle() {
    const next = _lang === 'es' ? 'en' : 'es';
    await _loadLang(next);
    _applyDOM();
    _updateToggle();
    // Disparar evento para que otros módulos reaccionen
    document.dispatchEvent(new CustomEvent('langchange', { detail: { lang: _lang } }));
  }

  function _applyDOM() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const val = get(key);
      if (val !== null) {
        if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
          el.placeholder = val;
        } else {
          el.textContent = val;
        }
      }
    });

    document.querySelectorAll('[data-i18n-html]').forEach(el => {
      const key = el.getAttribute('data-i18n-html');
      const val = get(key);
      if (val !== null) el.innerHTML = val;
    });

    document.querySelectorAll('[data-i18n-title]').forEach(el => {
      const key = el.getAttribute('data-i18n-title');
      const val = get(key);
      if (val !== null) el.title = val;
    });
  }

  function _updateToggle() {
    document.querySelectorAll('[data-lang-toggle]').forEach(el => {
      el.textContent = _lang === 'es' ? 'English' : 'Español';
    });
  }

  /**
   * Obtiene una clave anidada con notación punto: "admin.login_title"
   * Devuelve null si no existe.
   */
  function get(key, fallback = null) {
    const parts = key.split('.');
    let cur = _data;
    for (const p of parts) {
      if (cur == null || typeof cur !== 'object') return fallback;
      cur = cur[p];
    }
    return cur != null ? String(cur) : fallback;
  }

  function lang() { return _lang; }
  function config() { return _config; }

  return { init, toggle, get, lang, config };
})();
