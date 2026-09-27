/**
 * Base de Conocimiento DNSSEC ("Aprender DNSSEC") — lógica de presentación.
 * Consume window.DNSSEC_KB (public/dnssecKb.content.js, debe cargar ANTES
 * que este archivo). No contiene contenido editorial ni lógica del
 * analizador DNSSEC — solo landing, buscador, filtros, render de guía,
 * TOC/active-state y el hash-routing de la KB.
 *
 * Expone una única interfaz global, window.DnssecKb, para no llenar
 * `window` de funciones sueltas. Los `onclick` inline del HTML y el
 * wireup de `hashchange` al final de index.html llaman a DnssecKb.*.
 */
(function () {
  'use strict';

  let inited = false;
  let activeLevel = 'todos';
  let searchText = '';
  let searchDebounce = null;
  let tocObserver = null;
  let currentGuideId = null;

  // Búsqueda tolerante a acentos: "validacion" debe encontrar "validación".
  // Sin librería — Unicode NFD + remoción de diacríticos.
  function stripDiacritics(text) {
    return String(text).normalize('NFD').replace(/[̀-ͯ]/g, '');
  }

  function normalizeForSearch(text) {
    return stripDiacritics(text).toLowerCase();
  }

  function levelLabel(level) {
    return { basico: 'Básico', intermedio: 'Intermedio', avanzado: 'Avanzado', referencia: 'Referencia' }[level] || level;
  }

  function levelBadgeClass(level) {
    return {
      basico: 'bg-green-100 text-green-800 border-green-300',
      intermedio: 'bg-blue-100 text-blue-800 border-blue-300',
      avanzado: 'bg-purple-100 text-purple-800 border-purple-300',
      referencia: 'bg-gray-100 text-gray-700 border-gray-300'
    }[level] || 'bg-gray-100 text-gray-700 border-gray-300';
  }

  function findGuide(id) {
    const kb = window.DNSSEC_KB;
    if (!kb) return null;
    return kb.guides.find(function (g) { return g.id === id; }) || null;
  }

  function renderGrid() {
    const kb = window.DNSSEC_KB;
    const grid = document.getElementById('dnssec-kb-grid');
    const empty = document.getElementById('dnssec-kb-empty');
    if (!kb || !grid) return;

    const needle = normalizeForSearch(searchText);
    const filtered = kb.guides.filter(function (g) {
      if (activeLevel !== 'todos' && g.level !== activeLevel) return false;
      if (!needle) return true;
      const haystack = normalizeForSearch(g.title + ' ' + g.summary + ' ' + (g.keywords || []).join(' '));
      return haystack.indexOf(needle) !== -1;
    });

    if (filtered.length === 0) {
      grid.innerHTML = '';
      empty.classList.remove('hidden');
      return;
    }
    empty.classList.add('hidden');

    grid.innerHTML = filtered.map(function (g) {
      return '<button type="button" onclick="DnssecKb.openGuide(\'' + g.id + '\')" '
        + 'class="text-left bg-white border border-gray-200 rounded-lg p-4 hover:border-blue-400 hover:shadow-sm transition flex flex-col gap-2">'
        + '<div class="flex items-center gap-2">'
        + '<span class="text-[11px] font-semibold px-2 py-0.5 rounded-full border ' + levelBadgeClass(g.level) + '">' + escapeHtml(levelLabel(g.level)) + '</span>'
        + '<span class="text-xs text-gray-400">' + g.minutes + ' min</span>'
        + '</div>'
        + '<div class="font-semibold text-gray-800 text-sm">' + escapeHtml(g.title) + '</div>'
        + '<div class="text-xs text-gray-500 leading-relaxed">' + escapeHtml(g.summary) + '</div>'
        + '<span class="text-xs font-semibold text-blue-700 mt-1">Leer guía →</span>'
        + '</button>';
    }).join('');
  }

  function setLevel(level) {
    activeLevel = level;
    document.querySelectorAll('.dnssec-kb-level-btn').forEach(function (btn) {
      const active = btn.dataset.level === level;
      btn.setAttribute('aria-pressed', active ? 'true' : 'false');
      btn.classList.toggle('bg-blue-600', active);
      btn.classList.toggle('text-white', active);
      btn.classList.toggle('border-blue-600', active);
      btn.classList.toggle('bg-white', !active);
      btn.classList.toggle('text-gray-600', !active);
      btn.classList.toggle('border-gray-300', !active);
    });
    renderGrid();
  }

  function init() {
    if (inited) return;
    inited = true;

    const searchInput = document.getElementById('dnssec-kb-search');
    if (searchInput) {
      searchInput.addEventListener('input', function () {
        const value = this.value;
        clearTimeout(searchDebounce);
        searchDebounce = setTimeout(function () {
          searchText = value.trim();
          renderGrid();
        }, 180);
      });
    }

    setLevel(activeLevel);
  }

  function renderGuide(guide) {
    const body = document.getElementById('dnssec-kb-guide-body');
    const tocDesktop = document.getElementById('dnssec-kb-toc-desktop');
    const tocMobile = document.getElementById('dnssec-kb-toc-mobile');
    if (!body) return;

    currentGuideId = guide.id;

    const header = '<div class="mb-4">'
      + '<div class="flex items-center gap-2 mb-2">'
      + '<span class="text-[11px] font-semibold px-2 py-0.5 rounded-full border ' + levelBadgeClass(guide.level) + '">' + escapeHtml(levelLabel(guide.level)) + '</span>'
      + '<span class="text-xs text-gray-400">' + guide.minutes + ' min de lectura</span>'
      + '</div>'
      + '<h1 class="text-xl font-bold text-gray-900">' + escapeHtml(guide.title) + '</h1>'
      + '<p class="text-sm text-gray-600 mt-1">' + escapeHtml(guide.summary) + '</p>'
      + '</div>';

    const sectionsHtml = guide.sections.map(function (s) {
      const heading = '<h2 id="' + s.id + '" class="text-base font-semibold text-gray-800 mt-6 mb-2 scroll-mt-4">' + escapeHtml(s.heading) + '</h2>';
      if (s.collapsible) {
        return heading + '<details class="dnssec-kb-detail border border-gray-200 rounded-lg bg-gray-50 p-3">'
          + '<summary class="cursor-pointer text-sm font-semibold text-blue-700">Ver detalle técnico</summary>'
          + '<div class="mt-2 text-sm text-gray-700 leading-relaxed">' + s.html + '</div>'
          + '</details>';
      }
      return heading + '<div class="text-sm text-gray-700 leading-relaxed">' + s.html + '</div>';
    }).join('');

    body.innerHTML = header + sectionsHtml;

    const tocLinks = guide.sections.map(function (s) {
      return '<a href="#' + s.id + '" data-toc-target="' + s.id + '" class="dnssec-kb-toc-link block text-gray-600 hover:text-blue-700 py-0.5 border-l-2 border-transparent pl-2 -ml-2">' + escapeHtml(s.heading) + '</a>';
    }).join('');
    if (tocDesktop) tocDesktop.innerHTML = tocLinks;
    if (tocMobile) tocMobile.innerHTML = tocLinks;

    // Un solo observer vivo a la vez: se desconecta el anterior (si lo hay)
    // antes de observar las secciones de la guía recién renderizada, para
    // que nunca queden observers viejos escuchando nodos ya reemplazados.
    if (tocObserver) tocObserver.disconnect();
    const setActiveTocLink = function (sectionId) {
      document.querySelectorAll('.dnssec-kb-toc-link').forEach(function (link) {
        const active = link.dataset.tocTarget === sectionId;
        link.classList.toggle('text-blue-700', active);
        link.classList.toggle('font-semibold', active);
        link.classList.toggle('border-blue-600', active);
        link.classList.toggle('text-gray-600', !active);
      });
    };
    tocObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) setActiveTocLink(entry.target.id);
      });
    }, { rootMargin: '-10% 0px -70% 0px' });
    guide.sections.forEach(function (s) {
      const el = document.getElementById(s.id);
      if (el) tocObserver.observe(el);
    });

    document.querySelectorAll('#dnssec-kb-guide-body .dnssec-kb-detail').forEach(function (details) {
      details.addEventListener('toggle', function () {
        const summary = details.querySelector('summary');
        if (summary) summary.setAttribute('aria-expanded', details.open ? 'true' : 'false');
      });
    });

    const prevBtn = document.getElementById('dnssec-kb-prev');
    const nextBtn = document.getElementById('dnssec-kb-next');
    if (guide.prevId) {
      prevBtn.disabled = false;
      prevBtn.onclick = function () { openGuide(guide.prevId); };
    } else {
      prevBtn.disabled = true;
      prevBtn.onclick = null;
    }
    if (guide.nextId) {
      nextBtn.disabled = false;
      nextBtn.onclick = function () { openGuide(guide.nextId); };
    } else {
      nextBtn.disabled = true;
      nextBtn.onclick = null;
    }
  }

  function openGuide(id) {
    const guide = findGuide(id);
    if (!guide) return;

    document.getElementById('dnssec-kb-landing').classList.add('hidden');
    document.getElementById('dnssec-kb-guide-view').classList.remove('hidden');
    renderGuide(guide);

    const targetHash = '#/dnssec/aprender/' + guide.slug;
    if (window.location.hash !== targetHash) window.location.hash = targetHash;

    const panel = document.getElementById('dnssec-panel-aprender');
    if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function backToGrid() {
    document.getElementById('dnssec-kb-guide-view').classList.add('hidden');
    document.getElementById('dnssec-kb-landing').classList.remove('hidden');
    if (window.location.hash.indexOf('#/dnssec/aprender') === 0) {
      history.replaceState(null, '', window.location.pathname + window.location.search);
    }
  }

  function switchTopTab(tab) {
    const analizar = document.getElementById('dnssec-panel-analizar');
    const aprender = document.getElementById('dnssec-panel-aprender');
    const tAnalizar = document.getElementById('dnssec-top-tab-analizar');
    const tAprender = document.getElementById('dnssec-top-tab-aprender');
    const result = document.getElementById('dnssec-inline-result');

    if (tab === 'aprender') {
      aprender.classList.remove('hidden');
      analizar.classList.add('hidden');
      if (result) result.classList.add('hidden');
      tAprender.classList.add('bg-white', 'text-blue-700', 'shadow-sm');
      tAprender.classList.remove('text-gray-600');
      tAnalizar.classList.remove('bg-white', 'text-blue-700', 'shadow-sm');
      tAnalizar.classList.add('text-gray-600');
      init();
    } else {
      analizar.classList.remove('hidden');
      aprender.classList.add('hidden');
      tAnalizar.classList.add('bg-white', 'text-blue-700', 'shadow-sm');
      tAnalizar.classList.remove('text-gray-600');
      tAprender.classList.remove('bg-white', 'text-blue-700', 'shadow-sm');
      tAprender.classList.add('text-gray-600');
    }
  }

  function handleRoute() {
    const hash = window.location.hash || '';
    const prefix = '#/dnssec/aprender/';
    if (hash.indexOf(prefix) !== 0) return;
    const slug = hash.slice(prefix.length);
    if (!slug) return;

    const kb = window.DNSSEC_KB;
    if (!kb) return;
    const guide = kb.guides.find(function (g) { return g.slug === slug; });
    if (!guide) return;

    const dnssecTabBtn = document.querySelector('[data-tab="dnssec"]');
    if (dnssecTabBtn) dnssecTabBtn.click();
    switchTopTab('aprender');
    init();
    document.getElementById('dnssec-kb-landing').classList.add('hidden');
    document.getElementById('dnssec-kb-guide-view').classList.remove('hidden');
    // openGuide() ya renderizó esta misma guía justo antes de actualizar el
    // hash (que es lo que dispara este handler vía 'hashchange') — evita
    // reconstruir el DOM y recrear el IntersectionObserver dos veces por
    // una sola navegación.
    if (guide.id !== currentGuideId) renderGuide(guide);
  }

  // Enlace educativo discreto ("ⓘ"), usado por el analizador DNSSEC
  // (renderDnssecInlineResult, en index.html) junto a DS/DNSKEY/RRSIG/
  // estado final. No depende de ningún estado del analizador — solo arma
  // un fragmento de enlace hacia un slug del catálogo de la KB.
  function infoLink(slug, label) {
    return ` <a href="#/dnssec/aprender/${slug}" class="dnssec-info-link" title="${label}" aria-label="${label}" style="color:#2563eb;text-decoration:none;">ⓘ</a>`;
  }

  window.DnssecKb = {
    init: init,
    switchTopTab: switchTopTab,
    setLevel: setLevel,
    openGuide: openGuide,
    backToGrid: backToGrid,
    handleRoute: handleRoute,
    infoLink: infoLink
  };
})();
