'use strict';

/**
 * apply-patch.js — Integra el módulo agregado en server.js
 *
 * Uso: node aggregate/apply-patch.js
 *
 * El script es idempotente: si el patch ya fue aplicado, no hace nada.
 */

const fs = require('fs');
const path = require('path');

const serverPath = path.resolve(__dirname, '..', 'server.js');

let src = fs.readFileSync(serverPath, 'utf8');

let changed = false;

// ── PASO 1: require ──────────────────────────────────────────────────────────
const requireLine = `const { handleAggregateRequest } = require('./aggregate/routes/aggregate.routes');`;
const requireAnchor = `const { buildZoneChain } = require(\"./logic/builders/zoneChain.builder\");`;

if (!src.includes(requireLine)) {
  src = src.replace(requireAnchor, `${requireAnchor}\n${requireLine}`);
  changed = true;
  console.log('✓ require del módulo agregado añadido');
} else {
  console.log('· require ya presente, sin cambios');
}

// ── PASO 2: handler en el router ─────────────────────────────────────────────
const handlerBlock = `
  // Módulo agregado DNSSEC
  if (parsed.pathname.startsWith('/aggregate')) {
    return handleAggregateRequest(req, res, parsed);
  }
`;
const routerAnchor = `  sendJSON(res, 404, { error: 'Not found' });`;
const altAnchor    = `  sendJson(res, 404, { error: 'Not found' });`;

if (!src.includes('handleAggregateRequest(req')) {
  if (src.includes(routerAnchor)) {
    src = src.replace(routerAnchor, `${handlerBlock.trimEnd()}\n\n  ${routerAnchor}`);
    changed = true;
    console.log('✓ handler /aggregate añadido al router');
  } else if (src.includes(altAnchor)) {
    src = src.replace(altAnchor, `${handlerBlock.trimEnd()}\n\n  ${altAnchor}`);
    changed = true;
    console.log('✓ handler /aggregate añadido al router (variante)');
  } else {
    console.warn('⚠ No se encontró el punto de inserción del router. Añade manualmente:');
    console.warn(handlerBlock);
  }
} else {
  console.log('· handler ya presente, sin cambios');
}

if (changed) {
  const backup = serverPath + '.bak';
  fs.copyFileSync(serverPath, backup);
  console.log(`· Backup guardado en ${path.basename(backup)}`);
  fs.writeFileSync(serverPath, src, 'utf8');
  console.log('✓ server.js actualizado correctamente');
} else {
  console.log('\nNada que aplicar. El módulo ya está integrado.');
}
