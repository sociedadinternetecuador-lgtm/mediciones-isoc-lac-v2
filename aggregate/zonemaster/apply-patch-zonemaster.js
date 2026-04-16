'use strict';

/**
 * apply-patch-zonemaster.js
 *
 * Integra las rutas de Zonemaster en server.js.
 * Uso: node aggregate/zonemaster/apply-patch-zonemaster.js
 * Idempotente — si ya está aplicado, no hace nada.
 */

const fs   = require('fs');
const path = require('path');

const serverPath = path.resolve(__dirname, '../../server.js');
let src = fs.readFileSync(serverPath, 'utf8');
let changed = false;

// PASO 1: require
const requireLine   = `const { handleZonemasterRequest } = require('./aggregate/zonemaster/zonemaster.routes');`;
const requireAnchor = `const { handleAggregateRequest } = require('./aggregate/routes/aggregate.routes');`;

if (!src.includes(requireLine)) {
  src = src.replace(requireAnchor, `${requireAnchor}\n${requireLine}`);
  changed = true;
  console.log('✓ require Zonemaster añadido');
} else {
  console.log('· require ya presente');
}

// PASO 2: handler en el router
const handlerBlock = `
  // Módulo Zonemaster — análisis DNSSEC profundo
  if (parsed.pathname.startsWith('/zm')) {
    return handleZonemasterRequest(req, res, parsed);
  }
`;
const routerAnchor = `  // Módulo agregado DNSSEC`;

if (!src.includes('handleZonemasterRequest(req')) {
  if (src.includes(routerAnchor)) {
    src = src.replace(routerAnchor, `${handlerBlock.trimEnd()}\n\n  ${routerAnchor.trimStart()}`);
    changed = true;
    console.log('✓ handler /zm añadido al router');
  } else {
    console.warn('⚠ No se encontró el punto de inserción. Añade manualmente:');
    console.warn(handlerBlock);
  }
} else {
  console.log('· handler ya presente');
}

if (changed) {
  fs.copyFileSync(serverPath, serverPath + '.bak2');
  fs.writeFileSync(serverPath, src, 'utf8');
  console.log('✓ server.js actualizado. Backup: server.js.bak2');
} else {
  console.log('\nNada que aplicar.');
}
