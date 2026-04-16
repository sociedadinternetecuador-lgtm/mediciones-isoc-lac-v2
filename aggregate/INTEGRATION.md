// ─── INSTRUCCIONES DE INTEGRACIÓN EN server.js ───────────────────────────────
//
// PASO 1: Añadir el require al bloque de imports (después de la línea 15):
//
//   const { handleAggregateRequest } = require('./aggregate/routes/aggregate.routes');
//
//
// PASO 2: Añadir el handler ANTES del bloque "Ruta no encontrada" (línea 2613):
//
//   // Módulo agregado DNSSEC
//   if (parsed.pathname.startsWith('/aggregate')) {
//     return handleAggregateRequest(req, res, parsed);
//   }
//
// Con esos dos cambios el módulo queda integrado sin tocar ninguna lógica existente.
// ─────────────────────────────────────────────────────────────────────────────

// ─── PARA APLICAR EL PATCH AUTOMÁTICAMENTE ───────────────────────────────────
// Ejecutar desde la raíz del proyecto:
//
//   node aggregate/apply-patch.js
//
// El script verifica que los cambios no estén ya aplicados antes de modificar.
