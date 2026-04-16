'use strict';

/**
 * Exporters — Módulo Agregado DNSSEC ISOC LAC
 *
 * Tres formatos de exportación:
 *  - JSON: estructura completa, apta para APIs y almacenamiento
 *  - CSV: resultados por dominio, apto para análisis en hojas de cálculo
 *  - HTML: reporte ejecutivo con semáforo visual y recomendaciones
 */

// ─── JSON ────────────────────────────────────────────────────────────────────

function toJson(data) {
  return JSON.stringify(data, null, 2);
}

// ─── CSV ─────────────────────────────────────────────────────────────────────

function escapeCsv(value) {
  if (value === null || value === undefined) return '';
  const str = String(value);
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function resultsToCsv(results) {
  const headers = [
    'domain',
    'final_status',
    'risk_level',
    'blocking_level',
    'readiness',
    'confidence',
    'tld_zone',
    'parent_zone',
    'action_required'
  ];

  const rows = results.map(r => {
    const d = r?.dnssec || {};
    const zones = d?.zones || [];
    const tld = zones[0]?.zone || '';
    const parent = zones.length > 1 ? zones[zones.length - 2]?.zone : '';
    return [
      r?.domain || '',
      d?.final_status || '',
      d?.executive_summary?.risk_level || '',
      d?.blocking_level || '',
      d?.readiness || '',
      d?.assessment_meta?.confidence || '',
      tld,
      parent,
      d?.executive_summary?.action_required ? 'si' : 'no'
    ].map(escapeCsv).join(',');
  });

  return [headers.join(','), ...rows].join('\n');
}

// ─── HTML ─────────────────────────────────────────────────────────────────────

const SEMAPHORE_COLORS = {
  green:   { bg: '#e8f5e9', border: '#2e7d32', text: '#1b5e20', dot: '#43a047' },
  yellow:  { bg: '#fffde7', border: '#f9a825', text: '#e65100', dot: '#fbc02d' },
  red:     { bg: '#ffebee', border: '#c62828', text: '#b71c1c', dot: '#e53935' },
  unknown: { bg: '#f5f5f5', border: '#9e9e9e', text: '#424242', dot: '#9e9e9e' }
};

function statusBadge(status) {
  const map = {
    ok:               { color: '#1b5e20', bg: '#e8f5e9', label: 'OK' },
    not_implemented:  { color: '#e65100', bg: '#fff3e0', label: 'No implementado' },
    misconfigured:    { color: '#b71c1c', bg: '#ffebee', label: 'Mal configurado' },
    blocked_at_tld:   { color: '#4a148c', bg: '#f3e5f5', label: 'Bloqueado TLD' },
    blocked_at_parent:{ color: '#1a237e', bg: '#e8eaf6', label: 'Bloqueado padre' },
    indeterminate:    { color: '#37474f', bg: '#eceff1', label: 'Indeterminado' },
    non_existent:     { color: '#757575', bg: '#f5f5f5', label: 'No existe' }
  };
  const s = map[status] || { color: '#555', bg: '#eee', label: status };
  return `<span style="background:${s.bg};color:${s.color};padding:2px 8px;border-radius:4px;font-size:12px;font-family:monospace">${s.label}</span>`;
}

function buildHtmlReport({ country, aggregate, recommendations, results = [], regionData = null, engine = 'doh', analyzedAt = null }) {
  const sem        = SEMAPHORE_COLORS[aggregate?.semaphore?.color] || SEMAPHORE_COLORS.unknown;
  const adoptionPct= aggregate?.adoption?.rate ?? 'N/D';
  const semLabel   = aggregate?.semaphore?.label || '';
  const generated  = new Date().toLocaleString('es-EC', { timeZone: 'America/Guayaquil' });
  const analysisDate = analyzedAt
    ? new Date(analyzedAt).toLocaleDateString('es-EC', { timeZone: 'America/Guayaquil', year:'numeric', month:'long', day:'numeric' })
    : generated;

  // ── Advertencias ──────────────────────────────────────────────────────────
  const warnings = aggregate?.warnings || [];

  // Muestra pequeña
  const sampleStatus = aggregate?.sampleStatus || 'reliable';
  const sampleWarning = {
    insufficient: `<strong>Muestra insuficiente (${aggregate?.total || 0} dominios):</strong> Se necesitan al menos 10 dominios para un resultado indicativo y 30 para uno confiable. El semáforo y las recomendaciones no se pueden emitir con esta muestra.`,
    indicative:   `<strong>Muestra pequeña (${aggregate?.total || 0} dominios):</strong> El resultado es indicativo, no concluyente. Se recomiendan al menos 30 dominios para un criterio de madurez confiable.`,
    reliable:     null,
  }[sampleStatus];

  // Dominios genéricos
  const genericCount  = aggregate?.genericDomains || 0;
  const countryCount  = aggregate?.countryDomains  || 0;
  const totalAnalyzed = aggregate?.total || results.length;
  const genericPct    = totalAnalyzed > 0 ? Math.round(genericCount / totalAnalyzed * 100) : 0;

  let genericWarning = null;
  if (genericCount > 0 && countryCount > 0) {
    genericWarning = `<strong>Lista mixta:</strong> ${countryCount} dominio${countryCount !== 1 ? 's' : ''} de país (ccTLD) y ${genericCount} genérico${genericCount !== 1 ? 's' : ''} (.com, .net, .org, etc. — ${genericPct}% del total). Los dominios genéricos no dependen de la infraestructura ccTLD nacional y pueden distorsionar las métricas de madurez del país.`;
  } else if (genericCount > 0 && countryCount === 0) {
    genericWarning = `<strong>Solo dominios genéricos:</strong> Todos los ${genericCount} dominios analizados son .com, .net, .org u otros TLDs genéricos. Este análisis no refleja el estado DNSSEC de un país — los dominios genéricos no tienen dependencia de la infraestructura ccTLD nacional.`;
  }

  // Construir bloque de advertencias
  const allWarnings = [sampleWarning, genericWarning, ...warnings].filter(Boolean);
  const warningsBlock = allWarnings.length > 0 ? `
<div style="background:#fffbeb;border:2px solid #fcd34d;border-radius:8px;padding:16px 20px;margin:0 0 24px">
  <div style="font-weight:600;color:#92400e;margin-bottom:8px;font-size:14px">Advertencias sobre esta muestra</div>
  ${allWarnings.map(w => `<p style="font-size:13px;color:#78350f;margin:4px 0">• ${w}</p>`).join('')}
</div>` : '';

  // ── Dominio genérico en tabla ─────────────────────────────────────────────
  const GENERIC_TLDS = new Set(['com','net','org','io','co','info','biz','edu','int','gov','mil','mobi','name','pro']);
  function domainType(domain) {
    const parts = (domain || '').split('.');
    const tld = parts[parts.length - 1]?.toLowerCase();
    if (!tld) return 'unknown';
    if (tld.length === 2) return 'country';
    if (GENERIC_TLDS.has(tld)) return 'generic';
    return 'other';
  }

  const domainRows = results.slice(0, 200).map(r => {
    const d    = r?.dnssec || {};
    const tipo = domainType(r?.domain);
    const genericBadge = tipo === 'generic'
      ? '<span style="font-size:10px;color:#9ca3af;margin-left:4px">(genérico)</span>'
      : '';
    return `<tr>
      <td style="padding:4px 10px;font-family:monospace;font-size:13px">${r?.domain || ''}${genericBadge}</td>
      <td style="padding:4px 10px">${statusBadge(d?.final_status)}</td>
      <td style="padding:4px 10px;font-size:12px;color:#555">${d?.assessment_meta?.confidence || ''}</td>
    </tr>`;
  }).join('');

  // ── Disclaimer correcto por motor ─────────────────────────────────────────
  const engineLabel = engine === 'zonemaster'
    ? 'Motor: <strong>Zonemaster</strong> — validación criptográfica completa (DNSSEC01–DNSSEC17).'
    : 'Motor: <strong>DoH estructural</strong> — análisis de evidencia observable en DNS. No realiza validación criptográfica completa; complementar con Zonemaster para reportes oficiales.';

  // ── Indicador de confiabilidad ────────────────────────────────────────────
  const sampleBadgeHtml = {
    reliable:     '<span style="background:#dcfce7;color:#166534;font-size:11px;padding:2px 8px;border-radius:12px;font-weight:500">Muestra confiable (≥30 dominios)</span>',
    indicative:   '<span style="background:#fef3c7;color:#92400e;font-size:11px;padding:2px 8px;border-radius:12px;font-weight:500">Muestra indicativa (10–29 dominios)</span>',
    insufficient: '<span style="background:#f3f4f6;color:#6b7280;font-size:11px;padding:2px 8px;border-radius:12px;font-weight:500">Muestra insuficiente (&lt;10 dominios)</span>',
  }[sampleStatus] || '';

  const statusRows = Object.entries(aggregate?.status_distribution || {})
    .map(([s, count]) => `
      <tr>
        <td style="padding:6px 12px">${statusBadge(s)}</td>
        <td style="padding:6px 12px;text-align:right;font-weight:500">${count}</td>
        <td style="padding:6px 12px;text-align:right;color:#666">${aggregate?.total_domains > 0 ? Math.round(count / aggregate.total_domains * 100) + '%' : '-'}</td>
      </tr>`).join('');

  const policyItems   = (recommendations?.policy_actions   || []).map(a => `<li style="margin-bottom:6px">${a}</li>`).join('');
  const capacityItems = (recommendations?.capacity_actions  || []).map(a => `<li style="margin-bottom:6px">${a}</li>`).join('');
  const regionalItems = (recommendations?.regional_coordination || []).map(a => `<li style="margin-bottom:6px">${a}</li>`).join('');

  const rankingRows = (regionData?.ranking || []).slice(0, 20).map(r => `
    <tr>
      <td style="padding:5px 10px;text-align:center">${r.rank}</td>
      <td style="padding:5px 10px;font-weight:500">${r.country.toUpperCase()}</td>
      <td style="padding:5px 10px;text-align:right">${r.adoption_pct ?? '-'}%</td>
      <td style="padding:5px 10px">
        <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${SEMAPHORE_COLORS[r.semaphore]?.dot || '#999'}"></span>
        ${r.semaphore}
      </td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Reporte DNSSEC — ${country?.toUpperCase()} — ISOC LAC</title>
<style>
  body{font-family:system-ui,-apple-system,sans-serif;color:#212121;max-width:960px;margin:0 auto;padding:24px;background:#fafafa}
  h1{font-size:24px;font-weight:600;margin:0 0 4px}
  h2{font-size:18px;font-weight:500;margin:32px 0 12px;border-bottom:1px solid #e0e0e0;padding-bottom:6px}
  h3{font-size:15px;font-weight:500;color:#444;margin:20px 0 8px}
  table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e0e0e0;border-radius:6px;overflow:hidden}
  th{background:#f5f5f5;padding:8px 12px;text-align:left;font-size:13px;color:#555;font-weight:500}
  td{border-top:1px solid #f0f0f0}
  .semaphore-box{padding:20px 24px;border-radius:8px;border:2px solid ${sem.border};background:${sem.bg};display:flex;align-items:center;gap:20px;margin-bottom:24px}
  .semaphore-dot{width:48px;height:48px;border-radius:50%;background:${sem.dot};flex-shrink:0}
  .metric{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:16px;text-align:center}
  .metric-value{font-size:32px;font-weight:600;color:#212121}
  .metric-label{font-size:13px;color:#666;margin-top:4px}
  .grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:24px}
  ul{margin:0;padding-left:20px}
  .footer{margin-top:40px;font-size:12px;color:#999;border-top:1px solid #e0e0e0;padding-top:16px}
  @media(max-width:600px){.grid-3{grid-template-columns:1fr}}
</style>
</head>
<body>

<h1>Reporte DNSSEC — ${country?.toUpperCase()}</h1>
<p style="color:#666;margin:0 0 4px;font-size:14px">Mediciones ISOC LAC · Fecha de análisis: ${analysisDate}</p>
<p style="color:#666;margin:0 0 20px;font-size:13px">${engineLabel}</p>

${warningsBlock}

<div class="semaphore-box">
  <div class="semaphore-dot"></div>
  <div>
    <div style="font-size:20px;font-weight:600;color:${sem.text}">${semLabel}</div>
    <div style="font-size:14px;color:${sem.text};margin-top:4px">${aggregate?.semaphore?.description || ''}</div>
    <div style="font-size:12px;color:#666;margin-top:4px">Criterio: ${aggregate?.semaphore?.conditions || ''}</div>
  </div>
</div>

<div class="grid-3">
  <div class="metric">
    <div class="metric-value">${adoptionPct !== null ? adoptionPct + '%' : 'N/D'}</div>
    <div class="metric-label">Adopción DNSSEC</div>
  </div>
  <div class="metric">
    <div class="metric-value">${aggregate?.total_domains || 0}</div>
    <div class="metric-label">Dominios analizados</div>
    <div style="margin-top:6px">${sampleBadgeHtml}</div>
  </div>
  <div class="metric">
    <div class="metric-value">${aggregate?.barriers?.structural || 0}</div>
    <div class="metric-label">Con barrera estructural</div>
  </div>
</div>

<h2>Distribución de estados DNSSEC</h2>
<table>
  <thead><tr><th>Estado</th><th style="text-align:right">Dominios</th><th style="text-align:right">Porcentaje</th></tr></thead>
  <tbody>${statusRows}</tbody>
</table>

<h2>Barreras identificadas</h2>
<div class="grid-3">
  <div class="metric">
    <div class="metric-value" style="color:#b71c1c">${aggregate?.barriers?.structural || 0}</div>
    <div class="metric-label">Estructurales (${aggregate?.barriers?.structural_pct || 0}%)</div>
  </div>
  <div class="metric">
    <div class="metric-value" style="color:#e65100">${aggregate?.barriers?.actionable || 0}</div>
    <div class="metric-label">Accionables (${aggregate?.barriers?.actionable_pct || 0}%)</div>
  </div>
  <div class="metric">
    <div class="metric-value" style="color:#1b5e20">${aggregate?.status_distribution?.ok || 0}</div>
    <div class="metric-label">Sin barreras</div>
  </div>
</div>

${recommendations && sampleStatus !== 'insufficient' ? `
<h2>Recomendaciones de política pública</h2>
<p style="color:#555;font-size:14px">Perfil del país: <strong>${recommendations.profile_label}</strong> · Urgencia: <strong>${recommendations.urgency}</strong>${sampleStatus === 'indicative' ? ' · <em>Resultado indicativo — muestra pequeña</em>' : ''}</p>
<p style="color:#555;font-size:14px">Actor principal: ${recommendations.primary_actor}</p>

<h3>Acciones de política</h3>
<ul>${policyItems}</ul>

<h3>Acciones de capacitación</h3>
<ul>${capacityItems}</ul>

<h3>Coordinación regional</h3>
<ul>${regionalItems}</ul>
` : sampleStatus === 'insufficient' ? `
<h2>Recomendaciones de política pública</h2>
<p style="color:#92400e;font-size:14px;background:#fffbeb;padding:12px;border-radius:6px">
  La muestra es insuficiente para emitir recomendaciones de política diferenciadas. Analice al menos 30 dominios representativos del país.
</p>` : ''}

${regionData ? `
<h2>Posición regional — LAC</h2>
<p style="color:#555;font-size:14px">Adopción promedio regional: <strong>${regionData.regional_adoption?.average_pct ?? 'N/D'}%</strong></p>
<table>
  <thead><tr><th>#</th><th>País</th><th style="text-align:right">Adopción</th><th>Semáforo</th></tr></thead>
  <tbody>${rankingRows}</tbody>
</table>
` : ''}

${results.length > 0 ? `
<h2>Detalle por dominio${results.length > 200 ? ' (primeros 200)' : ''}</h2>
${genericCount > 0 ? `<p style="font-size:12px;color:#9ca3af;margin:0 0 8px">Los dominios marcados como (genérico) son .com, .net, .org u otros TLDs globales — no dependen de la infraestructura ccTLD del país analizado.</p>` : ''}
<table>
  <thead><tr><th>Dominio</th><th>Estado</th><th>Confianza</th></tr></thead>
  <tbody>${domainRows}</tbody>
</table>
` : ''}

<div class="footer">
  <p>Mediciones ISOC LAC — Sistema de análisis DNSSEC para América Latina y el Caribe.</p>
  <p>${engine === 'zonemaster'
    ? 'Análisis realizado con Zonemaster — validación criptográfica completa de la cadena DNSSEC.'
    : 'Análisis estructural mediante DoH (DNS over HTTPS). Para validación criptográfica completa, usar Zonemaster.'}</p>
  <p>Los resultados reflejan el estado en el momento del análisis y pueden variar con el tiempo.</p>
</div>
</body>
</html>`;
}

module.exports = { toJson, resultsToCsv, buildHtmlReport };
