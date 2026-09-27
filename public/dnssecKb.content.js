/**
 * Base de Conocimiento DNSSEC ("Aprender DNSSEC") — contenido estático,
 * original de Mediciones ISOC Ecuador, basado en RFC/IANA. No depende de
 * ningún servicio externo. Servido tal cual desde /public, sin backend.
 *
 * Forma: window.DNSSEC_KB = { categories: [{id,label}], guides: [...] }
 * Cada guía: { id, slug, level, category, title, minutes, summary,
 *   keywords[], sections: [{id, heading, html, collapsible?}], prevId, nextId }
 *
 * `level` es 'basico' | 'intermedio' | 'avanzado' para las 20 guías del
 * currículo (encadenadas por prevId/nextId), o 'referencia' para las
 * páginas de Glosario y Referencias, que quedan fuera de esa cadena lineal
 * y de los 3 filtros de nivel existentes (solo visibles bajo "Todos").
 */
(function () {
  'use strict';

  var categories = [
    { id: 'empieza-aqui', label: 'EMPIEZA AQUÍ' },
    { id: 'como-funciona', label: 'CÓMO FUNCIONA' },
    { id: 'registros-dnssec', label: 'REGISTROS DNSSEC' },
    { id: 'claves-criptografia', label: 'CLAVES Y CRIPTOGRAFÍA' },
    { id: 'validacion', label: 'VALIDACIÓN' },
    { id: 'problemas-frecuentes', label: 'PROBLEMAS FRECUENTES' },
    { id: 'operacion', label: 'OPERACIÓN' },
    { id: 'dnssec-en-la-raiz', label: 'DNSSEC EN LA RAÍZ' },
    { id: 'glosario', label: 'GLOSARIO' },
    { id: 'referencias', label: 'REFERENCIAS' }
  ];

  // ── Referencias completas (una sola vez, en la guía "Referencias y
  // estándares"). Las 20 guías del currículo ya NO repiten este bloque
  // completo — cada una enlaza aquí desde un "Referencias relacionadas"
  // breve (ver relatedRefsSection más abajo).
  var REFERENCE_CATALOG = [
    { code: 'RFC 4033', title: 'DNS Security Introduction and Requirements', url: 'https://www.rfc-editor.org/rfc/rfc4033',
      note: 'Introduce el modelo de DNSSEC y por qué es necesario: autenticidad e integridad de las respuestas DNS.' },
    { code: 'RFC 4034', title: 'Resource Records for the DNS Security Extensions', url: 'https://www.rfc-editor.org/rfc/rfc4034',
      note: 'Define los principales registros DNSSEC, entre ellos DNSKEY, RRSIG y DS.' },
    { code: 'RFC 4035', title: 'Protocol Modifications for the DNS Security Extensions', url: 'https://www.rfc-editor.org/rfc/rfc4035',
      note: 'Define cómo se firma y valida una respuesta DNS, y los estados Secure/Insecure/Bogus/Indeterminate.' },
    { code: 'RFC 5011', title: 'Automated Updates of DNS Security (DNSSEC) Trust Anchors', url: 'https://www.rfc-editor.org/rfc/rfc5011',
      note: 'Describe cómo un resolver puede actualizar automáticamente su ancla de confianza cuando la clave raíz rota.' },
    { code: 'RFC 5155', title: 'DNS Security (DNSSEC) Hashed Authenticated Denial of Existence', url: 'https://www.rfc-editor.org/rfc/rfc5155',
      note: 'Define NSEC3, el mecanismo de negación de existencia basado en hashes.' },
    { code: 'RFC 6781', title: 'DNSSEC Operational Practices, Version 2', url: 'https://www.rfc-editor.org/rfc/rfc6781',
      note: 'Guía operativa de referencia para gestión de claves, rollover y separación KSK/ZSK/CSK.' },
    { code: 'RFC 7344', title: 'Automating DNSSEC Delegation Trust Maintenance', url: 'https://www.rfc-editor.org/rfc/rfc7344',
      note: 'Define CDS y CDNSKEY, usados para automatizar la actualización del DS en la zona padre.' },
    { code: 'RFC 8078', title: 'Managing DS Records from the Parent via CDS/CDNSKEY', url: 'https://www.rfc-editor.org/rfc/rfc8078',
      note: 'Complementa RFC 7344 con el procedimiento concreto que sigue el operador del padre.' },
    { code: 'RFC 9276 / BCP 236', title: 'Guidance for NSEC3 Parameter Settings', url: 'https://www.rfc-editor.org/rfc/rfc9276',
      note: 'Recomienda cuándo usar NSEC3 frente a NSEC y cómo configurar sus parámetros — base de la precisión de esta Base de Conocimiento sobre NSEC3.' },
    { code: 'RFC 9364 / BCP 237', title: 'DNS Security Extensions (DNSSEC)', url: 'https://www.rfc-editor.org/rfc/rfc9364',
      note: 'Guía de despliegue de DNSSEC como práctica recomendada de Internet (BCP).' },
    { code: 'RFC 9499 / BCP 219', title: 'DNS Terminology', url: 'https://www.rfc-editor.org/rfc/rfc9499',
      note: 'Vocabulario DNS/DNSSEC de referencia usado para mantener consistencia terminológica en toda la Base de Conocimiento.' },
    { code: 'RFC 9904', title: 'DNSSEC Cryptographic Algorithm Recommendation Update Process', url: 'https://www.rfc-editor.org/rfc/rfc9904',
      note: 'Reemplaza a RFC 8624; establece el proceso vigente para requisitos de algoritmos criptográficos (sin fijar una lista estática).' }
  ];

  var IANA_REGISTRIES = [
    { title: 'IANA — DNSSEC Algorithm Numbers', url: 'https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml',
      note: 'Registro autoritativo y siempre actualizado de algoritmos DNSSEC — referencia en vez de una lista fija en esta Base de Conocimiento.' },
    { title: 'IANA — DS Digest Algorithms (DS RR Types)', url: 'https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml',
      note: 'Registro de algoritmos de digest usados en registros DS.' },
    { title: 'IANA — DNS Root Trust Anchors', url: 'https://www.iana.org/dnssec/files',
      note: 'Publicación oficial del ancla de confianza de la zona raíz.' }
  ];

  function refByCode(code) {
    for (var i = 0; i < REFERENCE_CATALOG.length; i++) {
      if (REFERENCE_CATALOG[i].code === code) return REFERENCE_CATALOG[i];
    }
    return null;
  }

  // Bloque breve, reutilizado al final de cada una de las 20 guías del
  // currículo: solo los códigos relevantes para esa guía + enlace a la
  // página central de Referencias (evita repetir la lista completa 20 veces).
  function relatedRefsSection(sectionId, codes) {
    var items = codes.map(function (code) {
      return '<li>' + code + '</li>';
    }).join('');
    return {
      id: sectionId,
      heading: 'Referencias relacionadas',
      html:
        '<ul class="list-disc pl-5 text-sm text-gray-600 space-y-0.5 mb-2">' + items + '</ul>' +
        '<a href="#/dnssec/aprender/referencias" class="text-sm font-semibold text-blue-700 hover:underline">Ver todas las referencias →</a>'
    };
  }

  var guides = [

    // ═══════════════════════ BÁSICO ═══════════════════════
    {
      id: 'que-es-dnssec', slug: 'que-es-dnssec', level: 'basico', category: 'empieza-aqui',
      title: 'Introducción a DNSSEC', minutes: 10,
      summary: 'Qué es DNSSEC, en una frase, y por qué existe.',
      keywords: ['dnssec', 'introducción', 'firma digital', 'autenticidad'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>DNSSEC (DNS Security Extensions) es un conjunto de extensiones al DNS que permite ' +
          'verificar, mediante firmas digitales, que una respuesta DNS proviene realmente del ' +
          'dueño de la zona consultada y que no fue alterada en el camino.</p>' },
        { id: 'que-significa', heading: 'Qué significa', html:
          '<p>El DNS tradicional no tiene forma de comprobar la autenticidad de una respuesta: ' +
          'un resolver simplemente confía en lo que recibe. DNSSEC agrega una capa de firma ' +
          'criptográfica sobre los registros DNS existentes, sin cambiar cómo funciona el DNS en sí.</p>' },
        { id: 'para-que-sirve', heading: 'Para qué sirve', html:
          '<p>Permite detectar respuestas DNS falsificadas o manipuladas (por ejemplo, ataques de ' +
          'envenenamiento de caché o de intermediario) antes de que un usuario final las reciba como válidas.</p>' },
        { id: 'como-funciona', heading: 'Cómo funciona', html:
          '<p>Cada zona firmada publica claves públicas (DNSKEY) y firmas (RRSIG) sobre sus registros. ' +
          'Un resolver validador reconstruye una cadena de confianza desde un ancla conocida hasta la zona ' +
          'consultada, verificando cada firma en el camino.</p>' },
        { id: 'que-puede-salir-mal', heading: 'Qué puede salir mal', html:
          '<p>Una firma vencida, una clave mal configurada, o una cadena de confianza rota entre ' +
          'zona padre e hija puede hacer que las respuestas de una zona firmada dejen de validar, ' +
          'incluso si el contenido DNS en sí es correcto.</p>' },
        { id: 'relacion-herramienta', heading: 'Relación con nuestra herramienta de medición', html:
          '<p>El analizador DNSSEC de este portal evalúa exactamente estos elementos — firmas, claves, ' +
          'delegación — y resume el resultado en un estado operativo propio (distinto de los 4 conceptos ' +
          'estándar de validación, ver la guía "Estados de validación DNSSEC").</p>' },
        relatedRefsSection('referencias-relacionadas', ['RFC 4033'])
      ],
      prevId: null, nextId: 'como-funciona-el-dns'
    },
    {
      id: 'como-funciona-el-dns', slug: 'como-funciona-el-dns', level: 'basico', category: 'empieza-aqui',
      title: 'Cómo funciona el DNS', minutes: 8,
      summary: 'Bases del sistema de nombres de dominio, antes de hablar de DNSSEC.',
      keywords: ['dns', 'resolución', 'zonas', 'delegación'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>El DNS traduce nombres de dominio (como isoc.org.ec) a direcciones IP, mediante un ' +
          'sistema jerárquico y distribuido de servidores.</p>' },
        { id: 'jerarquia', heading: 'Jerarquía y delegación', html:
          '<p>La jerarquía parte de la zona raíz (".") y se delega hacia abajo: la raíz delega ".ec" ' +
          'al operador del ccTLD ecuatoriano, este delega "org.ec" a Internet Society Ecuador, y así ' +
          'sucesivamente. Cada nivel es una "zona" administrada de forma independiente.</p>' },
        { id: 'diagrama-cadena', heading: 'Diagrama: cadena de delegación', html:
          '<div role="img" aria-label="Diagrama de la cadena de delegación DNS desde la raíz hasta isoc.org.ec, pasando por .ec y org.ec" ' +
          'style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding:12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;">' +
          '<span style="padding:6px 10px;border:1px solid #cbd5e1;border-radius:6px;background:#fff;font-family:monospace;">Raíz ( . )</span>' +
          '<span aria-hidden="true">→</span>' +
          '<span style="padding:6px 10px;border:1px solid #cbd5e1;border-radius:6px;background:#fff;font-family:monospace;">.ec</span>' +
          '<span aria-hidden="true">→</span>' +
          '<span style="padding:6px 10px;border:1px solid #cbd5e1;border-radius:6px;background:#fff;font-family:monospace;">org.ec</span>' +
          '<span aria-hidden="true">→</span>' +
          '<span style="padding:6px 10px;border:1px solid #2563eb;border-radius:6px;background:#eff6ff;font-family:monospace;">isoc.org.ec</span>' +
          '</div>' },
        { id: 'no-cifra', heading: 'Qué no protege el DNS (ni DNSSEC)', html:
          '<p>El DNS tradicional no autentica ni cifra nada. Es importante notar desde ya que ' +
          '<strong>DNSSEC tampoco cifra las consultas DNS</strong> — solo firma las respuestas para que ' +
          'se pueda verificar su autenticidad; quien observe el tráfico sigue viendo qué dominios se consultan.</p>' },
        relatedRefsSection('referencias-relacionadas', ['RFC 9499 / BCP 219'])
      ],
      prevId: 'que-es-dnssec', nextId: 'que-problema-resuelve'
    },
    {
      id: 'que-problema-resuelve', slug: 'que-problema-resuelve', level: 'basico', category: 'empieza-aqui',
      title: '¿Qué problema resuelve DNSSEC?', minutes: 8,
      summary: 'El problema concreto de confianza que motivó su diseño.',
      keywords: ['problema', 'spoofing', 'envenenamiento de caché', 'kaminsky'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>Sin DNSSEC, cualquier respuesta DNS que "parezca" venir del servidor correcto es aceptada ' +
          'por el resolver, incluso si en realidad fue inyectada por un atacante.</p>' },
        { id: 'que-significa', heading: 'Qué significa en la práctica', html:
          '<p>Un atacante que logre insertar una respuesta falsa en el momento oportuno (por ejemplo, ' +
          'mediante envenenamiento de caché) puede redirigir a un usuario hacia un servidor distinto ' +
          'del legítimo, sin que el usuario ni su resolver lo perciban.</p>' },
        { id: 'para-que-sirve', heading: 'Para qué sirve DNSSEC aquí', html:
          '<p>DNSSEC permite que el resolver rechace cualquier respuesta cuya firma no valide contra ' +
          'la cadena de confianza esperada, cerrando esta clase de ataque de suplantación.</p>' },
        { id: 'que-puede-salir-mal', heading: 'Qué puede salir mal', html:
          '<p>DNSSEC no elimina otros vectores de ataque (por ejemplo, contra el propio usuario o ' +
          'contra el servidor autoritativo) — resuelve específicamente la autenticidad de la respuesta DNS.</p>' },
        relatedRefsSection('referencias-relacionadas', ['RFC 4033'])
      ],
      prevId: 'como-funciona-el-dns', nextId: 'que-protege-dnssec'
    },
    {
      id: 'que-protege-dnssec', slug: 'que-protege-dnssec', level: 'basico', category: 'empieza-aqui',
      title: '¿Qué protege DNSSEC?', minutes: 8,
      summary: 'Autenticidad e integridad de las respuestas DNS.',
      keywords: ['integridad', 'autenticidad', 'protección'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>DNSSEC protege dos propiedades concretas de una respuesta DNS: que provenga realmente ' +
          'de quien dice ser dueño de la zona (autenticidad de origen) y que no haya sido modificada ' +
          'en tránsito (integridad de los datos).</p>' },
        { id: 'como-funciona', heading: 'Cómo lo logra', html:
          '<p>Mediante firmas digitales (RRSIG) sobre conjuntos de registros (RRset), verificables con ' +
          'la clave pública de la zona (DNSKEY), y una cadena de confianza que conecta esa clave con ' +
          'un ancla de confianza superior.</p>' },
        { id: 'ejemplo', heading: 'Ejemplo conceptual', html:
          '<p>Si alguien intenta responder que "banco.example" apunta a una IP distinta de la real, ' +
          'un resolver validador rechazará esa respuesta porque no vendrá acompañada de una firma válida.</p>' },
        relatedRefsSection('referencias-relacionadas', ['RFC 4033', 'RFC 4035'])
      ],
      prevId: 'que-problema-resuelve', nextId: 'que-no-protege-dnssec'
    },
    {
      id: 'que-no-protege-dnssec', slug: 'que-no-protege-dnssec', level: 'basico', category: 'empieza-aqui',
      title: '¿Qué no protege DNSSEC?', minutes: 8,
      summary: 'Límites explícitos: qué queda fuera de su alcance.',
      keywords: ['límites', 'confidencialidad', 'cifrado', 'disponibilidad'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>DNSSEC no protege la confidencialidad de las consultas, no protege contra denegación de ' +
          'servicio, y no protege el contenido de las conexiones que se establecen después de la resolución ' +
          '(por ejemplo, el tráfico web en sí).</p>' },
        { id: 'no-cifra', heading: 'DNSSEC no cifra las consultas', html:
          '<p><strong>Esta es una precisión importante y frecuentemente confundida:</strong> DNSSEC firma ' +
          'las respuestas para que se puedan verificar, pero no las cifra. Cualquiera que observe el tráfico ' +
          'de red sigue viendo qué dominios se están consultando. Para confidencialidad de las consultas se ' +
          'necesitan mecanismos distintos (ver la guía "DNSSEC, HTTPS y DNS cifrado").</p>' },
        { id: 'no-disponibilidad', heading: 'No protege la disponibilidad', html:
          '<p>Un ataque de denegación de servicio contra los servidores DNS de una zona firmada sigue ' +
          'siendo posible; DNSSEC no es un mecanismo de disponibilidad.</p>' },
        { id: 'no-transporte', heading: 'No protege lo que ocurre después de resolver', html:
          '<p>Una vez resuelto correctamente un nombre a una IP, la seguridad de la conexión que se ' +
          'establece con esa IP (por ejemplo, si usa HTTPS y con qué certificado) es un problema aparte.</p>' },
        relatedRefsSection('referencias-relacionadas', ['RFC 9364 / BCP 237'])
      ],
      prevId: 'que-protege-dnssec', nextId: 'cadena-de-confianza'
    },
    {
      id: 'cadena-de-confianza', slug: 'cadena-de-confianza', level: 'basico', category: 'empieza-aqui',
      title: 'Cadena de confianza', minutes: 12,
      summary: 'Cómo se conecta la confianza desde la raíz hasta un dominio firmado.',
      keywords: ['cadena de confianza', 'trust anchor', 'delegación segura', 'ds'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>La cadena de confianza es la secuencia de verificaciones criptográficas que conecta un ' +
          'ancla de confianza (trust anchor) conocida de antemano con la zona que finalmente se quiere validar.</p>' },
        { id: 'como-funciona', heading: 'Cómo funciona', html:
          '<p>Cada zona padre publica un registro DS que referencia (mediante un hash) una clave DNSKEY ' +
          'de la zona hija. Un resolver validador sigue esa cadena de referencias DS→DNSKEY desde la raíz ' +
          'hasta el dominio consultado, verificando cada eslabón.</p>' +
          '<p><strong>Precisión importante:</strong> el registro DS vive en la zona padre y referencia ' +
          'criptográficamente (mediante un digest) una clave DNSKEY de la zona hija — el DS no firma la ' +
          'zona hija, solo la vincula de forma verificable con su padre.</p>' },
        { id: 'diagrama', heading: 'Diagrama: cadena de confianza para isoc.org.ec', html:
          '<div role="img" aria-label="Ancla de confianza, luego raíz, luego punto ec mediante DS, luego org punto ec mediante DS, luego isoc punto org punto ec mediante DS, terminando en DNSKEY y RRSIG de isoc.org.ec" ' +
          'style="display:flex;flex-wrap:wrap;align-items:center;gap:6px;padding:12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;font-size:13px;">' +
          '<span style="padding:6px 10px;border:1px solid #94a3b8;border-radius:6px;background:#fff;">Ancla de confianza</span>' +
          '<span aria-hidden="true">→</span>' +
          '<span style="padding:6px 10px;border:1px solid #cbd5e1;border-radius:6px;background:#fff;font-family:monospace;">.</span>' +
          '<span aria-hidden="true">(DS)→</span>' +
          '<span style="padding:6px 10px;border:1px solid #cbd5e1;border-radius:6px;background:#fff;font-family:monospace;">.ec</span>' +
          '<span aria-hidden="true">(DS)→</span>' +
          '<span style="padding:6px 10px;border:1px solid #cbd5e1;border-radius:6px;background:#fff;font-family:monospace;">org.ec</span>' +
          '<span aria-hidden="true">(DS)→</span>' +
          '<span style="padding:6px 10px;border:1px solid #2563eb;border-radius:6px;background:#eff6ff;font-family:monospace;">isoc.org.ec</span>' +
          '<span aria-hidden="true">→</span>' +
          '<span style="padding:6px 10px;border:1px solid #16a34a;border-radius:6px;background:#f0fdf4;font-family:monospace;">DNSKEY + RRSIG</span>' +
          '</div>' },
        { id: 'que-puede-salir-mal', heading: 'Qué puede salir mal', html:
          '<p>Si un solo eslabón falla — por ejemplo, el DS en el padre no coincide con ningún DNSKEY ' +
          'del hijo — toda la cadena se rompe desde ese punto hacia abajo, aunque la zona hija esté ' +
          'correctamente firmada en sí misma.</p>' },
        relatedRefsSection('referencias-relacionadas', ['RFC 4034', 'RFC 4035'])
      ],
      prevId: 'que-no-protege-dnssec', nextId: 'dnssec-https-dns-cifrado'
    },
    {
      id: 'dnssec-https-dns-cifrado', slug: 'dnssec-https-dns-cifrado', level: 'basico', category: 'empieza-aqui',
      title: 'DNSSEC, HTTPS y DNS cifrado', minutes: 10,
      summary: 'En qué se parecen y en qué no DNSSEC, HTTPS y DoH/DoT.',
      keywords: ['https', 'doh', 'dot', 'dns cifrado', 'diferencias'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>DNSSEC, HTTPS y el "DNS cifrado" (DoH/DoT) resuelven problemas distintos y no son ' +
          'sustitutos entre sí.</p>' },
        { id: 'dnssec-vs-https', heading: 'DNSSEC vs. HTTPS', html:
          '<p>HTTPS protege la confidencialidad e integridad de una conexión web ya establecida hacia ' +
          'una IP. DNSSEC protege la autenticidad de la respuesta DNS que llevó a esa IP en primer lugar. ' +
          'Un sitio puede tener HTTPS sin DNSSEC, o DNSSEC sin HTTPS — son capas independientes.</p>' },
        { id: 'dnssec-vs-doh', heading: 'DNSSEC vs. DoH/DoT (DNS cifrado)', html:
          '<p>DoH (DNS over HTTPS) y DoT (DNS over TLS) cifran el transporte entre un cliente y su ' +
          'resolver, protegiendo la confidencialidad de la consulta frente a observadores en esa ruta. ' +
          'Ninguno de los dos verifica la autenticidad del contenido de la respuesta — eso sigue siendo ' +
          'responsabilidad de DNSSEC. Son mecanismos complementarios, no equivalentes.</p>' },
        { id: 'detalle-tecnico', heading: 'Detalle técnico: los bits AD y CD', html:
          '<p>El bit AD ("Authenticated Data") en una respuesta DNS indica que el resolver validó la ' +
          'cadena DNSSEC exitosamente. El bit CD ("Checking Disabled"), en una consulta, le pide al ' +
          'resolver que no valide DNSSEC y devuelva la respuesta igual, típico en herramientas de diagnóstico.</p>',
          collapsible: true },
        relatedRefsSection('referencias-relacionadas', ['RFC 9499 / BCP 219'])
      ],
      prevId: 'cadena-de-confianza', nextId: 'rrset-y-firmas'
    },

    // ═══════════════════════ INTERMEDIO ═══════════════════════
    {
      id: 'rrset-y-firmas', slug: 'rrset-y-firmas', level: 'intermedio', category: 'como-funciona',
      title: 'RRsets y firmas digitales', minutes: 12,
      summary: 'La unidad que DNSSEC realmente firma: el conjunto de registros.',
      keywords: ['rrset', 'firma', 'rrsig'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>DNSSEC no firma registros individuales, sino "RRsets" — el conjunto completo de registros ' +
          'del mismo nombre y tipo (por ejemplo, todos los registros A de un nombre juntos).</p>' },
        { id: 'como-funciona', heading: 'Cómo funciona', html:
          '<p>Un RRSIG cubre un RRset completo. Si ese RRset cambia (se agrega o quita un registro), ' +
          'la firma debe regenerarse para el conjunto completo, no para el registro individual.</p>' },
        { id: 'relacion-herramienta', heading: 'Relación con nuestra herramienta de medición', html:
          '<p>Cuando el analizador reporta zonas y su estado de firma, evalúa exactamente la presencia ' +
          'y validez de estos RRSIG sobre los RRsets relevantes de cada zona en la cadena.</p>' },
        relatedRefsSection('referencias-relacionadas', ['RFC 4034'])
      ],
      prevId: 'dnssec-https-dns-cifrado', nextId: 'dnskey-ds-rrsig'
    },
    {
      id: 'dnskey-ds-rrsig', slug: 'dnskey-ds-rrsig', level: 'intermedio', category: 'registros-dnssec',
      title: 'DNSKEY, DS y RRSIG', minutes: 15,
      summary: 'Los tres registros centrales de DNSSEC, explicados por separado.',
      keywords: ['dnskey', 'ds', 'rrsig', 'registros'],
      sections: [
        { id: 'dnskey-explicacion', heading: 'DNSKEY — explicación breve', html:
          '<p>Publica la clave pública de una zona. Cualquiera puede usarla para verificar las firmas ' +
          '(RRSIG) generadas con la clave privada correspondiente.</p>' },
        { id: 'dnskey-detalle', heading: 'DNSKEY — detalle técnico', html:
          '<p>Cada DNSKEY incluye: flags (bit 256 = ZSK, bit 257 = SEP/KSK), protocolo (siempre 3), ' +
          'algoritmo (ver IANA DNSSEC Algorithm Numbers), la clave pública en sí, y un Key Tag derivado ' +
          '(identificador corto de 16 bits usado para referenciar la clave desde un RRSIG o un DS).</p>',
          collapsible: true },
        { id: 'ds-explicacion', heading: 'DS — explicación breve', html:
          '<p>El registro DS ("Delegation Signer") vive en la zona <strong>padre</strong> y contiene ' +
          'un hash (digest) de una DNSKEY de la zona <strong>hija</strong>, permitiendo verificar esa ' +
          'clave sin tener que confiar ciegamente en la zona hija.</p>' },
        { id: 'ds-detalle', heading: 'DS — detalle técnico', html:
          '<p>Un DS incluye: Key Tag (referenciando la DNSKEY correspondiente), algoritmo, tipo de ' +
          'digest (ver IANA DS Digest Algorithms) y el digest en sí. <strong>El DS no firma la zona ' +
          'hija</strong> — únicamente referencia de forma verificable una de sus claves públicas.</p>',
          collapsible: true },
        { id: 'rrsig-explicacion', heading: 'RRSIG — explicación breve', html:
          '<p>Es la firma digital sobre un RRset. Permite comprobar que ese conjunto de registros fue ' +
          'generado por quien posee la clave privada correspondiente y que no fue alterado.</p>' },
        { id: 'rrsig-detalle', heading: 'RRSIG — detalle técnico', html:
          '<p>Incluye: tipo de registro cubierto, algoritmo, número de etiquetas, TTL original, fecha de ' +
          'expiración e inicio de validez, Key Tag de la DNSKEY firmante, nombre de la zona firmante, y ' +
          'la firma en sí.</p>',
          collapsible: true },
        relatedRefsSection('referencias-relacionadas', ['RFC 4034', 'RFC 4035'])
      ],
      prevId: 'rrset-y-firmas', nextId: 'nsec-y-nsec3'
    },
    {
      id: 'nsec-y-nsec3', slug: 'nsec-y-nsec3', level: 'intermedio', category: 'registros-dnssec',
      title: 'NSEC y NSEC3', minutes: 15,
      summary: 'Cómo demuestra DNSSEC que algo no existe.',
      keywords: ['nsec', 'nsec3', 'negación de existencia', 'nsec3param'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>DNS necesita poder demostrar de forma autenticada no solo que algo existe, sino también ' +
          'que un nombre <em>no</em> existe (negación de existencia). NSEC y NSEC3 son los dos mecanismos ' +
          'que lo permiten bajo DNSSEC.</p>' },
        { id: 'nsec', heading: 'NSEC', html:
          '<p>NSEC enlaza cada nombre existente con el "siguiente" nombre en orden canónico de la zona, ' +
          'firmado. Si una consulta cae entre dos nombres consecutivos, el NSEC firmado demuestra que no ' +
          'hay nada en ese hueco. Efecto secundario: permite enumerar todos los nombres de la zona ' +
          '("zone walking"), recorriendo los enlaces NSEC uno por uno.</p>' },
        { id: 'nsec3', heading: 'NSEC3', html:
          '<p>NSEC3 usa hashes de los nombres en vez de los nombres en sí, dificultando la enumeración ' +
          'directa de la zona. Se configura mediante NSEC3PARAM (algoritmo de hash, iteraciones, salt).</p>' },
        { id: 'precision-nsec3', heading: 'Precisión importante: NSEC3 no es automáticamente mejor', html:
          '<p><strong>NSEC3 no debe presentarse como una mejora automática sobre NSEC.</strong> Según ' +
          'RFC 9276 / BCP 236, se recomienda preferir NSEC cuando no se necesita específicamente la ' +
          'opacidad frente a enumeración que ofrece NSEC3, ya que NSEC3 con iteraciones altas añade ' +
          'costo computacional de validación sin beneficio adicional. La elección depende del caso de uso.</p>' },
        relatedRefsSection('referencias-relacionadas', ['RFC 5155', 'RFC 9276 / BCP 236'])
      ],
      prevId: 'dnskey-ds-rrsig', nextId: 'estados-de-validacion-dnssec'
    },
    {
      id: 'estados-de-validacion-dnssec', slug: 'estados-de-validacion-dnssec', level: 'intermedio', category: 'validacion',
      title: 'Estados de validación DNSSEC', minutes: 12,
      summary: 'Secure, Insecure, Bogus e Indeterminate — y cómo se relacionan con nuestra taxonomía propia.',
      keywords: ['secure', 'insecure', 'bogus', 'indeterminate', 'estados', 'taxonomía'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>La validación DNSSEC de un resolver produce, conceptualmente, uno de cuatro resultados ' +
          'estándar definidos por el protocolo (RFC 4035 y RFC 9499): Secure, Insecure, Bogus e Indeterminate.</p>' },
        { id: 'los-cuatro-estados', heading: 'Los cuatro estados estándar', html:
          '<ul class="list-disc pl-5 space-y-1">' +
          '<li><strong>Secure:</strong> la cadena de confianza validó correctamente de punta a punta.</li>' +
          '<li><strong>Insecure:</strong> la zona, de forma legítima y verificada, no está firmada — no ' +
          'hay una cadena DS que la conecte con un ancla de confianza, y eso es intencional (no es un error).</li>' +
          '<li><strong>Bogus:</strong> hay firmas o delegación DNSSEC presentes, pero la validación falla ' +
          '(firma vencida, DS que no coincide, etc.) — indica un problema real.</li>' +
          '<li><strong>Indeterminate:</strong> el resolver no cuenta con información suficiente para ' +
          'decidir (por ejemplo, no tiene un ancla de confianza configurada).</li>' +
          '</ul>' },
        { id: 'precision-taxonomia', heading: 'Importante: esto no es la taxonomía operativa de Mediciones', html:
          '<p>Estos 4 conceptos son el modelo estándar de validación DNSSEC del protocolo. ' +
          '<strong>Nuestra herramienta de análisis usa una taxonomía operativa propia, más detallada, con ' +
          'sus propios estados</strong> (por ejemplo, distinguiendo bloqueos en el TLD de bloqueos en la ' +
          'zona padre, o separando "no implementado" de "mal configurado"). Son dos vocabularios distintos ' +
          'que describen fenómenos relacionados pero no deben confundirse ni mezclarse: la taxonomía de la ' +
          'herramienta es una clasificación diagnóstica más granular, no un reemplazo de los 4 conceptos ' +
          'estándar ni viceversa.</p>' },
        relatedRefsSection('referencias-relacionadas', ['RFC 4035', 'RFC 9499 / BCP 219'])
      ],
      prevId: 'nsec-y-nsec3', nextId: 'interpretar-medicion-dnssec'
    },
    {
      id: 'interpretar-medicion-dnssec', slug: 'interpretar-medicion-dnssec', level: 'intermedio', category: 'validacion',
      title: 'Cómo interpretar una medición DNSSEC', minutes: 15,
      summary: 'Las tres preguntas que responde nuestro analizador.',
      keywords: ['interpretar', 'resultado', 'análisis', 'medición'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>El analizador DNSSEC de este portal organiza su resultado alrededor de tres preguntas ' +
          'concretas, en orden.</p>' },
        { id: 'pregunta-1', heading: '1. ¿Está la zona firmada?', html:
          '<p>¿Existen registros DNSKEY y RRSIG para el dominio consultado? Si no, el resultado apunta ' +
          'a "no implementado" — DNSSEC simplemente no está en uso todavía.</p>' },
        { id: 'pregunta-2', heading: '2. ¿Hay delegación segura?', html:
          '<p>Si la zona está firmada, ¿existe un DS correcto en la zona padre que la referencie? Sin ' +
          'esto, aunque la zona esté firmada, la cadena de confianza no puede construirse desde arriba.</p>' },
        { id: 'pregunta-3', heading: '3. ¿Puede validar la cadena completa?', html:
          '<p>Con firma y delegación presentes, ¿validan efectivamente todos los eslabones, desde el ' +
          'ancla de confianza hasta el dominio? Un fallo aquí (firma vencida, DS que no coincide con ' +
          'ninguna DNSKEY) es lo que nuestra taxonomía marca como configuración incorrecta.</p>' },
        { id: 'relacion-herramienta', heading: 'Relación con el resto de la Base de Conocimiento', html:
          '<p>Cada uno de los enlaces "ⓘ" junto a los resultados del analizador lleva directamente a la ' +
          'guía relevante para esa pregunta específica.</p>' },
        relatedRefsSection('referencias-relacionadas', ['RFC 4035'])
      ],
      prevId: 'estados-de-validacion-dnssec', nextId: 'key-tag-y-digest'
    },
    {
      id: 'key-tag-y-digest', slug: 'key-tag-y-digest', level: 'intermedio', category: 'claves-criptografia',
      title: 'Key Tag y digest', minutes: 12,
      summary: 'Los identificadores cortos que conectan DS, DNSKEY y RRSIG entre sí.',
      keywords: ['key tag', 'digest', 'hash'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>El Key Tag es un número corto (16 bits) calculado a partir de una DNSKEY, usado como ' +
          'referencia rápida hacia esa clave desde un RRSIG o un DS, sin tener que incluir la clave completa.</p>' },
        { id: 'detalle-tecnico', heading: 'Detalle técnico', html:
          '<p>El Key Tag no identifica de forma única una clave (pueden existir colisiones), por lo que ' +
          'siempre se usa junto con el algoritmo para desambiguar. El "digest" de un DS es un hash ' +
          '(por ejemplo SHA-256) calculado sobre el nombre del propietario y el contenido completo de la ' +
          'DNSKEY referenciada — es este digest, no el Key Tag, el que efectivamente vincula de forma ' +
          'criptográfica el DS con su DNSKEY.</p>',
          collapsible: true },
        relatedRefsSection('referencias-relacionadas', ['RFC 4034'])
      ],
      prevId: 'interpretar-medicion-dnssec', nextId: 'ksk-zsk-csk'
    },

    // ═══════════════════════ AVANZADO ═══════════════════════
    {
      id: 'ksk-zsk-csk', slug: 'ksk-zsk-csk', level: 'avanzado', category: 'claves-criptografia',
      title: 'KSK, ZSK y CSK', minutes: 18,
      summary: 'Separación de claves — una práctica común, no un requisito del protocolo.',
      keywords: ['ksk', 'zsk', 'csk', 'claves'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>Muchas zonas usan dos claves con roles distintos: una KSK (Key Signing Key) que firma ' +
          'solo el conjunto de DNSKEY, y una ZSK (Zone Signing Key) que firma el resto de los RRsets ' +
          'de la zona.</p>' },
        { id: 'por-que-separar', heading: 'Por qué se separan (cuando se separan)', html:
          '<p>Permite rotar la ZSK con frecuencia (menor impacto operativo, ya que no requiere ' +
          'actualizar el DS en el padre) manteniendo la KSK más estable (su rotación sí implica ' +
          'actualizar el DS delegado).</p>' },
        { id: 'precision-csk', heading: 'Precisión importante: la separación no es obligatoria', html:
          '<p><strong>KSK/ZSK es una práctica operativa común, no un requisito del protocolo DNSSEC.</strong> ' +
          'Una zona puede usar una sola clave que cumple ambos roles — llamada CSK (Combined Signing Key) — ' +
          'de forma perfectamente válida. La elección entre separar claves o usar una CSK es una decisión ' +
          'operativa de la zona, no una regla técnica de DNSSEC en sí.</p>' },
        relatedRefsSection('referencias-relacionadas', ['RFC 6781'])
      ],
      prevId: 'key-tag-y-digest', nextId: 'algoritmos-dnssec'
    },
    {
      id: 'algoritmos-dnssec', slug: 'algoritmos-dnssec', level: 'avanzado', category: 'claves-criptografia',
      title: 'Algoritmos DNSSEC', minutes: 15,
      summary: 'Por qué esta guía no da una lista fija de algoritmos "recomendados".',
      keywords: ['algoritmos', 'rsa', 'ecdsa', 'eddsa', 'iana'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>DNSSEC soporta múltiples algoritmos de firma (por ejemplo, distintas variantes de RSA, ' +
          'ECDSA y EdDSA), cada uno identificado por un número de algoritmo registrado en IANA.</p>' },
        { id: 'precision-lista-fija', heading: 'Precisión importante: no existe una lista fija "recomendada"', html:
          '<p><strong>Esta guía deliberadamente no incluye una lista estática de "algoritmos recomendados".</strong> ' +
          'RFC 9904 (que reemplazó a RFC 8624) establece los requisitos de implementación vigentes, y estos ' +
          'criterios evolucionan con el tiempo a medida que ciertos algoritmos se consideran obsoletos y ' +
          'aparecen nuevos. La referencia autoritativa y siempre actualizada es el registro oficial de IANA ' +
          '(DNSSEC Algorithm Numbers) junto con el RFC vigente en el momento de la consulta — nunca una ' +
          'tabla fija congelada en esta página.</p>' },
        relatedRefsSection('referencias-relacionadas', ['RFC 9904'])
      ],
      prevId: 'ksk-zsk-csk', nextId: 'trust-anchors'
    },
    {
      id: 'trust-anchors', slug: 'trust-anchors', level: 'avanzado', category: 'validacion',
      title: 'Trust Anchors', minutes: 15,
      summary: 'El punto de partida de toda validación DNSSEC.',
      keywords: ['trust anchor', 'ancla de confianza', 'raíz'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>Un trust anchor (ancla de confianza) es una clave pública que un resolver validador ' +
          'acepta como punto de partida confiable, sin necesidad de verificarla contra nada superior.</p>' },
        { id: 'como-funciona', heading: 'Cómo funciona en la práctica', html:
          '<p>La mayoría de los resolvers validadores usan como ancla de confianza la clave pública de ' +
          'la zona raíz, publicada oficialmente por IANA y actualizada mediante el mecanismo de rollover ' +
          'automático descrito en RFC 5011.</p>' },
        relatedRefsSection('referencias-relacionadas', ['RFC 5011'])
      ],
      prevId: 'algoritmos-dnssec', nextId: 'gestion-rollover-claves'
    },
    {
      id: 'gestion-rollover-claves', slug: 'gestion-rollover-claves', level: 'avanzado', category: 'operacion',
      title: 'Gestión y rollover de claves', minutes: 25,
      summary: 'Cómo se rota una clave DNSSEC sin romper la validación.',
      keywords: ['rollover', 'rotación de claves', 'cds', 'cdnskey'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>El "rollover" es el proceso de reemplazar una clave DNSSEC (ZSK o KSK) por una nueva, ' +
          'manteniendo la validación ininterrumpida durante la transición.</p>' },
        { id: 'por-que-es-delicado', heading: 'Por qué es delicado', html:
          '<p>Mientras una firma antigua siga circulando en cachés de resolvers, la clave que la generó ' +
          'debe seguir siendo válida. Retirar una clave demasiado pronto rompe la validación para quien ' +
          'aún tenga una respuesta cacheada firmada con la clave anterior.</p>' },
        { id: 'escenario-multiples-dnskey', heading: 'Escenario: múltiples DNSKEY simultáneas', html:
          '<p>Durante un rollover es normal y esperado ver temporalmente más de una DNSKEY publicada ' +
          'para el mismo rol — la antigua y la nueva conviven mientras las cachés se renuevan.</p>',
          collapsible: true },
        { id: 'automatizacion', heading: 'Automatización del rollover de KSK (CDS/CDNSKEY)', html:
          '<p>RFC 7344 y RFC 8078 definen cómo una zona hija puede publicar registros CDS/CDNSKEY que el ' +
          'padre consulta periódicamente para actualizar el DS automáticamente, sin intervención manual ' +
          'del operador del padre en cada rotación.</p>' },
        relatedRefsSection('referencias-relacionadas', ['RFC 6781', 'RFC 7344', 'RFC 8078'])
      ],
      prevId: 'trust-anchors', nextId: 'cds-cdnskey'
    },
    {
      id: 'cds-cdnskey', slug: 'cds-cdnskey', level: 'avanzado', category: 'operacion',
      title: 'CDS y CDNSKEY', minutes: 18,
      summary: 'Registros que la zona hija publica para que el padre actualice el DS solo.',
      keywords: ['cds', 'cdnskey', 'automatización'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>CDS (Child DS) y CDNSKEY (Child DNSKEY) son registros que una zona hija publica en sí ' +
          'misma para comunicarle al operador del padre qué DS debería tener, sin necesidad de un canal ' +
          'de comunicación separado.</p>' },
        { id: 'como-funciona', heading: 'Cómo funciona', html:
          '<p>El operador del padre (o un proceso automatizado del registro) consulta periódicamente ' +
          'el CDS/CDNSKEY de sus hijas delegadas y actualiza el DS publicado cuando detecta un cambio ' +
          'consistente y verificado, siguiendo el procedimiento de RFC 7344 / RFC 8078.</p>' },
        relatedRefsSection('referencias-relacionadas', ['RFC 7344', 'RFC 8078'])
      ],
      prevId: 'gestion-rollover-claves', nextId: 'diagnostico-errores-dnssec'
    },
    {
      id: 'diagnostico-errores-dnssec', slug: 'diagnostico-errores-dnssec', level: 'avanzado', category: 'problemas-frecuentes',
      title: 'Diagnóstico de errores DNSSEC', minutes: 25,
      summary: 'Problemas frecuentes y cómo reconocerlos en un resultado de análisis.',
      keywords: ['errores', 'diagnóstico', 'problemas', 'mal configurado'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>La mayoría de los problemas DNSSEC en producción caen en un puñado de patrones reconocibles.</p>' },
        { id: 'ds-sin-dnskey', heading: 'DS sin DNSKEY coincidente', html:
          '<p>El padre publica un DS que no corresponde a ninguna DNSKEY actual de la zona hija — típico ' +
          'tras un rollover de KSK mal coordinado con el registro.</p>' },
        { id: 'firma-vencida', heading: 'Firma (RRSIG) vencida', html:
          '<p>La zona dejó de re-firmarse periódicamente y las firmas expiraron — los datos siguen ' +
          'siendo correctos, pero ya no validan.</p>' },
        { id: 'delegacion-rota', heading: 'Delegación rota entre padre e hijo', html:
          '<p>El padre no tiene DS en absoluto para una hija que sí está firmada, dejando a la hija ' +
          '"insecure" desde la perspectiva de la cadena, aunque internamente esté bien configurada.</p>' },
        { id: 'ejemplo-configuracion', heading: 'Ejemplo conceptual de una mala configuración', html:
          '<p>Un dominio renueva su ZSK pero olvida volver a firmar todos los RRsets con la nueva clave: ' +
          'el resolver encuentra un RRSIG que referencia (por Key Tag) una DNSKEY que ya no coincide con ' +
          'la firma presentada, y la validación falla.</p>' },
        { id: 'relacion-herramienta', heading: 'Relación con nuestra herramienta de medición', html:
          '<p>Cada uno de estos patrones corresponde a un estado específico de la taxonomía operativa del ' +
          'analizador (ver "Estados de validación DNSSEC" para la distinción con los 4 conceptos estándar).</p>' },
        relatedRefsSection('referencias-relacionadas', ['RFC 4035'])
      ],
      prevId: 'cds-cdnskey', nextId: 'dnssec-zona-raiz'
    },
    {
      id: 'dnssec-zona-raiz', slug: 'dnssec-zona-raiz', level: 'avanzado', category: 'dnssec-en-la-raiz',
      title: 'DNSSEC en la zona raíz', minutes: 15,
      summary: 'El ancla de todo el sistema, y por qué debe monitorearse.',
      keywords: ['zona raíz', 'root', 'iana', 'trust anchor'],
      sections: [
        { id: 'explicacion', heading: 'Explicación breve', html:
          '<p>La zona raíz (".") está firmada desde 2010 y funciona como el ancla de confianza por ' +
          'defecto de prácticamente todos los resolvers validadores del mundo.</p>' },
        { id: 'monitoreo', heading: 'DNSSEC debe monitorearse, no solo activarse', html:
          '<p>Firmar una zona una vez no es suficiente: firmas que expiran, claves que rotan y ' +
          'delegaciones que cambian requieren monitoreo continuo. Lo mismo aplica, en menor escala, a ' +
          'cualquier zona firmada — la validación de hoy no garantiza la de mañana sin mantenimiento.</p>' },
        relatedRefsSection('referencias-relacionadas', ['RFC 5011', 'RFC 9364 / BCP 237'])
      ],
      prevId: 'diagnostico-errores-dnssec', nextId: null
    },

    // ═══════════════════ REFERENCIA (fuera de la cadena básico/intermedio/avanzado) ═══════════════════
    {
      id: 'glosario-dnssec', slug: 'glosario', level: 'referencia', category: 'glosario',
      title: 'Glosario DNSSEC', minutes: 6,
      summary: 'Consulta rápidamente los principales términos utilizados en DNSSEC.',
      keywords: [
        'glosario', 'ad', 'bogus', 'cd', 'cdnskey', 'cds', 'csk', 'delegación segura', 'digest',
        'dns', 'dnskey', 'dnssec', 'ds', 'indeterminate', 'insecure', 'key tag', 'ksk',
        'nsec', 'nsec3', 'nsec3param', 'resolver', 'resolver validador', 'rollover',
        'rrset', 'rrsig', 'secure', 'trust anchor', 'zsk', 'zona', 'zona hija', 'zona padre'
      ],
      sections: [
        { id: 'intro', heading: 'Cómo usar este glosario', html:
          '<p>Términos en orden alfabético. Cada uno incluye una definición corta y, cuando existe, un ' +
          'enlace a la guía donde se explica con más detalle.</p>' },
        { id: 'terminos-a-d', heading: 'A – D', html:
          glossaryTermHtml('AD', 'Bit "Authenticated Data" en una respuesta DNS: indica que el resolver validó exitosamente la cadena DNSSEC.', 'dnssec-https-dns-cifrado', 'DNSSEC, HTTPS y DNS cifrado') +
          glossaryTermHtml('Bogus', 'Estado de validación en el que hay firmas o delegación DNSSEC presentes, pero la validación falla — indica un problema real.', 'estados-de-validacion-dnssec', 'Estados de validación DNSSEC') +
          glossaryTermHtml('CD', 'Bit "Checking Disabled" en una consulta DNS: le pide al resolver que no valide DNSSEC y devuelva la respuesta igual.', 'dnssec-https-dns-cifrado', 'DNSSEC, HTTPS y DNS cifrado') +
          glossaryTermHtml('CDNSKEY', 'Registro que la zona hija publica en sí misma con el contenido de una DNSKEY, para que el padre lo consulte y actualice el DS automáticamente.', 'cds-cdnskey', 'CDS y CDNSKEY') +
          glossaryTermHtml('CDS', 'Registro que la zona hija publica en sí misma con el DS que debería tener en el padre, permitiendo automatizar su actualización.', 'cds-cdnskey', 'CDS y CDNSKEY') +
          glossaryTermHtml('CSK', 'Combined Signing Key: una sola clave que cumple los roles de KSK y ZSK a la vez, alternativa válida a separarlas.', 'ksk-zsk-csk', 'KSK, ZSK y CSK') +
          glossaryTermHtml('Delegación segura', 'Situación en la que la zona padre publica un DS correcto que referencia una DNSKEY vigente de la zona hija, permitiendo construir la cadena de confianza.', 'cadena-de-confianza', 'Cadena de confianza') +
          glossaryTermHtml('Digest', 'Hash calculado sobre una DNSKEY, incluido en un registro DS para referenciarla de forma verificable sin incluir la clave completa.', 'key-tag-y-digest', 'Key Tag y digest') +
          glossaryTermHtml('DNS', 'Domain Name System: sistema jerárquico y distribuido que traduce nombres de dominio a direcciones IP y otros datos.', 'como-funciona-el-dns', 'Cómo funciona el DNS') +
          glossaryTermHtml('DNSKEY', 'Registro que publica la clave pública de una zona, usada para verificar las firmas (RRSIG) generadas con la clave privada correspondiente.', 'dnskey-ds-rrsig', 'DNSKEY, DS y RRSIG') +
          glossaryTermHtml('DNSSEC', 'DNS Security Extensions: extensiones al DNS que permiten verificar, mediante firmas digitales, la autenticidad e integridad de las respuestas.', 'que-es-dnssec', 'Introducción a DNSSEC') +
          glossaryTermHtml('DS', 'Delegation Signer: registro publicado en la zona padre que contiene una referencia criptográfica (digest) a una DNSKEY de la zona hija.', 'dnskey-ds-rrsig', 'DNSKEY, DS y RRSIG')
        },
        { id: 'terminos-i-n', heading: 'I – N', html:
          glossaryTermHtml('Indeterminate', 'Estado de validación en el que el resolver no cuenta con información suficiente para decidir (por ejemplo, sin ancla de confianza configurada).', 'estados-de-validacion-dnssec', 'Estados de validación DNSSEC') +
          glossaryTermHtml('Insecure', 'Estado de validación en el que la zona, de forma legítima y verificada, no está firmada — no es un error.', 'estados-de-validacion-dnssec', 'Estados de validación DNSSEC') +
          glossaryTermHtml('Key Tag', 'Identificador corto (16 bits) de una DNSKEY, usado para referenciarla rápidamente desde un RRSIG o un DS, junto con el algoritmo.', 'key-tag-y-digest', 'Key Tag y digest') +
          glossaryTermHtml('KSK', 'Key Signing Key: clave que firma únicamente el conjunto de registros DNSKEY de una zona, cuando se usa separación de claves.', 'ksk-zsk-csk', 'KSK, ZSK y CSK') +
          glossaryTermHtml('NSEC', 'Registro que enlaza cada nombre existente con el siguiente en orden canónico de la zona, usado para demostrar de forma autenticada que un nombre no existe.', 'nsec-y-nsec3', 'NSEC y NSEC3') +
          glossaryTermHtml('NSEC3', 'Variante de NSEC que usa hashes de los nombres en vez de los nombres en sí, dificultando la enumeración directa de la zona.', 'nsec-y-nsec3', 'NSEC y NSEC3') +
          glossaryTermHtml('NSEC3PARAM', 'Registro que configura los parámetros de NSEC3 en una zona (algoritmo de hash, iteraciones, salt).', 'nsec-y-nsec3', 'NSEC y NSEC3')
        },
        { id: 'terminos-r-s', heading: 'R – S', html:
          glossaryTermHtml('Resolver', 'Componente que realiza consultas DNS en nombre de un cliente y procesa las respuestas recibidas.', 'como-funciona-el-dns', 'Cómo funciona el DNS') +
          glossaryTermHtml('Resolver validador', 'Resolver que además verifica las firmas DNSSEC de las respuestas antes de aceptarlas como válidas.', 'interpretar-medicion-dnssec', 'Cómo interpretar una medición DNSSEC') +
          glossaryTermHtml('Rollover', 'Proceso de reemplazar una clave DNSSEC (ZSK o KSK) por una nueva, manteniendo la validación ininterrumpida durante la transición.', 'gestion-rollover-claves', 'Gestión y rollover de claves') +
          glossaryTermHtml('RRset', 'Conjunto completo de registros del mismo nombre y tipo — la unidad que efectivamente firma DNSSEC, no el registro individual.', 'rrset-y-firmas', 'RRsets y firmas digitales') +
          glossaryTermHtml('RRSIG', 'Firma digital sobre un RRset completo, que permite comprobar que fue generado por quien posee la clave privada correspondiente.', 'dnskey-ds-rrsig', 'DNSKEY, DS y RRSIG') +
          glossaryTermHtml('Secure', 'Estado de validación en el que la cadena de confianza validó correctamente de punta a punta.', 'estados-de-validacion-dnssec', 'Estados de validación DNSSEC')
        },
        { id: 'terminos-t-z', heading: 'T – Z', html:
          glossaryTermHtml('Trust Anchor', 'Ancla de confianza: clave pública que un resolver validador acepta como punto de partida confiable, sin verificarla contra nada superior.', 'trust-anchors', 'Trust Anchors') +
          glossaryTermHtml('ZSK', 'Zone Signing Key: clave que firma el resto de los RRsets de una zona (todo excepto el conjunto DNSKEY), cuando se usa separación de claves.', 'ksk-zsk-csk', 'KSK, ZSK y CSK') +
          glossaryTermHtml('Zona', 'Porción del espacio de nombres DNS administrada de forma independiente (por ejemplo, "org.ec").', 'como-funciona-el-dns', 'Cómo funciona el DNS') +
          glossaryTermHtml('Zona hija', 'Zona delegada por otra zona (la zona padre); en DNSSEC, la que es referenciada por un DS.', 'cadena-de-confianza', 'Cadena de confianza') +
          glossaryTermHtml('Zona padre', 'Zona que delega una parte de su espacio de nombres a otra zona (la zona hija) y publica su DS.', 'cadena-de-confianza', 'Cadena de confianza')
        },
        relatedRefsSection('referencias-relacionadas', ['RFC 9499 / BCP 219'])
      ],
      prevId: null, nextId: null
    },
    {
      id: 'referencias-estandares', slug: 'referencias', level: 'referencia', category: 'referencias',
      title: 'Referencias y estándares DNSSEC', minutes: 8,
      summary: 'RFC, BCP y registros IANA utilizados como base técnica de estas guías.',
      keywords: ['referencias', 'estándares', 'rfc', 'bcp', 'iana', 'fuentes'],
      sections: [
        { id: 'intro', heading: 'Sobre esta página', html:
          '<p>Esta página centraliza las referencias técnicas que sustentan el contenido de la Base de ' +
          'Conocimiento DNSSEC. Cada guía enlaza aquí en vez de repetir la lista completa. Solo se enlaza ' +
          'a fuentes oficiales (RFC Editor e IANA) — no se reproduce texto extenso de ningún RFC.</p>' },
        { id: 'rfcs', heading: 'RFC y BCP', html:
          REFERENCE_CATALOG.map(function (ref) {
            return '<div class="mb-3 pb-3 border-b border-gray-100 last:border-0">' +
              '<div class="font-semibold text-gray-800">' +
              '<a href="' + ref.url + '" target="_blank" rel="noopener noreferrer" class="text-blue-700 hover:underline">' + ref.code + '</a>' +
              '</div>' +
              '<div class="text-sm text-gray-600">' + ref.title + '</div>' +
              '<p class="text-sm text-gray-500 mt-1">' + ref.note + '</p>' +
              '</div>';
          }).join('')
        },
        { id: 'iana', heading: 'Registros IANA', html:
          '<ul class="space-y-3">' +
          IANA_REGISTRIES.map(function (reg) {
            return '<li><a href="' + reg.url + '" target="_blank" rel="noopener noreferrer" class="font-semibold text-blue-700 hover:underline">' + reg.title + '</a>' +
              '<p class="text-sm text-gray-500 mt-1">' + reg.note + '</p></li>';
          }).join('') +
          '</ul>'
        }
      ],
      prevId: null, nextId: null
    }
  ];

  function glossaryTermHtml(term, definition, relatedGuideId, relatedGuideTitle) {
    // relatedGuideId coincide con el slug de la guía (slug === id en todas
    // las guías del currículo), por eso se usa directo en el href.
    return '<div class="mb-3">' +
      '<div class="font-semibold text-gray-800">' + term + '</div>' +
      '<p class="text-sm text-gray-600">' + definition + '</p>' +
      (relatedGuideId ? '<a href="#/dnssec/aprender/' + relatedGuideId + '" class="text-xs font-semibold text-blue-700 hover:underline">Ver guía: ' + relatedGuideTitle + ' →</a>' : '') +
      '</div>';
  }

  window.DNSSEC_KB = { categories: categories, guides: guides };
})();
