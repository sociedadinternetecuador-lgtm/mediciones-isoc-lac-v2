'use strict';

/**
 * Policy Recommender — Módulo Agregado DNSSEC ISOC LAC
 *
 * Genera recomendaciones de política pública y capacitación
 * diferenciadas según el perfil del país y su semáforo de madurez.
 *
 * Perfiles:
 *  - tld_blocked:    TLD sin firmar; la barrera es externa al operador
 *  - low_capacity:   adopción muy baja, barreras principalmente accionables
 *  - ready_to_adopt: infraestructura lista, operadores sin actuar
 *  - leader:         adopción sólida, puede compartir experiencia regional
 *  - mixed:          combinación de barreras, requiere análisis multi-nivel
 */

const RECOMMENDATIONS = {
  tld_blocked: {
    profile_label: 'TLD sin firmar — barrera estructural externa',
    urgency: 'alta',
    primary_actor: 'Gobierno / Ministerio de Telecomunicaciones / Registry ccTLD',
    policy_actions: [
      'Gestionar ante el registry del ccTLD la firma DNSSEC de la zona raíz del país.',
      'Incluir la firma DNSSEC del TLD como requisito en el marco regulatorio de Internet.',
      'Coordinar con LACNIC e ICANN para acceder a asistencia técnica y financiera para la firma del TLD.',
      'Publicar un cronograma público de implementación DNSSEC para el ccTLD.',
      'Monitorear avance mediante mediciones periódicas (mínimo trimestral).'
    ],
    capacity_actions: [
      'Capacitar al equipo técnico del registry en operaciones DNSSEC (DNSSEC signing, KSK/ZSK rollover).',
      'Realizar talleres con LACTLD y LACNOG sobre gestión de claves DNSSEC.',
      'Documentar el procedimiento de firma para referencia futura y auditoría.'
    ],
    regional_coordination: [
      'Presentar el caso en el foro de LACTLD para compartir el proceso con otros registros.',
      'Solicitar a LACNIC mentoría de países que ya completaron la firma de su TLD.'
    ],
    references: [
      'https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en',
      'https://lactld.org',
      'https://www.lacnic.net/innovaportal/file/2042/1/dnssec-lac.pdf'
    ]
  },

  low_capacity: {
    profile_label: 'Capacidad técnica baja — adopción accionable pero sin avance',
    urgency: 'alta',
    primary_actor: 'Organismos gubernamentales TIC / Registrars / Universidades',
    policy_actions: [
      'Emitir directiva ministerial que establezca DNSSEC como requisito para dominios del Estado.',
      'Incluir DNSSEC en los pliegos técnicos de adquisición de servicios de hosting y registro de dominios.',
      'Crear incentivos para registrars que ofrezcan DNSSEC activado por defecto.',
      'Establecer fecha límite para implementación en dominios .gob con seguimiento público.'
    ],
    capacity_actions: [
      'Desarrollar programa de certificación DNSSEC para administradores de sistemas en el sector público.',
      'Crear materiales de capacitación en español adaptados al contexto LAC (guías paso a paso por registrar).',
      'Organizar hackatones o laboratorios técnicos con LACNOG para implementación práctica.',
      'Publicar casos de estudio de dominios que ya implementaron DNSSEC en el país.'
    ],
    regional_coordination: [
      'Solicitar a ISOC LAC programa de asistencia técnica directa.',
      'Participar en el programa DNS Operations de LACNIC para formación gratuita.'
    ],
    references: [
      'https://www.lacnic.net/3077/2/lacnic/capacitacion',
      'https://www.internetsociety.org/deploy360/dnssec/basics/'
    ]
  },

  ready_to_adopt: {
    profile_label: 'Listo para adoptar — infraestructura habilitada, operadores inactivos',
    urgency: 'media',
    primary_actor: 'Operadores de dominio / Registrars / Administradores de sistemas',
    policy_actions: [
      'Difundir entre organismos públicos que el TLD ya soporta DNSSEC y que la implementación es posible hoy.',
      'Incluir auditoría DNSSEC en los controles periódicos de seguridad del Estado.',
      'Promover que los registrars locales activen DNSSEC por defecto en los planes de registro.',
      'Publicar dashboard público de adopción DNSSEC para generar presión institucional positiva.'
    ],
    capacity_actions: [
      'Webinars prácticos de "DNSSEC en 30 minutos" para administradores de dominios .gob.',
      'Guía específica por registrar (ej. NIC.ec, NIC.co) con capturas de pantalla del proceso.',
      'Mesa de ayuda técnica DNSSEC habilitada por el organismo regulador.',
      'Programa de reconocimiento para organismos que implementen DNSSEC.'
    ],
    regional_coordination: [
      'Compartir el modelo de adopción con países vecinos que tengan perfil similar.',
      'Presentar en LACNOG los avances como caso de referencia regional.'
    ],
    references: [
      'https://www.internetsociety.org/deploy360/dnssec/',
      'https://dnsviz.net'
    ]
  },

  leader: {
    profile_label: 'Líder regional — adopción sólida, potencial de mentoría',
    urgency: 'baja',
    primary_actor: 'Organismos TIC / LACNIC / ISOC LAC',
    policy_actions: [
      'Mantener y mejorar el monitoreo de la tasa de adopción para detectar retrocesos.',
      'Formalizar el proceso de implementación DNSSEC como política de Estado documentada.',
      'Participar activamente en la gobernanza de DNSSEC en la región (LACNIC, LACTLD, LACNOG).',
      'Publicar métricas de adopción DNSSEC como indicador de transparencia de Internet.'
    ],
    capacity_actions: [
      'Documentar el proceso de adopción como caso de estudio replicable para la región.',
      'Ofrecer mentoría técnica a países con perfil low_capacity o ready_to_adopt.',
      'Desarrollar materiales educativos propios y compartirlos con la comunidad LAC.'
    ],
    regional_coordination: [
      'Proponer en LACNIC un programa de mentoría sur-sur para DNSSEC.',
      'Presentar resultados en foros internacionales (RIPE, IETF, IGF) como referente LAC.',
      'Colaborar con ISOC en la medición regional de adopción DNSSEC.'
    ],
    references: [
      'https://www.lacnic.net',
      'https://www.internetsociety.org'
    ]
  },

  mixed: {
    profile_label: 'Perfil mixto — barreras estructurales y accionables coexisten',
    urgency: 'media-alta',
    primary_actor: 'Múltiples actores: Government + Registry + Operadores',
    policy_actions: [
      'Realizar un diagnóstico detallado para separar los dominios con barrera estructural de los accionables.',
      'Priorizar la acción en los dominios accionables (NOT_IMPLEMENTED, MISCONFIGURED) mientras se gestiona la barrera estructural.',
      'Crear un grupo de trabajo interinstitucional con participación de registro, gobierno y sector privado.',
      'Definir un plan de implementación escalonado con metas trimestrales.'
    ],
    capacity_actions: [
      'Capacitación diferenciada: técnica para operadores de dominios accionables, diplomática para los que enfrentan barreras estructurales.',
      'Mapear qué registrars soportan DNSSEC para guiar a los operadores hacia proveedores habilitados.',
      'Desarrollar un inventario nacional de dominios por estado DNSSEC para priorizar intervenciones.'
    ],
    regional_coordination: [
      'Buscar asistencia técnica de LACNIC para el análisis de barreras estructurales.',
      'Compartir el mapa de situación con pares regionales que hayan resuelto barreras similares.'
    ],
    references: [
      'https://www.lacnic.net',
      'https://www.internetsociety.org/deploy360/dnssec/'
    ]
  }
};

function getRecommendations(countryAggregate) {
  const profile = countryAggregate?.country_profile || 'mixed';
  const rec = RECOMMENDATIONS[profile] || RECOMMENDATIONS.mixed;

  return {
    country: countryAggregate.country,
    semaphore: countryAggregate.semaphore?.color,
    profile,
    ...rec,
    context: {
      adoption_pct: countryAggregate.adoption?.rate,
      structural_barriers: countryAggregate.barriers?.structural,
      actionable_barriers: countryAggregate.barriers?.actionable,
      tld_blocked: countryAggregate.barriers?.tld_blocked > 0
    },
    generated_at: new Date().toISOString()
  };
}

module.exports = { getRecommendations, RECOMMENDATIONS };
