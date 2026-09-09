'use strict';

/**
 * Envío de correo transaccional — Mediciones ISOC LAC.
 *
 * Única función: notificar contraseñas generadas por el sistema (alta de
 * administrador, recuperación del super_admin). Usa nodemailer (única
 * dependencia nueva del proyecto además de dns-packet) contra un relay SMTP
 * externo (Brevo) configurado por variables de entorno — nunca credenciales
 * en código.
 *
 * Variables requeridas en .env:
 *   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM
 *
 * Nota Brevo: usar smtp-relay.sendinblue.com, NO smtp-relay.brevo.com —
 * este último falla con "Hostname/IP does not match certificate's
 * altnames" (el certificado real es para *.sendinblue.com), verificado
 * contra el relay real. Mismo hallazgo ya documentado en otros proyectos
 * CORPECE que usan la misma cuenta Brevo.
 */

const nodemailer = require('nodemailer');

let transporter = null;

function getTransporter() {
  const host = process.env.SMTP_HOST || 'smtp-relay.sendinblue.com';
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASSWORD;
  if (!host || !user || !pass) return null;

  if (!transporter) {
    transporter = nodemailer.createTransport({
      host,
      port,
      secure: false, // STARTTLS explícito sobre 587, no TLS implícito
      auth: { user, pass },
      connectionTimeout: 15000,
      greetingTimeout: 15000,
      socketTimeout: 15000,
    });
  }
  return transporter;
}

function isConfigured() {
  return getTransporter() !== null;
}

async function sendMail({ to, subject, text }) {
  const t = getTransporter();
  if (!t) throw new Error('smtp_not_configured');
  const from = process.env.SMTP_FROM || 'Mediciones ISOC-LAC <noreply@corpece.org.ec>';
  await t.sendMail({ from, to, subject, text });
}

module.exports = { sendMail, isConfigured };
