'use strict';

/**
 * Adaptador DNS crudo (UDP con fallback a TCP) — réplica de dns_query() del
 * validador de referencia (validador/validar_dominios_isoc_lac.py), que usa
 * dnspython allá. Aquí se usa dns-packet (ya dependencia del proyecto) sobre
 * dgram/net (núcleo de Node) — nada nuevo que instalar.
 *
 * Réplica deliberada de estos detalles del Python, uno a uno:
 *  - Flag CD=1 (Checking Disabled) en cada consulta, para no depender de
 *    validación DNSSEC del resolver (evita falsos SERVFAIL).
 *  - EDNS habilitado (use_edns=True en dnspython -> registro OPT aquí).
 *  - UDP primero; si la respuesta viene truncada (TC=1), reintenta la MISMA
 *    consulta por TCP, con timeout propio (no se resta del de UDP).
 *  - Reintentos (`retries`) solo ante timeout o error de transporte — una
 *    respuesta recibida (incluye SERVFAIL/REFUSED/NXDOMAIN) se acepta de
 *    inmediato, sin reintentar.
 *  - Cada intento tiene su propio timeout completo (no es un presupuesto
 *    acumulado entre intentos).
 */

const dgram = require('dgram');
const net = require('net');
const dnsPacket = require('dns-packet');

function randomId() {
  return Math.floor(Math.random() * 65535);
}

function buildQueryBuffer(id, name, rtype) {
  return dnsPacket.encode({
    type: 'query',
    id,
    flags: dnsPacket.RECURSION_DESIRED | dnsPacket.CHECKING_DISABLED,
    questions: [{ type: rtype, name, class: 'IN' }],
    additionals: [{ type: 'OPT', name: '.', udpPayloadSize: 4096 }],
  });
}

function queryUdp(server, queryBuf, queryId, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    let settled = false;

    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.close();
      fn(arg);
    };

    const timer = setTimeout(() => {
      finish(reject, Object.assign(new Error('Timeout'), { code: 'TIMEOUT' }));
    }, timeoutMs);

    socket.on('message', (msg) => {
      let decoded;
      try {
        decoded = dnsPacket.decode(msg);
      } catch {
        return; // paquete no parseable — seguir esperando hasta el timeout
      }
      if (decoded.id !== queryId) return; // respuesta de otra consulta
      finish(resolve, decoded);
    });

    socket.on('error', (err) => {
      finish(reject, Object.assign(err, { code: err.code || 'ERROR' }));
    });

    socket.send(queryBuf, 0, queryBuf.length, 53, server);
  });
}

function queryTcp(server, queryBuf, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: server, port: 53 });
    let settled = false;
    let buffer = Buffer.alloc(0);

    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      fn(arg);
    };

    socket.setTimeout(timeoutMs, () => {
      finish(reject, Object.assign(new Error('Timeout'), { code: 'TIMEOUT' }));
    });

    socket.on('connect', () => {
      const lenPrefix = Buffer.alloc(2);
      lenPrefix.writeUInt16BE(queryBuf.length, 0);
      socket.write(Buffer.concat([lenPrefix, queryBuf]));
    });

    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < 2) return;
      const msgLen = buffer.readUInt16BE(0);
      if (buffer.length < 2 + msgLen) return;
      try {
        finish(resolve, dnsPacket.decode(buffer.subarray(2, 2 + msgLen)));
      } catch (error) {
        finish(reject, error);
      }
    });

    socket.on('error', (err) => {
      finish(reject, Object.assign(err, { code: err.code || 'ERROR' }));
    });
  });
}

// Réplica de dns_query() del validador Python.
async function dnsQuery(resolverName, server, name, rtype, timeoutMs, retries) {
  const maxAttempts = retries + 1;
  let lastRcode = 'ERROR';
  let lastError = '';

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const id = randomId();
      const queryBuf = buildQueryBuffer(id, name, rtype);

      let response = await queryUdp(server, queryBuf, id, timeoutMs);
      if (response.flags & dnsPacket.TRUNCATED_RESPONSE) {
        response = await queryTcp(server, queryBuf, timeoutMs);
      }

      return {
        resolver: resolverName,
        server,
        rtype,
        rcode: response.rcode,
        error: '',
        attempts: attempt,
      };
    } catch (error) {
      if (error.code === 'TIMEOUT') {
        lastRcode = 'TIMEOUT';
        lastError = 'Timeout';
      } else {
        lastRcode = 'ERROR';
        lastError = error.code || error.message || 'Error';
      }
    }
  }

  return {
    resolver: resolverName,
    server,
    rtype,
    rcode: lastRcode,
    error: lastError,
    attempts: maxAttempts,
  };
}

module.exports = { dnsQuery };
