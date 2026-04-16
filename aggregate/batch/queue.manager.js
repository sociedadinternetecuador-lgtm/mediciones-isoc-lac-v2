'use strict';

/**
 * Queue Manager — Módulo Agregado DNSSEC ISOC LAC
 *
 * Ejecuta análisis DNSSEC en batch con concurrencia controlada.
 * Diseño sin dependencias externas, compatible con el stack existente.
 *
 * Concurrencia: N dominios en paralelo (por defecto 10).
 * Retry: hasta 2 reintentos con backoff exponencial.
 * Progreso: emite eventos que el caller puede escuchar vía SSE.
 */

const { EventEmitter } = require('events');
const { validateDomainInput } = require('../../logic/validators/domain.validator');
const { getDnssecAnalysis } = require('../../services/dnssec.service');
const { processDnssecAnalysis } = require('../../logic/processors/dnssec.processor');

const DEFAULT_CONCURRENCY = 10;
const DEFAULT_RETRY_LIMIT = 2;
const RETRY_BASE_DELAY_MS = 1500;

class BatchQueue extends EventEmitter {
  constructor({ concurrency = DEFAULT_CONCURRENCY, retryLimit = DEFAULT_RETRY_LIMIT } = {}) {
    super();
    this.concurrency = concurrency;
    this.retryLimit = retryLimit;
    this.results = [];
    this.errors = [];
    this._running = 0;
    this._cancelled = false;
  }

  cancel() {
    this._cancelled = true;
  }

  async run(domains) {
    const total = domains.length;
    let processed = 0;
    this._cancelled = false;
    this.results = [];
    this.errors = [];

    this.emit('start', { total });

    const queue = [...domains];
    const workers = [];

    const next = async () => {
      while (queue.length > 0 && !this._cancelled) {
        const domain = queue.shift();
        this._running++;

        const result = await this._analyzeWithRetry(domain);

        if (result.success) {
          this.results.push(result.data);
        } else {
          this.errors.push({ domain, error: result.error });
        }

        processed++;
        this._running--;

        this.emit('progress', {
          processed,
          total,
          percent: Math.round((processed / total) * 100),
          lastDomain: domain,
          lastStatus: result.success ? result.data?.dnssec?.final_status : 'error',
          running: this._running
        });
      }
    };

    for (let i = 0; i < Math.min(this.concurrency, domains.length); i++) {
      workers.push(next());
    }

    await Promise.all(workers);

    const summary = this._cancelled
      ? { status: 'cancelled', processed, total }
      : { status: 'completed', processed, total };

    this.emit('done', summary);
    return { results: this.results, errors: this.errors, summary };
  }

  async _analyzeWithRetry(rawDomain, attempt = 0) {
    let domain;
    try {
      domain = validateDomainInput(rawDomain);
    } catch {
      return { success: false, error: 'invalid_domain' };
    }

    try {
      const raw = await getDnssecAnalysis(domain);
      const processed = processDnssecAnalysis(raw);
      return { success: true, data: processed };
    } catch (err) {
      if (attempt < this.retryLimit) {
        const delay = RETRY_BASE_DELAY_MS * Math.pow(2, attempt);
        await new Promise(r => setTimeout(r, delay));
        return this._analyzeWithRetry(rawDomain, attempt + 1);
      }
      return { success: false, error: err?.message || 'analysis_failed' };
    }
  }
}

module.exports = { BatchQueue };
