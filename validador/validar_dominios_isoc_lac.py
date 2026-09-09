#!/usr/bin/env python3
"""
Mediciones ISOC LAC — Domain Dataset Validator
Versión 6.1

Flujo:
    archivo fuente
    -> normalización
    -> clasificación con Public Suffix List (sección ICANN)
    -> preflight de resolvers
    -> validación DNS (primera pasada)
    -> reintento automático de REVIEW
    -> análisis e integridad
    -> reporte y listas por sufijo

Principio metodológico:
- Esta herramienta SOLO determina si un nombre existe en DNS y puede entrar al
  universo de Mediciones LAC.
- NO exige A, AAAA, MX, DNSSEC, HTTPS, web, correo, etc.
- VALID: NOERROR en al menos uno de los resolvers (NS o SOA).
- NXDOMAIN: NXDOMAIN confirmado por ambos resolvers para el mismo tipo de consulta.
- REVIEW: resultado no concluyente; no se elimina automáticamente.
- Las consultas usan CD=1 para reducir falsos negativos por DNSSEC roto.

Uso:
    py validar_dominios_isoc_lac_v6.py archivo.csv --tld ec --out ec_validado

Dependencia:
    py -m pip install dnspython

Public Suffix List:
- Se obtiene de https://publicsuffix.org/list/public_suffix_list.dat
- Se cachea localmente y se usa la sección ICANN.
- Puede pasarse una copia local con --psl-file.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

try:
    import dns.exception
    import dns.flags
    import dns.message
    import dns.query
    import dns.rcode
except ImportError:
    print("Falta dnspython. Instálelo con: py -m pip install dnspython", file=sys.stderr)
    sys.exit(2)


VERSION = "6.1"
DEFAULT_RESOLVERS = {
    "cloudflare": "1.1.1.1",
    "google": "8.8.8.8",
}
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
PSL_CACHE_DAYS = 7
LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
DATE_RE = re.compile(r"(20\d{2}-\d{2}-\d{2})")


@dataclass(frozen=True)
class DNSAnswer:
    resolver: str
    server: str
    rtype: str
    rcode: str
    error: str = ""
    attempts: int = 1


@dataclass
class ValidationResult:
    domain: str
    suffix: str
    status: str
    reason: str
    discrepancy: bool
    answers: dict[tuple[str, str], DNSAnswer]


class ICANNPublicSuffixList:
    """
    Implementación compacta de la Public Suffix List.

    Para Mediciones LAC se usa por defecto SOLO la sección ICANN, no PRIVATE.
    Soporta reglas exactas, wildcard y exception.
    """

    def __init__(self, text: str):
        self.exact: set[str] = set()
        self.wildcards: set[str] = set()
        self.exceptions: set[str] = set()
        self._parse(text)

    def _parse(self, text: str) -> None:
        in_icann = False
        for raw in text.splitlines():
            line = raw.strip()
            if line == "// ===BEGIN ICANN DOMAINS===":
                in_icann = True
                continue
            if line == "// ===END ICANN DOMAINS===":
                break
            if not in_icann:
                continue
            if not line or line.startswith("//"):
                continue

            raw_rule = line.lower()
            prefix = ""
            body = raw_rule
            if raw_rule.startswith("!"):
                prefix = "!"
                body = raw_rule[1:]
            elif raw_rule.startswith("*."):
                prefix = "*."
                body = raw_rule[2:]

            try:
                body = body.encode("idna").decode("ascii")
            except Exception:
                continue

            if prefix == "!":
                self.exceptions.add(body)
            elif prefix == "*.":
                self.wildcards.add(body)
            else:
                self.exact.add(body)

        if not self.exact:
            raise ValueError("La Public Suffix List no contiene reglas ICANN utilizables.")

    def public_suffix(self, domain: str) -> str:
        labels = domain.lower().rstrip(".").split(".")
        if len(labels) < 2:
            return labels[-1]

        # Regla exception: el public suffix es la excepción sin su etiqueta izquierda.
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in self.exceptions:
                parts = candidate.split(".")
                return ".".join(parts[1:]) if len(parts) > 1 else candidate

        matches: list[tuple[int, str]] = []

        # Regla por defecto "*": último label.
        matches.append((1, labels[-1]))

        # Reglas exactas.
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in self.exact:
                matches.append((len(labels) - i, candidate))

        # Wildcard "*.foo": debe existir al menos una etiqueta a la izquierda.
        for i in range(1, len(labels)):
            base = ".".join(labels[i:])
            if base in self.wildcards:
                suffix = ".".join(labels[i - 1:])
                matches.append((len(labels) - (i - 1), suffix))

        return max(matches, key=lambda item: item[0])[1]

    def registrable_domain(self, domain: str) -> str | None:
        suffix = self.public_suffix(domain)
        dlabels = domain.split(".")
        slabels = suffix.split(".")
        if len(dlabels) <= len(slabels):
            return None
        return ".".join(dlabels[-(len(slabels) + 1):])


def format_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{seconds:.2f} s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)} min {sec:.1f} s"
    hours, minutes = divmod(int(minutes), 60)
    return f"{hours} h {minutes} min {sec:.1f} s"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text_lines(lines: Iterable[str]) -> str:
    values = list(lines)
    payload = ("\n".join(values) + ("\n" if values else "")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def normalize_domain(raw: str) -> str:
    return raw.strip().strip('"').strip("'").rstrip(".").lower()


def static_valid(domain: str, tld: str) -> tuple[bool, str, str]:
    if not domain:
        return False, "empty", ""
    try:
        ascii_domain = domain.encode("idna").decode("ascii").lower()
    except Exception:
        return False, "idna_error", ""

    if not ascii_domain.endswith("." + tld):
        return False, "outside_tld", ascii_domain
    if ascii_domain == tld:
        return False, "tld_itself", ascii_domain
    if len(ascii_domain) > 253:
        return False, "too_long", ascii_domain

    labels = ascii_domain.split(".")
    if any(not LABEL_RE.fullmatch(label) for label in labels):
        return False, "invalid_label", ascii_domain
    return True, "", ascii_domain


def psl_cache_path() -> Path:
    root = Path.home() / ".cache" / "mediciones_lac"
    root.mkdir(parents=True, exist_ok=True)
    return root / "public_suffix_list.dat"


def download_psl(target: Path, timeout: float = 20.0) -> None:
    req = urllib.request.Request(
        PSL_URL,
        headers={"User-Agent": "Mediciones-LAC-Domain-Validator/6.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        data = response.read()
    if len(data) < 10_000:
        raise RuntimeError("La respuesta de Public Suffix List parece incompleta.")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def load_psl(psl_file: str, force_update: bool) -> tuple[ICANNPublicSuffixList, Path, str]:
    """
    Retorna (psl, ruta, origen).
    """
    if psl_file:
        path = Path(psl_file)
        if not path.exists():
            raise FileNotFoundError(f"No existe --psl-file: {path}")
        return ICANNPublicSuffixList(path.read_text(encoding="utf-8", errors="ignore")), path, "local"

    path = psl_cache_path()
    stale = True
    if path.exists():
        age_seconds = time.time() - path.stat().st_mtime
        stale = age_seconds > PSL_CACHE_DAYS * 86400

    if force_update or not path.exists() or stale:
        try:
            download_psl(path)
            origin = "downloaded"
        except Exception as exc:
            if not path.exists():
                raise RuntimeError(
                    f"No se pudo descargar Public Suffix List y no existe caché local: {type(exc).__name__}: {exc}"
                ) from exc
            print(
                f"AVISO: no se pudo actualizar PSL ({type(exc).__name__}); se usará la caché existente.",
                file=sys.stderr,
            )
            origin = "cached_after_update_failure"
    else:
        origin = "cached"

    return ICANNPublicSuffixList(path.read_text(encoding="utf-8", errors="ignore")), path, origin


def parse_input(src: Path, tld: str):
    raw_lines = src.read_text(encoding="utf-8", errors="ignore").splitlines()
    seen: set[str] = set()
    normalized: list[str] = []
    rejected: list[tuple[str, str]] = []
    stats = Counter()
    stats["raw_lines"] = len(raw_lines)

    for line in raw_lines:
        first = line.split(",", 1)[0]
        d = normalize_domain(first)
        if not d:
            stats["empty"] += 1
            continue

        ok, reason, ascii_domain = static_valid(d, tld)
        if not ok:
            rejected.append((d, reason))
            stats[f"rejected_{reason}"] += 1
            continue

        if ascii_domain in seen:
            stats["duplicates"] += 1
            continue

        seen.add(ascii_domain)
        normalized.append(ascii_domain)

    normalized.sort()
    stats["normalized"] = len(normalized)
    stats["rejected"] = len(rejected)
    return normalized, rejected, stats


def dns_query(
    resolver_name: str,
    server: str,
    name: str,
    rtype: str,
    timeout: float,
    retries: int,
) -> DNSAnswer:
    last_rcode = "ERROR"
    last_error = ""
    max_attempts = retries + 1

    for attempt in range(1, max_attempts + 1):
        try:
            q = dns.message.make_query(name, rtype, use_edns=True)
            q.flags |= dns.flags.CD

            response = dns.query.udp(q, server, timeout=timeout)
            if response.flags & dns.flags.TC:
                response = dns.query.tcp(q, server, timeout=timeout)

            return DNSAnswer(
                resolver=resolver_name,
                server=server,
                rtype=rtype,
                rcode=dns.rcode.to_text(response.rcode()),
                attempts=attempt,
            )
        except dns.exception.Timeout:
            last_rcode = "TIMEOUT"
            last_error = "Timeout"
        except OSError as exc:
            last_rcode = "ERROR"
            last_error = type(exc).__name__
        except Exception as exc:
            last_rcode = "ERROR"
            last_error = type(exc).__name__

    return DNSAnswer(
        resolver=resolver_name,
        server=server,
        rtype=rtype,
        rcode=last_rcode,
        error=last_error,
        attempts=max_attempts,
    )


def answer_value(result: ValidationResult, resolver: str, rtype: str) -> str:
    ans = result.answers.get((resolver, rtype))
    return ans.rcode if ans else "NOT_QUERIED"


def answer_error(result: ValidationResult, resolver: str, rtype: str) -> str:
    ans = result.answers.get((resolver, rtype))
    return ans.error if ans else ""


def answer_attempts(result: ValidationResult, resolver: str, rtype: str) -> int | str:
    ans = result.answers.get((resolver, rtype))
    return ans.attempts if ans else ""


def observation_text(result: ValidationResult) -> str:
    parts = []
    for rtype in ("NS", "SOA"):
        for resolver_name in DEFAULT_RESOLVERS:
            ans = result.answers.get((resolver_name, rtype))
            if not ans:
                continue
            txt = f"{resolver_name}({ans.server}):{rtype}:{ans.rcode}"
            if ans.error:
                txt += f":{ans.error}"
            if ans.attempts > 1:
                txt += f":attempts={ans.attempts}"
            parts.append(txt)
    return " | ".join(parts)


def classify_answers(
    answers: dict[tuple[str, str], DNSAnswer],
    resolvers: dict[str, str],
) -> tuple[str, str, bool]:
    resolver_names = list(resolvers)
    ns = [answers[(name, "NS")].rcode for name in resolver_names if (name, "NS") in answers]
    soa = [answers[(name, "SOA")].rcode for name in resolver_names if (name, "SOA") in answers]

    all_rcodes = ns + soa
    discrepancy = (len(ns) >= 2 and len(set(ns)) > 1) or (len(soa) >= 2 and len(set(soa)) > 1)

    if "NOERROR" in all_rcodes:
        where = "NS" if "NOERROR" in ns else "SOA"
        return "VALID", f"NOERROR confirmado en {where}", discrepancy

    if len(ns) == len(resolver_names) and len(ns) >= 2 and all(x == "NXDOMAIN" for x in ns):
        return "NXDOMAIN", "NXDOMAIN confirmado por ambos resolvers en NS", discrepancy

    if len(soa) == len(resolver_names) and len(soa) >= 2 and all(x == "NXDOMAIN" for x in soa):
        return "NXDOMAIN", "NXDOMAIN confirmado por ambos resolvers en SOA", discrepancy

    return "REVIEW", "Resultado DNS no concluyente", discrepancy


def validate_dns(
    domain: str,
    suffix: str,
    timeout: float,
    retries: int,
    resolvers: dict[str, str],
) -> ValidationResult:
    answers: dict[tuple[str, str], DNSAnswer] = {}

    for resolver_name, server in resolvers.items():
        answers[(resolver_name, "NS")] = dns_query(
            resolver_name, server, domain, "NS", timeout, retries
        )

    status, reason, discrepancy = classify_answers(answers, resolvers)
    if status in {"VALID", "NXDOMAIN"}:
        return ValidationResult(domain, suffix, status, reason, discrepancy, answers)

    for resolver_name, server in resolvers.items():
        answers[(resolver_name, "SOA")] = dns_query(
            resolver_name, server, domain, "SOA", timeout, retries
        )

    status, reason, discrepancy = classify_answers(answers, resolvers)
    return ValidationResult(domain, suffix, status, reason, discrepancy, answers)


def review_subtype(result: ValidationResult) -> str:
    if result.status != "REVIEW":
        return ""

    values = [
        ans.rcode
        for ans in result.answers.values()
        if ans.rcode and ans.rcode != "NOT_QUERIED"
    ]
    if not values:
        return "REVIEW_ERROR"

    unique = set(values)

    if result.discrepancy:
        return "REVIEW_CONFLICT"
    if unique == {"TIMEOUT"}:
        return "REVIEW_TIMEOUT"
    if unique == {"SERVFAIL"}:
        return "REVIEW_SERVFAIL"
    if "REFUSED" in unique:
        return "REVIEW_REFUSED"
    if "ERROR" in unique:
        return "REVIEW_ERROR"
    if "TIMEOUT" in unique and "SERVFAIL" in unique:
        return "REVIEW_MIXED_TIMEOUT_SERVFAIL"
    if "TIMEOUT" in unique:
        return "REVIEW_TIMEOUT"
    if "SERVFAIL" in unique:
        return "REVIEW_SERVFAIL"
    return "REVIEW_OTHER"


def preflight_resolvers(
    resolvers: dict[str, str],
    timeout: float,
) -> dict[str, DNSAnswer]:
    """
    Verifica que cada resolver pueda responder una consulta estable antes de
    lanzar el lote. Se usa "." NS para no depender de un dominio de tercero.
    """
    results = {}
    for name, server in resolvers.items():
        results[name] = dns_query(name, server, ".", "NS", timeout, 0)
    return results


def preflight_ok(results: dict[str, DNSAnswer]) -> bool:
    return all(ans.rcode == "NOERROR" for ans in results.values())


def resolve_output_dir(requested: Path) -> tuple[Path, bool]:
    if not requested.exists():
        return requested, False

    stamp = datetime.now().astimezone().strftime("%Y-%m-%d_%H%M%S")
    parent = requested.parent
    base_name = requested.name or "salida_validacion"
    candidate = parent / f"{base_name}_{stamp}"

    counter = 2
    while candidate.exists():
        candidate = parent / f"{base_name}_{stamp}_{counter:02d}"
        counter += 1

    return candidate, True


def run_validation_batch(
    domains: list[str],
    suffix_by_domain: dict[str, str],
    workers: int,
    timeout: float,
    retries: int,
    label: str,
) -> dict[str, ValidationResult]:
    results: dict[str, ValidationResult] = {}
    start = time.perf_counter()
    live = Counter()

    if not domains:
        return results

    print(f"\n=== {label} ===")
    print(f"Dominios: {len(domains):,} | workers={workers} | timeout={timeout}s | retries={retries}")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                validate_dns,
                domain,
                suffix_by_domain[domain],
                timeout,
                retries,
                DEFAULT_RESOLVERS,
            ): domain
            for domain in domains
        }

        total = len(futures)
        done = 0

        for fut in as_completed(futures):
            domain = futures[fut]
            try:
                result = fut.result()
            except Exception as exc:
                result = ValidationResult(
                    domain=domain,
                    suffix=suffix_by_domain[domain],
                    status="REVIEW",
                    reason=f"Excepción no controlada: {type(exc).__name__}",
                    discrepancy=False,
                    answers={},
                )

            results[domain] = result
            live[result.status] += 1
            done += 1

            if done % 500 == 0 or done == total:
                elapsed = time.perf_counter() - start
                print(
                    f"{done:,}/{total:,} | VALID {live['VALID']:,} | "
                    f"NXDOMAIN {live['NXDOMAIN']:,} | REVIEW {live['REVIEW']:,} | "
                    f"{format_duration(elapsed)}"
                )

    return results


def write_lines(path: Path, values: Iterable[str]) -> None:
    vals = list(values)
    path.write_text("\n".join(vals) + ("\n" if vals else ""), encoding="utf-8")


def infer_source_date(filename: str) -> str:
    m = DATE_RE.search(filename)
    return m.group(1) if m else ""


def make_suffix_summary(results: Iterable[ValidationResult]):
    summary: dict[str, Counter] = defaultdict(Counter)
    for r in results:
        summary[r.suffix]["TOTAL"] += 1
        summary[r.suffix][r.status] += 1
    return summary


def compute_integrity_checks(
    normalized: list[str],
    final_results: dict[str, ValidationResult],
    summary: dict[str, Counter],
) -> dict:
    statuses = Counter(r.status for r in final_results.values())
    normalized_set = set(normalized)
    result_set = set(final_results)

    suffix_total = sum(counts["TOTAL"] for counts in summary.values())

    checks = {
        "normalized_equals_result_count": len(normalized) == len(final_results),
        "status_partition_equals_result_count": (
            statuses["VALID"] + statuses["NXDOMAIN"] + statuses["REVIEW"]
            == len(final_results)
        ),
        "all_normalized_domains_have_result": normalized_set == result_set,
        "result_domains_are_unique": len(result_set) == len(final_results),
        "suffix_totals_equal_result_count": suffix_total == len(final_results),
    }
    return {
        "passed": all(checks.values()),
        "checks": checks,
    }


def write_master_csv(
    path: Path,
    normalized: list[str],
    first_results: dict[str, ValidationResult],
    final_results: dict[str, ValidationResult],
) -> None:
    cols = [
        "domain",
        "suffix",
        "first_pass_status",
        "final_status",
        "status_reason",
        "review_subtype",
        "retry_performed",
        "discrepancy",
        "cloudflare_ns",
        "google_ns",
        "cloudflare_soa",
        "google_soa",
        "cloudflare_ns_error",
        "google_ns_error",
        "cloudflare_soa_error",
        "google_soa_error",
        "cloudflare_ns_attempts",
        "google_ns_attempts",
        "cloudflare_soa_attempts",
        "google_soa_attempts",
        "first_pass_observations",
        "final_observations",
    ]

    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)

        for domain in normalized:
            first = first_results[domain]
            final = final_results[domain]
            retried = first.status == "REVIEW"

            w.writerow([
                domain,
                final.suffix,
                first.status,
                final.status,
                final.reason,
                review_subtype(final),
                "YES" if retried else "NO",
                "YES" if final.discrepancy else "NO",
                answer_value(final, "cloudflare", "NS"),
                answer_value(final, "google", "NS"),
                answer_value(final, "cloudflare", "SOA"),
                answer_value(final, "google", "SOA"),
                answer_error(final, "cloudflare", "NS"),
                answer_error(final, "google", "NS"),
                answer_error(final, "cloudflare", "SOA"),
                answer_error(final, "google", "SOA"),
                answer_attempts(final, "cloudflare", "NS"),
                answer_attempts(final, "google", "NS"),
                answer_attempts(final, "cloudflare", "SOA"),
                answer_attempts(final, "google", "SOA"),
                observation_text(first),
                observation_text(final),
            ])


def write_discrepancies(path: Path, final_results: dict[str, ValidationResult]) -> int:
    rows = [r for r in final_results.values() if r.discrepancy]
    rows.sort(key=lambda r: r.domain)

    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "domain", "suffix", "final_status", "review_subtype",
            "cloudflare_ns", "google_ns", "cloudflare_soa", "google_soa",
            "dns_observations",
        ])
        for r in rows:
            w.writerow([
                r.domain,
                r.suffix,
                r.status,
                review_subtype(r),
                answer_value(r, "cloudflare", "NS"),
                answer_value(r, "google", "NS"),
                answer_value(r, "cloudflare", "SOA"),
                answer_value(r, "google", "SOA"),
                observation_text(r),
            ])
    return len(rows)


def generate_outputs(
    *,
    out: Path,
    src: Path,
    tld: str,
    source: str,
    source_date: str,
    normalized: list[str],
    rejected: list[tuple[str, str]],
    input_stats: Counter,
    first_results: dict[str, ValidationResult],
    final_results: dict[str, ValidationResult],
    preflight: dict[str, DNSAnswer],
    psl_path: Path,
    psl_origin: str,
    args,
    timings: dict[str, float],
) -> dict:
    per_suffix = out / "listas_por_sufijo"
    per_suffix.mkdir(parents=True, exist_ok=True)

    write_lines(out / "dominios_normalizados.txt", normalized)

    if rejected:
        with (out / "rechazados_estructura.csv").open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["input_value", "reason"])
            w.writerows(rejected)

    write_master_csv(
        out / "validacion_dns.csv",
        normalized,
        first_results,
        final_results,
    )

    final_values = list(final_results.values())
    valid = sorted(r.domain for r in final_values if r.status == "VALID")
    nxdomain = sorted(r.domain for r in final_values if r.status == "NXDOMAIN")
    review = sorted(r.domain for r in final_values if r.status == "REVIEW")

    write_lines(out / "dominios_validos.txt", valid)
    write_lines(out / "dominios_nxdomain.txt", nxdomain)
    write_lines(out / "dominios_revisar.txt", review)

    review_groups: dict[str, list[str]] = defaultdict(list)
    for r in final_values:
        subtype = review_subtype(r)
        if subtype:
            review_groups[subtype].append(r.domain)

    review_dir = out / "review_por_tipo"
    review_dir.mkdir(exist_ok=True)
    for subtype, domains in sorted(review_groups.items()):
        write_lines(review_dir / f"{subtype.lower()}.txt", sorted(domains))

    groups: dict[str, list[str]] = defaultdict(list)
    for r in final_values:
        if r.status == "VALID":
            groups[r.suffix].append(r.domain)

    for suffix, values in sorted(groups.items()):
        fname = suffix.lstrip(".").replace(".", "_") + ".txt"
        write_lines(per_suffix / fname, sorted(values))

    summary = make_suffix_summary(final_values)
    summary_rows = []
    for suffix, counts in sorted(summary.items(), key=lambda kv: (-kv[1]["TOTAL"], kv[0])):
        total = counts["TOTAL"]
        v = counts["VALID"]
        nx = counts["NXDOMAIN"]
        rv = counts["REVIEW"]
        summary_rows.append((
            suffix, total, v, nx, rv,
            round(v / total * 100, 2) if total else 0,
            round(nx / total * 100, 2) if total else 0,
            round(rv / total * 100, 2) if total else 0,
        ))

    with (out / "resumen_sufijos.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "suffix", "total", "valid", "nxdomain", "review",
            "valid_pct", "nxdomain_pct", "review_pct",
        ])
        w.writerows(summary_rows)

    discrepancy_count = write_discrepancies(
        out / "discrepancias_resolvers.csv",
        final_results,
    )

    first_status = Counter(r.status for r in first_results.values())
    final_status = Counter(r.status for r in final_results.values())
    review_subtypes = Counter(
        review_subtype(r) for r in final_values if r.status == "REVIEW"
    )

    first_review_domains = [
        d for d, r in first_results.items() if r.status == "REVIEW"
    ]
    review_transitions = Counter()
    for domain in first_review_domains:
        review_transitions[final_results[domain].status] += 1

    integrity = compute_integrity_checks(normalized, final_results, summary)

    if not integrity["passed"]:
        execution_status = "FAILED_INTEGRITY_CHECK"
    elif final_status["REVIEW"] > 0:
        execution_status = "COMPLETED_WITH_REVIEW"
    else:
        execution_status = "COMPLETED"

    now = datetime.now(timezone.utc).astimezone()

    metadata = {
        "project": "Mediciones LAC - Internet Society",
        "validator_version": VERSION,
        "execution_status": execution_status,
        "source": source,
        "source_file": src.name,
        "source_date": source_date or None,
        "cctld": "." + tld,
        "processed_at": now.isoformat(timespec="seconds"),
        "input_sha256": sha256_file(src),
        "normalized_sha256": sha256_text_lines(normalized),
        "public_suffix_list": {
            "mode": "ICANN section only",
            "path": str(psl_path),
            "origin": psl_origin,
            "sha256": sha256_file(psl_path),
            "source_url": PSL_URL,
        },
        "input": dict(input_stats),
        "preflight": {
            name: {
                "server": ans.server,
                "query": ". NS",
                "rcode": ans.rcode,
                "error": ans.error,
            }
            for name, ans in preflight.items()
        },
        "results": {
            "total_validated": len(final_results),
            "first_pass": dict(first_status),
            "final": dict(final_status),
            "discrepancies": discrepancy_count,
            "review_retry": {
                "retried": len(first_review_domains),
                "became_VALID": review_transitions["VALID"],
                "became_NXDOMAIN": review_transitions["NXDOMAIN"],
                "remained_REVIEW": review_transitions["REVIEW"],
            },
            "review_subtypes": dict(review_subtypes),
        },
        "integrity": integrity,
        "timing": {k: round(v, 3) for k, v in timings.items()},
        "validation": {
            "methodology_version": "2.0",
            "purpose": "Confirm DNS existence only; do not measure service adoption at this stage",
            "resolvers": DEFAULT_RESOLVERS,
            "timeout_seconds": args.timeout,
            "retries": args.retries,
            "workers": args.workers,
            "review_retry_enabled": not args.no_review_retry,
            "review_retry_wait_seconds": args.review_wait,
            "transport": {
                "primary": "UDP",
                "fallback": "TCP when TC=1",
            },
            "query_sequence": [
                "Preflight: query . NS against both resolvers",
                "Query NS against both resolvers for every domain",
                "If NS is inconclusive, query SOA against both resolvers",
                "After first pass, retry only REVIEW domains unless disabled",
            ],
            "checking_disabled": True,
            "policy": {
                "VALID": "NOERROR from at least one resolver in NS or SOA",
                "NXDOMAIN": "NXDOMAIN confirmed by both resolvers for the same query type",
                "REVIEW": "Inconclusive result; do not discard automatically",
            },
            "non_exclusion_criteria": [
                "A", "AAAA", "IPv6", "MX", "DNSSEC", "HTTPS", "website availability"
            ],
            "principle": "Conservative inclusion: only confirmed NXDOMAIN is excluded automatically",
        },
    }

    (out / "metadata.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    total = len(final_results)
    pct = lambda n: (n / total * 100) if total else 0.0

    lines = [
        f"# Reporte de validación DNS — .{tld}",
        "",
        "## Identificación",
        "",
        "- Proyecto: **Mediciones LAC - Internet Society**",
        f"- Validador: **v{VERSION}**",
        f"- Estado de ejecución: **{execution_status}**",
        f"- Fuente declarada: **{source}**",
        f"- Archivo de entrada: `{src.name}`",
        f"- Fecha de la fuente: **{source_date or 'no indicada'}**",
        f"- ccTLD: **.{tld}**",
        f"- Fecha de procesamiento: **{now.strftime('%Y-%m-%d %H:%M:%S %z')}**",
        f"- SHA-256 archivo fuente: `{metadata['input_sha256']}`",
        f"- SHA-256 lista normalizada: `{metadata['normalized_sha256']}`",
        "",
        "## Public Suffix List",
        "",
        "- Clasificación de sufijos: **Public Suffix List, sección ICANN**.",
        f"- Origen en esta ejecución: **{psl_origin}**.",
        f"- Archivo utilizado: `{psl_path}`",
        f"- SHA-256 PSL: `{metadata['public_suffix_list']['sha256']}`",
        "",
        "## Nota sobre la fuente OpenINTEL" if source.lower() == "openintel" else "## Fuente de datos",
        "",
        (
            "Las listas ccTLD de OpenINTEL se construyen a partir de nombres observados en Certificate Transparency (CT), "
            "procesados para extraer dominios registrables. Constituyen una fuente de descubrimiento amplia, pero no un "
            "archivo oficial de zona ni un censo completo del ccTLD. La validación DNS de esta herramienta existe precisamente "
            "para comprobar qué nombres de la lista pueden utilizarse en la ejecución de Mediciones LAC."
            if source.lower() == "openintel"
            else "El origen del archivo ha sido declarado por el usuario. La herramienta valida técnicamente los nombres, pero no certifica la exhaustividad de la fuente."
        ),
        "",
        "## Normalización",
        "",
        f"- Líneas originales: **{input_stats['raw_lines']:,}**",
        f"- Líneas vacías: **{input_stats['empty']:,}**",
        f"- Duplicados eliminados: **{input_stats['duplicates']:,}**",
        f"- Rechazados por estructura/ccTLD: **{input_stats['rejected']:,}**",
        f"- Dominios normalizados: **{input_stats['normalized']:,}**",
        "",
        "## Preflight de resolvers",
        "",
    ]

    for name, ans in preflight.items():
        lines.append(
            f"- {name.capitalize()} `{ans.server}`: **{ans.rcode}**"
            + (f" ({ans.error})" if ans.error else "")
        )

    lines += [
        "",
        "El lote DNS solo se inicia cuando ambos resolvers superan el preflight, salvo que el usuario use explícitamente `--skip-preflight`.",
        "",
        "## Resultado final",
        "",
        "| Estado | Dominios | Porcentaje | Significado |",
        "|---|---:|---:|---|",
        f"| VALID | {final_status['VALID']:,} | {pct(final_status['VALID']):.2f}% | Existencia DNS confirmada. Pasa al dataset de Mediciones LAC. |",
        f"| NXDOMAIN | {final_status['NXDOMAIN']:,} | {pct(final_status['NXDOMAIN']):.2f}% | Inexistencia confirmada por ambos resolvers. Se excluye del dataset operativo. |",
        f"| REVIEW | {final_status['REVIEW']:,} | {pct(final_status['REVIEW']):.2f}% | Resultado no concluyente. No se descarta automáticamente. |",
        f"| **TOTAL** | **{total:,}** | **100.00%** | |",
        "",
        "## Reintento automático de REVIEW",
        "",
        f"- REVIEW después de la primera pasada: **{len(first_review_domains):,}**",
        f"- Se resolvieron como VALID: **{review_transitions['VALID']:,}**",
        f"- Se resolvieron como NXDOMAIN: **{review_transitions['NXDOMAIN']:,}**",
        f"- Permanecieron REVIEW: **{review_transitions['REVIEW']:,}**",
        "",
        "El segundo intento se aplica solamente a los dominios REVIEW para reducir falsos pendientes causados por timeouts o fallos transitorios.",
        "",
        "## Tipos de REVIEW final",
        "",
    ]

    if review_subtypes:
        for subtype, count in review_subtypes.most_common():
            lines.append(f"- **{subtype}**: {count:,}")
    else:
        lines.append("No quedaron dominios REVIEW después del reintento.")

    lines += [
        "",
        "## Metodología de validación",
        "",
        "1. **Normalización.** Se limpian las entradas, se convierten a minúsculas, se elimina el punto final, se aplica IDNA/Punycode cuando corresponde, se eliminan duplicados y se valida sintaxis y pertenencia al ccTLD.",
        "2. **Clasificación PSL.** Cada nombre se clasifica usando la Public Suffix List, sección ICANN, evitando reglas manuales por país.",
        f"3. **Preflight.** Antes del lote se comprueba que Cloudflare (`{DEFAULT_RESOLVERS['cloudflare']}`) y Google (`{DEFAULT_RESOLVERS['google']}`) puedan responder una consulta `. NS`.",
        "4. **Consulta NS.** Todos los dominios se consultan por NS contra ambos resolvers.",
        "5. **Consulta SOA de respaldo.** Si NS es inconcluso, se consulta SOA contra ambos resolvers.",
        "6. **VALID.** Se asigna cuando al menos un resolver devuelve NOERROR en NS o SOA.",
        "7. **NXDOMAIN.** Se excluye automáticamente solo cuando ambos resolvers confirman NXDOMAIN para el mismo tipo de consulta.",
        "8. **REVIEW.** SERVFAIL, TIMEOUT, REFUSED, ERROR o respuestas no concluyentes no se interpretan como inexistencia.",
        "9. **Segundo intento.** Los REVIEW de la primera pasada se vuelven a consultar automáticamente salvo que se desactive esta opción.",
        "10. **DNSSEC.** Las consultas usan CD=1 para reducir falsos negativos causados por validación DNSSEC defectuosa.",
        "11. **Transporte.** Se usa UDP inicialmente y TCP cuando la respuesta está truncada (TC=1).",
        "12. **Sin sesgo por mediciones posteriores.** A, AAAA, IPv6, MX, DNSSEC, HTTPS o disponibilidad web no se utilizan como criterios de exclusión.",
        "",
        "> El principio es conservador: solo se excluye automáticamente un nombre cuya inexistencia DNS ha sido confirmada por ambos resolvers.",
        "",
        "## Discrepancias entre resolvers",
        "",
        f"Se detectaron **{discrepancy_count:,}** dominios con respuestas diferentes entre Cloudflare y Google en al menos una consulta final.",
        "El detalle está en `discrepancias_resolvers.csv`.",
        "",
        "## Resultado por sufijo",
        "",
        "| Sufijo | Total | VALID | NXDOMAIN | REVIEW | VALID % |",
        "|---|---:|---:|---:|---:|---:|",
    ]

    for suffix, total_s, valid_s, nx_s, rev_s, valid_pct, _, _ in summary_rows:
        lines.append(
            f"| {suffix} | {total_s:,} | {valid_s:,} | {nx_s:,} | {rev_s:,} | {valid_pct:.2f}% |"
        )

    lines += [
        "",
        "## Control de integridad",
        "",
        f"- Resultado global: **{'PASSED' if integrity['passed'] else 'FAILED'}**",
    ]
    for check, passed in integrity["checks"].items():
        lines.append(f"- `{check}`: **{'OK' if passed else 'FAIL'}**")

    lines += [
        "",
        "## Tiempos de ejecución",
        "",
        f"- Normalización + PSL: **{format_duration(timings['normalization_and_psl_seconds'])}**",
        f"- Preflight: **{format_duration(timings['preflight_seconds'])}**",
        f"- Primera pasada DNS: **{format_duration(timings['first_dns_pass_seconds'])}**",
        f"- Reintento REVIEW: **{format_duration(timings['review_retry_seconds'])}**",
        f"- Validación DNS total: **{format_duration(timings['dns_validation_seconds'])}**",
        f"- Generación de archivos/reporte: **{format_duration(timings['output_generation_seconds'])}**",
        f"- Tiempo total: **{format_duration(timings['total_execution_seconds'])}**",
        "",
        "## Archivos generados",
        "",
        "- `validacion_dns.csv`: CSV maestro con primera pasada, estado final y respuestas DNS.",
        "- `dominios_normalizados.txt`: universo después de normalización.",
        "- `dominios_validos.txt`: dataset operativo que pasa a Mediciones LAC.",
        "- `dominios_nxdomain.txt`: nombres excluidos por inexistencia confirmada.",
        "- `dominios_revisar.txt`: casos finales no concluyentes.",
        "- `review_por_tipo/`: REVIEW separados por causa.",
        "- `discrepancias_resolvers.csv`: respuestas distintas entre Cloudflare y Google.",
        "- `resumen_sufijos.csv`: resultados por sufijo.",
        "- `listas_por_sufijo/`: todos los dominios VALID separados por sufijo.",
        "- `metadata.json`: parámetros, hashes, metodología, tiempos e integridad.",
        "",
        "## Uso en Mediciones LAC",
        "",
        "El dataset operativo está formado por `dominios_validos.txt` o por las listas VALID de `listas_por_sufijo/`.",
        "Los dominios REVIEW permanecen separados y no deben tratarse como inexistentes sin revisión adicional.",
    ]

    (out / "reporte_validacion.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    return {
        "execution_status": execution_status,
        "integrity": integrity,
        "total": total,
        "valid": final_status["VALID"],
        "nxdomain": final_status["NXDOMAIN"],
        "review": final_status["REVIEW"],
        "discrepancies": discrepancy_count,
        "suffixes": len(summary_rows),
        "review_retried": len(first_review_domains),
        "review_resolved": review_transitions["VALID"] + review_transitions["NXDOMAIN"],
    }


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Valida y reporta datasets de dominios para Mediciones ISOC LAC"
    )
    ap.add_argument("input", help="Archivo .txt/.csv; un dominio por línea o primera columna")
    ap.add_argument("--tld", required=True, help="ccTLD sin punto, por ejemplo ec")
    ap.add_argument("--workers", type=int, default=20)
    ap.add_argument("--timeout", type=float, default=2.5)
    ap.add_argument("--retries", type=int, default=1)
    ap.add_argument("--out", default="salida_validacion")
    ap.add_argument("--source", default="OpenINTEL")
    ap.add_argument("--source-date", default="")
    ap.add_argument("--review-wait", type=float, default=2.0, help="Espera antes de reintentar REVIEW")
    ap.add_argument("--no-review-retry", action="store_true", help="Desactiva segunda pasada REVIEW")
    ap.add_argument("--skip-preflight", action="store_true", help="Permite continuar aunque falle preflight")
    ap.add_argument("--psl-file", default="", help="Public Suffix List local")
    ap.add_argument("--force-psl-update", action="store_true", help="Fuerza actualización de PSL")
    args = ap.parse_args()

    total_start = time.perf_counter()

    src = Path(args.input)
    if not src.exists() or not src.is_file():
        print(f"ERROR: no existe el archivo de entrada: {src}", file=sys.stderr)
        sys.exit(1)
    if args.workers < 1 or args.timeout <= 0 or args.retries < 0 or args.review_wait < 0:
        print("ERROR: parámetros numéricos inválidos.", file=sys.stderr)
        sys.exit(1)

    tld = args.tld.lower().lstrip(".")
    requested_out = Path(args.out)
    out, renamed = resolve_output_dir(requested_out)
    out.mkdir(parents=True, exist_ok=False)

    if renamed:
        print(
            "AVISO: la salida solicitada ya existía y NO será sobrescrita.\n"
            f"Nueva ejecución: {out.resolve()}"
        )
    else:
        print(f"Directorio de salida: {out.resolve()}")

    # Normalización + PSL.
    stage = time.perf_counter()
    normalized, rejected, input_stats = parse_input(src, tld)
    try:
        psl, psl_path, psl_origin = load_psl(args.psl_file, args.force_psl_update)
    except Exception as exc:
        print(f"ERROR PSL: {exc}", file=sys.stderr)
        sys.exit(2)

    suffix_by_domain = {
        domain: "." + psl.public_suffix(domain)
        for domain in normalized
    }
    normalization_psl_seconds = time.perf_counter() - stage

    print("\n=== Normalización y clasificación ===")
    print(f"Líneas originales:       {input_stats['raw_lines']:,}")
    print(f"Vacías:                  {input_stats['empty']:,}")
    print(f"Duplicados:              {input_stats['duplicates']:,}")
    print(f"Rechazados:              {input_stats['rejected']:,}")
    print(f"Normalizados:            {input_stats['normalized']:,}")
    print(f"Sufijos PSL detectados:  {len(set(suffix_by_domain.values())):,}")
    print(f"PSL:                     {psl_origin} ({psl_path})")
    print(f"Tiempo:                  {format_duration(normalization_psl_seconds)}")

    # Preflight.
    stage = time.perf_counter()
    preflight = preflight_resolvers(DEFAULT_RESOLVERS, args.timeout)
    preflight_seconds = time.perf_counter() - stage

    print("\n=== Preflight de resolvers ===")
    for name, ans in preflight.items():
        print(f"{name:12s} {ans.server:15s} -> {ans.rcode} {ans.error}".rstrip())

    if not preflight_ok(preflight) and not args.skip_preflight:
        print(
            "\nERROR: al menos un resolver no superó el preflight. "
            "No se iniciará el lote para evitar producir REVIEW masivos.\n"
            "Revise conectividad/firewall o use --skip-preflight solo si comprende el riesgo.",
            file=sys.stderr,
        )
        sys.exit(3)

    # Primera pasada.
    dns_total_start = time.perf_counter()
    stage = time.perf_counter()
    first_results = run_validation_batch(
        normalized,
        suffix_by_domain,
        args.workers,
        args.timeout,
        args.retries,
        "Validación DNS — primera pasada",
    )
    first_pass_seconds = time.perf_counter() - stage

    # Reintento automático REVIEW.
    first_review = sorted(
        domain for domain, result in first_results.items()
        if result.status == "REVIEW"
    )
    retry_seconds = 0.0
    final_results = dict(first_results)

    if first_review and not args.no_review_retry:
        if args.review_wait:
            print(
                f"\nEsperando {args.review_wait:.1f}s antes de reintentar "
                f"{len(first_review):,} REVIEW..."
            )
            time.sleep(args.review_wait)

        stage = time.perf_counter()
        retry_results = run_validation_batch(
            first_review,
            suffix_by_domain,
            args.workers,
            args.timeout,
            args.retries,
            "Validación DNS — segundo intento REVIEW",
        )
        retry_seconds = time.perf_counter() - stage
        final_results.update(retry_results)

    dns_total_seconds = time.perf_counter() - dns_total_start

    # Salidas.
    source_date = args.source_date or infer_source_date(src.name)
    output_start = time.perf_counter()

    # Se calcula una estimación preliminar del total; output_generation y total se
    # actualizan justo antes de generar metadata/report.
    timings = {
        "normalization_and_psl_seconds": normalization_psl_seconds,
        "preflight_seconds": preflight_seconds,
        "first_dns_pass_seconds": first_pass_seconds,
        "review_retry_seconds": retry_seconds,
        "dns_validation_seconds": dns_total_seconds,
        "output_generation_seconds": 0.0,
        "total_execution_seconds": 0.0,
    }

    # Generación principal.
    summary = generate_outputs(
        out=out,
        src=src,
        tld=tld,
        source=args.source,
        source_date=source_date,
        normalized=normalized,
        rejected=rejected,
        input_stats=input_stats,
        first_results=first_results,
        final_results=final_results,
        preflight=preflight,
        psl_path=psl_path,
        psl_origin=psl_origin,
        args=args,
        timings=timings,
    )

    output_seconds = time.perf_counter() - output_start
    total_seconds = time.perf_counter() - total_start
    timings["output_generation_seconds"] = output_seconds
    timings["total_execution_seconds"] = total_seconds

    # Actualizar únicamente los tiempos finales dentro de metadata.json.
    metadata_path = out / "metadata.json"
    metadata_obj = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata_obj["timing"] = {k: round(v, 3) for k, v in timings.items()}
    metadata_path.write_text(
        json.dumps(metadata_obj, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # Sustituir las líneas de tiempo del reporte sin regenerar datasets.
    report_path = out / "reporte_validacion.md"
    report_text = report_path.read_text(encoding="utf-8")
    replacements = {
        r"- Normalización \+ PSL: \*\*.*?\*\*": f"- Normalización + PSL: **{format_duration(normalization_psl_seconds)}**",
        r"- Preflight: \*\*.*?\*\*": f"- Preflight: **{format_duration(preflight_seconds)}**",
        r"- Primera pasada DNS: \*\*.*?\*\*": f"- Primera pasada DNS: **{format_duration(first_pass_seconds)}**",
        r"- Reintento REVIEW: \*\*.*?\*\*": f"- Reintento REVIEW: **{format_duration(retry_seconds)}**",
        r"- Validación DNS total: \*\*.*?\*\*": f"- Validación DNS total: **{format_duration(dns_total_seconds)}**",
        r"- Generación de archivos/reporte: \*\*.*?\*\*": f"- Generación de archivos/reporte: **{format_duration(output_seconds)}**",
        r"- Tiempo total: \*\*.*?\*\*": f"- Tiempo total: **{format_duration(total_seconds)}**",
    }
    for pattern, repl in replacements.items():
        report_text = re.sub(pattern, repl, report_text)
    report_path.write_text(report_text, encoding="utf-8")

    print("\n=== Resultado final ===")
    print(f"Estado:        {summary['execution_status']}")
    print(f"TOTAL:         {summary['total']:,}")
    print(f"VALID:         {summary['valid']:,}")
    print(f"NXDOMAIN:      {summary['nxdomain']:,}")
    print(f"REVIEW:        {summary['review']:,}")
    print(f"Reintentados:  {summary['review_retried']:,}")
    print(f"Resueltos:     {summary['review_resolved']:,}")
    print(f"Discrepancias: {summary['discrepancies']:,}")
    print(f"Sufijos:       {summary['suffixes']:,}")
    print(f"Integridad:    {'PASSED' if summary['integrity']['passed'] else 'FAILED'}")

    print("\n=== Tiempos ===")
    print(f"Normalización + PSL: {format_duration(normalization_psl_seconds)}")
    print(f"Preflight:            {format_duration(preflight_seconds)}")
    print(f"Primera pasada DNS:   {format_duration(first_pass_seconds)}")
    print(f"Reintento REVIEW:     {format_duration(retry_seconds)}")
    print(f"DNS total:            {format_duration(dns_total_seconds)}")
    print(f"Salidas/reporte:      {format_duration(output_seconds)}")
    print(f"Total:                {format_duration(total_seconds)}")

    print(f"\nReporte: {out / 'reporte_validacion.md'}")
    print(f"Salida completa: {out.resolve()}")

    if not summary["integrity"]["passed"]:
        sys.exit(4)


if __name__ == "__main__":
    main()
