#!/usr/bin/env python3
"""
Auditoría técnica independiente de sitios de capítulos ISOC LAC
=================================================================

Qué hace este script (y qué NO hace):

Hace, con evidencia real de red:
  - Disponibilidad: estado HTTP de dominio raíz y www, cadena de
    redirecciones, hostname final.
  - HTTPS/TLS: certificado (CN/SAN, emisor, validez, fechas), y qué
    protocolos TLS acepta el servidor (1.0/1.1/1.2/1.3).
  - IPv6: existencia de AAAA en el hostname final Y conexión TCP+TLS
    real por esa dirección (no solo "tiene AAAA").
  - DNS/DNSSEC: DS en la zona padre, DNSKEY/RRSIG en la zona, y el bit
    AD (Authenticated Data) devuelto por un resolvedor validador
    (Cloudflare 1.1.1.1 y Google 8.8.8.8) como señal de validación
    efectiva. Esto NO sustituye una caminata completa de cadena de
    confianza como hace DNSViz/Zonemaster — se anota como limitación.
  - Correo: MX, SPF (TXT), DMARC (_dmarc TXT) y su política (p=),
    MTA-STS (registro + política en /.well-known/mta-sts.txt),
    TLS-RPT (_smtp._tls TXT). DKIM NO se declara ausente por defecto
    (no se puede sin conocer el selector): se deja como
    "no verificable sin selector conocido".
  - Cabeceras HTTP de seguridad en la respuesta HTTPS final.
  - Otros: CAA, TLSA/DANE en :443, robots.txt, sitemap,
    /.well-known/security.txt.
  - RPKI/ROA: vía la API pública de RIPEstat (rpki-validation), para
    cada IP (v4 y v6) resuelta del hostname final. Clasifica
    Valid/Invalid/NotFound. Esto SÍ requiere salida a internet real.

NO hace (queda para revisión humana / herramientas dedicadas):
  - Verificación de contenido institucional (misión, autoridades,
    transparencia, etc.) — eso ya se hizo por lectura manual/fetch.
  - Rendimiento/disponibilidad histórica.
  - Accesibilidad (WCAG).
  - Validación DNSSEC "fuerte" equivalente a Zonemaster/DNSViz.

Requisitos:
    pip install dnspython requests cryptography

Uso:
    python3 isoc_lac_audit.py > resultado.json
    (o dejar que Claude Code lo ejecute y te muestre el resumen)

El script imprime progreso a stderr y el JSON final a stdout.
"""

import concurrent.futures
import datetime
import json
import socket
import ssl
import sys
import traceback

import dns.flags
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# ----------------------------------------------------------------------
# Muestra a analizar (dominio raíz tal como lo usa el usuario; el script
# prueba raíz y www por separado y sigue redirecciones para hallar el
# hostname final real).
# ----------------------------------------------------------------------
SAMPLE = {
    "Ecuador": "isoc.org.ec",
    "Colombia": "isoc.co",
    "Peru": "isoc.pe",
    "Bolivia": "isoc.bo",
    "Brasil": "isoc.org.br",
    "Chile": "isoc.cl",
    "Costa Rica": "isoc.cr",
    "Republica Dominicana": "isoc.do",
    "Paraguay": "isoc.org.py",
    "Uruguay": "isoc.uy",
    "Panama": "isoc.org.pa",
    # Argentina: sin dominio institucional propio segun el directorio
    # oficial de ISOC (redirige a Instagram) -> no se prueba como sitio.
}

RESOLVERS = ["1.1.1.1", "8.8.8.8"]
TIMEOUT = 8
HEADERS_UA = {"User-Agent": "ISOC-LAC-audit/1.0 (+auditoria tecnica independiente)"}


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ----------------------------------------------------------------------
# DNS helpers
# ----------------------------------------------------------------------
def raw_query(qname, rdtype, resolver_ip, want_dnssec=True):
    """Consulta DNS cruda (para leer flags como AD) contra un resolver dado."""
    q = dns.message.make_query(qname, rdtype, want_dnssec=want_dnssec)
    try:
        r = dns.query.udp(q, resolver_ip, timeout=TIMEOUT)
        return r
    except Exception:
        try:
            r = dns.query.tcp(q, resolver_ip, timeout=TIMEOUT)
            return r
        except Exception as e:
            return {"error": str(e)}


def get_records(qname, rdtype):
    out = []
    try:
        res = dns.resolver.Resolver()
        res.nameservers = RESOLVERS
        res.timeout = TIMEOUT
        res.lifetime = TIMEOUT
        ans = res.resolve(qname, rdtype)
        out = [r.to_text() for r in ans]
    except Exception as e:
        out = {"error": str(e)}
    return out


def dnssec_check(hostname):
    """
    Clasifica: 'valido' | 'no_desplegado' | 'desplegado_invalido' |
    'no_verificable'. Basado en: presencia de DS en el padre, DNSKEY en
    la zona, y bit AD devuelto por resolvedores validadores para una
    consulta DNSSEC del propio hostname.
    LIMITACION: no reconstruye la cadena completa; usa el resolvedor
    como oraculo de confianza (practica comun, pero no equivalente a
    un chequeo independiente tipo DNSViz).
    """
    result = {"ds_parent": None, "dnskey": None, "ad_bit": {}, "clasificacion": None}

    labels = hostname.split(".")
    parent = ".".join(labels[1:]) if len(labels) > 1 else hostname
    result["ds_parent"] = get_records(hostname, "DS")
    result["dnskey"] = get_records(hostname, "DNSKEY")

    ad_seen = []
    for rip in RESOLVERS:
        try:
            r = raw_query(hostname, dns.rdatatype.A, rip, want_dnssec=True)
            if isinstance(r, dict):
                result["ad_bit"][rip] = f"error: {r.get('error')}"
                continue
            ad = bool(r.flags & dns.flags.AD)
            result["ad_bit"][rip] = ad
            ad_seen.append(ad)
        except Exception as e:
            result["ad_bit"][rip] = f"error: {e}"

    ds_ok = isinstance(result["ds_parent"], list) and len(result["ds_parent"]) > 0
    dnskey_ok = isinstance(result["dnskey"], list) and len(result["dnskey"]) > 0

    if not ds_ok:
        result["clasificacion"] = "no_desplegado"
    elif ds_ok and dnskey_ok and any(ad_seen):
        result["clasificacion"] = "valido"
    elif ds_ok and (not dnskey_ok or not any(ad_seen)):
        result["clasificacion"] = "desplegado_invalido"
    else:
        result["clasificacion"] = "no_verificable"

    return result


def mail_check(domain):
    out = {}
    out["mx"] = get_records(domain, "MX")
    txt = get_records(domain, "TXT")
    txt = txt if isinstance(txt, list) else []
    spf = [t for t in txt if "v=spf1" in t.lower()]
    out["spf"] = spf if spf else "no_encontrado"
    out["spf_multiple"] = len(spf) > 1

    dmarc = get_records(f"_dmarc.{domain}", "TXT")
    out["dmarc"] = dmarc

    mtasts_txt = get_records(f"_mta-sts.{domain}", "TXT")
    out["mta_sts_record"] = mtasts_txt
    try:
        r = requests.get(
            f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
            timeout=TIMEOUT, headers=HEADERS_UA,
        )
        out["mta_sts_policy"] = r.text[:500] if r.status_code == 200 else f"http_{r.status_code}"
    except Exception as e:
        out["mta_sts_policy"] = f"no_accesible: {e}"

    tlsrpt = get_records(f"_smtp._tls.{domain}", "TXT")
    out["tls_rpt"] = tlsrpt

    return out


def caa_check(hostname):
    return get_records(hostname, "CAA")


def tlsa_check(hostname):
    return get_records(f"_443._tcp.{hostname}", "TLSA")


# ----------------------------------------------------------------------
# HTTP / TLS helpers
# ----------------------------------------------------------------------
def http_probe(url):
    """Sigue redirecciones y devuelve cadena completa + hostname final."""
    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=True, headers=HEADERS_UA)
        chain = [{"url": h.url, "status": h.status_code} for h in r.history]
        chain.append({"url": r.url, "status": r.status_code})
        return {
            "ok": True,
            "cadena_redirecciones": chain,
            "url_final": r.url,
            "status_final": r.status_code,
            "headers_finales": dict(r.headers),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def tls_supported_versions(hostname, port=443):
    versions = {
        "TLSv1.0": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }
    supported = {}
    for name, ver in versions.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    supported[name] = True
        except Exception:
            supported[name] = False
    return supported


def cert_info(hostname, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der, default_backend())
        sans = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            pass
        return {
            "valido": True,
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "sans": sans,
        }
    except Exception as e:
        return {"valido": False, "error": str(e)}


def ipv6_functional_check(hostname):
    """Diferencia 'tiene AAAA' de 'funciona por IPv6 de verdad'."""
    out = {"aaaa": None, "conecta_ipv6": False, "tls_ipv6_ok": False}
    try:
        infos = socket.getaddrinfo(hostname, 443, socket.AF_INET6)
        addrs = sorted(set(i[4][0] for i in infos))
        out["aaaa"] = addrs
        if addrs:
            addr = addrs[0]
            try:
                with socket.create_connection((addr, 443), timeout=TIMEOUT):
                    out["conecta_ipv6"] = True
                ctx = ssl.create_default_context()
                with socket.create_connection((addr, 443), timeout=TIMEOUT) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname):
                        out["tls_ipv6_ok"] = True
            except Exception as e:
                out["error_conexion"] = str(e)
    except socket.gaierror as e:
        out["aaaa"] = []
        out["error_resolucion"] = str(e)
    return out


def rpki_check(ip):
    """Consulta RIPEstat (publica, sin API key) para validez RPKI de la IP."""
    try:
        ni = requests.get(
            "https://stat.ripe.net/data/network-info/data.json",
            params={"resource": ip}, timeout=TIMEOUT,
        ).json()
        asns = ni.get("data", {}).get("asns", [])
        prefix = ni.get("data", {}).get("prefix")
        if not asns or not prefix:
            return {"estado": "no_encontrado", "detalle": ni.get("data")}
        asn = asns[0]
        rv = requests.get(
            "https://stat.ripe.net/data/rpki-validation/data.json",
            params={"resource": asn, "prefix": prefix}, timeout=TIMEOUT,
        ).json()
        status = rv.get("data", {}).get("status")
        return {"asn": asn, "prefix": prefix, "estado_rpki": status}
    except Exception as e:
        return {"error": str(e)}


def wellknown_checks(base_url):
    out = {}
    for path in ["/.well-known/security.txt", "/robots.txt", "/sitemap.xml"]:
        try:
            r = requests.get(base_url.rstrip("/") + path, timeout=TIMEOUT, headers=HEADERS_UA)
            out[path] = {"status": r.status_code, "snippet": r.text[:300] if r.status_code == 200 else None}
        except Exception as e:
            out[path] = {"error": str(e)}
    return out


# ----------------------------------------------------------------------
# Orquestador por dominio
# ----------------------------------------------------------------------
def audit_domain(country, domain):
    print(f"[{now_utc()}] Analizando {country} ({domain})...", file=sys.stderr)
    result = {"pais": country, "dominio_base": domain, "timestamp_utc": now_utc()}

    result["http_raiz"] = http_probe(f"https://{domain}/")
    result["http_www"] = http_probe(f"https://www.{domain}/")

    final = None
    if result["http_raiz"].get("ok"):
        final = result["http_raiz"]["url_final"]
    elif result["http_www"].get("ok"):
        final = result["http_www"]["url_final"]

    if not final:
        result["error_general"] = "No se pudo obtener respuesta HTTPS de raiz ni www."
        return result

    hostname = final.split("//", 1)[-1].split("/", 1)[0]
    result["hostname_final"] = hostname

    try:
        result["certificado"] = cert_info(hostname)
    except Exception as e:
        result["certificado"] = {"error": str(e)}

    try:
        result["tls_versiones"] = tls_supported_versions(hostname)
    except Exception as e:
        result["tls_versiones"] = {"error": str(e)}

    try:
        result["ipv6"] = ipv6_functional_check(hostname)
    except Exception as e:
        result["ipv6"] = {"error": str(e)}

    try:
        result["dnssec"] = dnssec_check(hostname)
    except Exception as e:
        result["dnssec"] = {"error": str(e)}

    try:
        result["correo"] = mail_check(domain)
    except Exception as e:
        result["correo"] = {"error": str(e)}

    try:
        result["caa"] = caa_check(hostname)
    except Exception as e:
        result["caa"] = {"error": str(e)}

    try:
        result["tlsa_dane"] = tlsa_check(hostname)
    except Exception as e:
        result["tlsa_dane"] = {"error": str(e)}

    try:
        result["otros"] = wellknown_checks(f"https://{hostname}")
    except Exception as e:
        result["otros"] = {"error": str(e)}

    # RPKI para IPv4 e IPv6 del hostname final
    rpki_results = {}
    try:
        v4 = sorted(set(i[4][0] for i in socket.getaddrinfo(hostname, 443, socket.AF_INET)))
    except Exception:
        v4 = []
    v6 = (result.get("ipv6") or {}).get("aaaa") or []
    for ip in v4 + v6:
        rpki_results[ip] = rpki_check(ip)
    result["rpki"] = rpki_results

    return result


def main():
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(audit_domain, c, d): c for c, d in SAMPLE.items()}
        for fut in concurrent.futures.as_completed(futures):
            country = futures[fut]
            try:
                results[country] = fut.result()
            except Exception as e:
                results[country] = {"error_fatal": str(e), "trace": traceback.format_exc()}

    print(json.dumps(results, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
