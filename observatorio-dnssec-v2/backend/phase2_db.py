"""PostgreSQL access helpers for the FASE 2 DNSSEC laboratory.

The public FASE 1 service must keep working when PostgreSQL is not configured.
This module therefore treats DATABASE_URL as optional and imports psycopg lazily.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator


DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

REQUIRED_TABLES = (
    "app_users",
    "roles",
    "user_roles",
    "system_settings",
    "analysis_jobs",
    "analysis_job_items",
    "domain_inputs",
    "domain_snapshots",
    "dnsviz_artifacts",
    "dnssec_status_groups",
    "dnssec_findings",
    "infrastructure_entities",
    "domain_entity_links",
    "reports",
    "report_sections",
    "report_publications",
    "audit_log",
    "rate_limits",
)


class Phase2DatabaseNotConfigured(RuntimeError):
    pass


def is_configured() -> bool:
    return bool(DATABASE_URL)


def _import_psycopg():
    try:
        import psycopg  # type: ignore
    except Exception as exc:
        raise RuntimeError(
            "psycopg is not installed. Install backend requirements before "
            "using the FASE 2 PostgreSQL laboratory."
        ) from exc
    return psycopg


@contextmanager
def connect() -> Iterator[object]:
    if not DATABASE_URL:
        raise Phase2DatabaseNotConfigured("DATABASE_URL is not configured")
    psycopg = _import_psycopg()
    conn = psycopg.connect(DATABASE_URL, connect_timeout=5)
    try:
        yield conn
    finally:
        conn.close()


def check_schema() -> dict:
    """Return a compact health summary for the FASE 2 schema."""
    if not DATABASE_URL:
        return {
            "configured": False,
            "status": "not_configured",
            "missing_tables": list(REQUIRED_TABLES),
        }

    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute("select current_database(), current_user")
                database, user = cur.fetchone()
                cur.execute(
                    """
                    select table_name
                    from information_schema.tables
                    where table_schema = 'public'
                      and table_name = any(%s)
                    """,
                    (list(REQUIRED_TABLES),),
                )
                existing = {row[0] for row in cur.fetchall()}
    except Exception as exc:
        return {
            "configured": True,
            "status": "error",
            "error": str(exc),
            "missing_tables": list(REQUIRED_TABLES),
        }

    missing = [table for table in REQUIRED_TABLES if table not in existing]
    return {
        "configured": True,
        "status": "ok" if not missing else "schema_incomplete",
        "database": database,
        "user": user,
        "required_tables": len(REQUIRED_TABLES),
        "existing_tables": len(existing),
        "missing_tables": missing,
    }

