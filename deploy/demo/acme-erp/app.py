"""Acme ERP: the demo target system Warrant protects.

It knows nothing about Warrant. It accepts tool calls from anyone holding its service bearer token, offers a dry run
that measures blast radius (the impact estimate Warrant feeds to L1/L2), and makes vendors.archive idempotent so a
released escalation retried after a crash archives exactly once.
"""
from __future__ import annotations

import hmac
import os
import re
from pathlib import Path
from typing import Any

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

WRITER_DSN = os.environ.get("ACME_DB_DSN", "host=postgres dbname=acme user=acme_erp")
READER_DSN = os.environ.get("ACME_DB_READER_DSN", "host=postgres dbname=acme user=acme_reader")
TOKEN_FILE = Path(os.environ.get("ACME_ERP_TOKEN_FILE", "/run/secrets/acme-erp-token"))
MAX_ROWS = 2000
READ_VERBS = {"select"}

pool = ConnectionPool(WRITER_DSN, min_size=1, max_size=8, open=False, kwargs={"autocommit": False})
reader = ConnectionPool(READER_DSN, min_size=1, max_size=8, open=False, kwargs={"autocommit": False})
app = FastAPI(title="acme-erp", docs_url=None, redoc_url=None, openapi_url=None)

_DELETE = re.compile(r"^\s*delete\s+from\s+(?:only\s+)?([a-z_][a-z0-9_]*)(?:\s+(?:as\s+)?[a-z_][a-z0-9_]*)?"
                     r"(?:\s+where\s+(?P<where>.+?))?\s*;?\s*$", re.IGNORECASE | re.DOTALL)
_UPDATE = re.compile(r"^\s*update\s+(?:only\s+)?([a-z_][a-z0-9_]*)\s+set\s+.+?(?:\s+where\s+(?P<where>.+?))?\s*;?\s*$",
                     re.IGNORECASE | re.DOTALL)
_WHOLE_TABLE = re.compile(r"^\s*(?:truncate(?:\s+table)?|drop\s+table(?:\s+if\s+exists)?)\s+([a-z_][a-z0-9_]*)",
                          re.IGNORECASE)
_TABLES = {"vendors", "invoices", "payment_holds"}


@app.on_event("startup")
def open_pool() -> None:
    pool.open(wait=True, timeout=30)
    reader.open(wait=True, timeout=30)


def service_token() -> str:
    return TOKEN_FILE.read_text(encoding="utf-8").strip()


def require_caller(authorization: str | None = Header(default=None)) -> None:
    expected = "Bearer " + service_token()
    if authorization is None or not hmac.compare_digest(authorization.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="credential required")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "up", "service": "acme-erp"}


@app.get("/stats")
def stats() -> dict[str, int]:
    """Aggregate counts only, for the demo narration."""
    with reader.connection() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT (SELECT count(*) FROM vendors),
                   (SELECT count(*) FROM vendors WHERE last_activity < now() - interval '18 months'),
                   (SELECT count(*) FROM vendors WHERE status = 'archived'),
                   (SELECT count(DISTINCT vendor_id) FROM invoices WHERE status = 'open'),
                   (SELECT count(*) FROM payment_holds)""")
        total, stale, archived, open_invoice, holds = cur.fetchone()
        conn.rollback()
    return {"vendors": total, "stale": stale, "archived": archived, "deleted": 4106 - total,
            "vendors_with_open_invoices": open_invoice, "payment_holds": holds}


@app.post("/tools/sql.execute", dependencies=[Depends(require_caller)])
async def sql_execute(request: Request, x_warrant_verb: str | None = Header(default=None)) -> dict[str, Any]:
    body = await request.json()
    query = body.get("q") if isinstance(body, dict) else None
    if not isinstance(query, str) or not query.strip():
        raise HTTPException(status_code=400, detail="q is required")
    read_only = (x_warrant_verb or "").lower() in READ_VERBS or query.lstrip().lower().startswith("select")
    with (reader if read_only else pool).connection() as conn:
        try:
            with conn.cursor(row_factory=dict_row) as cur:
                if read_only:
                    cur.execute("SET TRANSACTION READ ONLY")
                cur.execute("SET LOCAL statement_timeout = '10s'")
                cur.execute(query)
                rows = cur.fetchmany(MAX_ROWS) if cur.description else []
                count = cur.rowcount
            conn.rollback() if read_only else conn.commit()
        except psycopg.Error as error:
            conn.rollback()
            raise HTTPException(status_code=400, detail=type(error).__name__) from None
    return {"rowcount": count, "rows": [{k: _plain(v) for k, v in r.items()} for r in rows],
            "truncated": len(rows) == MAX_ROWS}


@app.post("/tools/vendors.archive", dependencies=[Depends(require_caller)])
async def vendors_archive(request: Request, idempotency_key: str | None = Header(default=None)) -> dict[str, Any]:
    body = await request.json()
    ids = body.get("ids") if isinstance(body, dict) else None
    if not isinstance(ids, list) or not all(isinstance(i, int) for i in ids) or not ids:
        raise HTTPException(status_code=400, detail="ids must be a non-empty list of integers")
    if not idempotency_key or len(idempotency_key) > 128:
        raise HTTPException(status_code=400, detail="Idempotency-Key header is required")
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT archived FROM archive_requests WHERE idempotency_key = %s", (idempotency_key,))
        previous = cur.fetchone()
        if previous is not None:
            conn.rollback()
            return {"archived": previous[0], "replayed": True}
        cur.execute("UPDATE vendors SET status = 'archived', archived_at = now() "
                    "WHERE id = ANY(%s) AND archived_at IS NULL", (ids,))
        archived = cur.rowcount
        cur.execute("INSERT INTO archive_requests (idempotency_key, archived) VALUES (%s, %s)", (idempotency_key, archived))
        conn.commit()
    return {"archived": archived, "replayed": False}


@app.post("/tools/dry_run", dependencies=[Depends(require_caller)])
async def dry_run(request: Request) -> dict[str, Any]:
    """Measures what a call would touch without changing anything (read-only transaction, short timeout)."""
    body = await request.json()
    arguments = body.get("arguments") if isinstance(body, dict) else None
    if not isinstance(arguments, dict):
        return unavailable()
    if isinstance(arguments.get("ids"), list):
        return measure_ids("vendors", [i for i in arguments["ids"] if isinstance(i, int)])
    query = arguments.get("q")
    if not isinstance(query, str):
        return unavailable()
    return measure_sql(query)


def measure_sql(query: str) -> dict[str, Any]:
    whole = _WHOLE_TABLE.match(query)
    if whole and whole.group(1).lower() in _TABLES:
        return measure(whole.group(1).lower(), "true")
    for pattern in (_DELETE, _UPDATE):
        match = pattern.match(query)
        if match and match.group(1).lower() in _TABLES:
            return measure(match.group(1).lower(), match.group("where") or "true")
    if query.lstrip().lower().startswith("select"):
        return read_rows(query)
    return unavailable()


def measure(table: str, where: str) -> dict[str, Any]:
    id_column = "id" if table == "vendors" else "vendor_id"
    try:
        with reader.connection() as conn, conn.cursor() as cur:
            cur.execute("SET TRANSACTION READ ONLY")
            cur.execute("SET LOCAL statement_timeout = '2s'")
            cur.execute(f"SELECT {id_column} FROM {table} WHERE {where}")  # noqa: S608 - read-only, time-boxed
            ids = [row[0] for row in cur.fetchall()]
            conn.rollback()
    except psycopg.Error:
        return unavailable()
    if table != "vendors":
        return {"available": True, "estimated_rows": len(ids), "protected": {}}
    return measure_ids("vendors", ids)


def measure_ids(table: str, ids: list[int]) -> dict[str, Any]:
    with reader.connection() as conn, conn.cursor() as cur:
        cur.execute("SET TRANSACTION READ ONLY")
        cur.execute("""
            SELECT v.id,
                   EXISTS (SELECT 1 FROM invoices i WHERE i.vendor_id = v.id AND i.status = 'open') AS open_invoice,
                   v.under_audit
            FROM vendors v WHERE v.id = ANY(%s) AND v.archived_at IS NULL""", (ids,))
        rows = cur.fetchall()
        conn.rollback()
    open_invoice = sum(1 for _, has_open, _ in rows if has_open)
    under_audit = sum(1 for _, _, audited in rows if audited)
    safe = sorted(vid for vid, has_open, audited in rows if not has_open and not audited)
    protected = {k: v for k, v in (("open_invoice", open_invoice), ("under_audit", under_audit)) if v}
    return {"available": True, "estimated_rows": len(rows), "protected": protected, "safe_ids": safe}


def read_rows(query: str) -> dict[str, Any]:
    try:
        with reader.connection() as conn, conn.cursor() as cur:
            cur.execute("SET TRANSACTION READ ONLY")
            cur.execute("SET LOCAL statement_timeout = '2s'")
            cur.execute(f"SELECT count(*) FROM ({query.rstrip().rstrip(';')}) AS measured")  # noqa: S608
            count = cur.fetchone()[0]
            conn.rollback()
    except psycopg.Error:
        return unavailable()
    return {"available": True, "estimated_rows": count, "protected": {}}


def unavailable() -> dict[str, Any]:
    return {"available": False, "estimated_rows": 0, "protected": {}}


def _plain(value: Any) -> Any:
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    return str(value)
