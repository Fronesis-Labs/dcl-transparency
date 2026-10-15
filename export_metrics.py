"""
Run on the VPS (cron) to export current state into metrics.json for the
static GitHub Pages board. Read-only everywhere — never writes to any DCL db.

Example crontab (every 15 min):
    */15 * * * * cd /root/dcl-status-export && /root/dcl-trust-oracle-x402/venv/bin/python export_metrics.py

Assumes:
  - dcl_chain.db and dcl_chain_bazaar.db both have `chain` (dcl_core) +
    `chain_payments` (payment_log.sql) tables.
  - Sentinel verdicts in dcl_chain.db's `sentinel_events` table have been
    updated to COMMIT/NO_COMMIT (Дари's own fix, matching the rest of the stack).
  - `sentinel_events` has a timestamp column — NAME NOT CONFIRMED. Set
    SENTINEL_TS_COLUMN below to match the real column in sentinel_db.py's
    schema before relying on chronological ordering/recency for Sentinel rows.
    If the query fails, this script logs a warning and just omits the
    Sentinel section rather than crashing the whole export.
"""

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# Verified demo events. metrics.json is regenerated; this file is the source of truth.
DEMO_EVENTS_PATH = Path(__file__).with_name("canonical_demo_events.json")

# TODO confirm against sentinel_db.py's actual schema
SENTINEL_TS_COLUMN = "created_at"

# Newest chain rows exported per service. Bounds file size only: totals come
# from full-table queries below and do not depend on this value.
RECENT_EVENTS_LIMIT = int(os.environ.get("DCL_RECENT_EVENTS_LIMIT", "500"))

# Name of a chain_payments column CONFIRMED (schema + writer code) to hold the
# on-chain settlement transaction hash. None on purpose: chain_payments.tx_hash
# is the join key to chain.tx_hash, i.e. the local DCL audit hash, and must never
# be exported as a settlement hash.
PAYMENT_SETTLEMENT_COLUMN = None

_TX_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _ro_connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _table_columns(conn: sqlite3.Connection, table: str) -> set:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _ts_text(*candidates) -> "str | None":
    """UTC 'YYYY-MM-DD HH:MM:SS' (the existing public row format).

    Takes the first usable candidate: a unix epoch number or an ISO-8601 string
    (naive strings are treated as UTC, like the Board does).
    """
    for value in candidates:
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            try:
                dt = datetime.fromtimestamp(value, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                continue
        elif isinstance(value, str) and value.strip():
            try:
                dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            except ValueError:
                continue
            dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
        else:
            continue
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return None


def _canonical_index(events: list) -> dict:
    """proof.tx_hash (local DCL audit hash) -> canonical event.

    A hash claimed by more than one event is ambiguous and is dropped.
    """
    index, ambiguous = {}, set()
    for event in events:
        proof = event.get("proof") if isinstance(event, dict) else None
        audit_hash = proof.get("tx_hash") if isinstance(proof, dict) else None
        if not isinstance(audit_hash, str) or not audit_hash:
            continue
        if audit_hash in index:
            ambiguous.add(audit_hash)
        else:
            index[audit_hash] = event
    for audit_hash in ambiguous:
        index.pop(audit_hash, None)
    return index


def _exact_canonical_match(index: dict, audit_hash, agent_id, verdict, chain_n: int):
    """Canonical event for a legacy row, or None. Never invents anything.

    Requires a unique audit hash on both sides plus agreeing agent_id and verdict,
    and real string event_id/trace_id on the canonical event.
    """
    if not index or not isinstance(audit_hash, str) or chain_n > 1:
        return None
    event = index.get(audit_hash)
    if event is None:
        return None
    event_id, trace_id = event.get("event_id"), event.get("trace_id")
    if not (isinstance(event_id, str) and event_id and isinstance(trace_id, str) and trace_id):
        return None
    if event.get("agent_id") != agent_id or event.get("verdict") != verdict:
        return None
    return event


def _settlement_status(settle, audit_hash) -> tuple:
    """(tx_hash, status). Only a well-formed hash that differs from the audit hash qualifies."""
    if settle is None or settle == "":
        return None, "unavailable"
    if not isinstance(settle, str) or not _TX_HASH_RE.match(settle):
        return None, "malformed"
    if isinstance(audit_hash, str) and settle.lower() == audit_hash.lower():
        return None, "same_as_audit_hash"
    return settle, "settlement"


def _read_chain_service(db_path: str, service_name: str, canonical_index: dict = None) -> dict:
    if not os.path.exists(db_path):
        return {"available": False, "reason": f"{db_path} not found"}

    conn = _ro_connect(db_path)
    c = conn.cursor()

    # Totals: unchanged queries, so published metrics keep their meaning.
    total = c.execute("SELECT COUNT(*) FROM chain").fetchone()[0]
    commit_count = c.execute("SELECT COUNT(*) FROM chain WHERE verdict='COMMIT'").fetchone()[0]
    no_commit_count = total - commit_count
    unique_agents = c.execute("SELECT COUNT(DISTINCT agent_id) FROM chain").fetchone()[0]

    usdc_protected = c.execute(
        """
        SELECT COALESCE(SUM(p.amount_usdc), 0)
        FROM chain c JOIN chain_payments p ON p.tx_hash = c.tx_hash
        WHERE c.verdict = 'COMMIT'
        """
    ).fetchone()[0]

    chain_cols = _table_columns(conn, "chain")
    pay_cols = _table_columns(conn, "chain_payments")

    network_distribution = [
        {"network": row["network"] or "unknown", "count": row["cnt"]}
        for row in c.execute(
            """
            SELECT COALESCE(network, 'unknown') AS network, COUNT(*) AS cnt
            FROM chain_payments GROUP BY network
            """
            if "network" in pay_cols
            else "SELECT 'unknown' AS network, COUNT(*) AS cnt FROM chain_payments"
        ).fetchall()
    ]

    # Row-level view. One output row per chain row: payments are pre-aggregated per
    # tx_hash so a duplicated tx_hash can neither duplicate nor drop a row, and chain
    # rows without a payment row are kept (LEFT JOIN).
    def pay_agg(col: str) -> str:
        return f"MIN({col}) AS {col}" if col in pay_cols else f"NULL AS {col}"

    settle_col = PAYMENT_SETTLEMENT_COLUMN
    if settle_col and (not _IDENT_RE.match(settle_col) or settle_col == "tx_hash" or settle_col not in pay_cols):
        print(f"[export] ignoring PAYMENT_SETTLEMENT_COLUMN={settle_col!r}: not a distinct existing column")
        settle_col = None
    settle_sql = f"MIN({settle_col}) AS settle" if settle_col else "NULL AS settle"
    chain_route_sql = "c.route AS c_route" if "route" in chain_cols else "NULL AS c_route"

    rows = c.execute(
        f"""
        SELECT c.timestamp AS c_ts, c.agent_id, c.task_type, c.verdict,
               c.tx_hash AS audit_hash, {chain_route_sql},
               (SELECT COUNT(*) FROM chain c2 WHERE c2.tx_hash = c.tx_hash) AS chain_n,
               pa.pay_n, pa.amount_usdc, pa.network, pa.route AS p_route, pa.logged_at, pa.settle
        FROM chain c
        LEFT JOIN (
            SELECT tx_hash, COUNT(*) AS pay_n, MIN(amount_usdc) AS amount_usdc,
                   {pay_agg("network")}, {pay_agg("route")}, {pay_agg("logged_at")}, {settle_sql}
            FROM chain_payments GROUP BY tx_hash
        ) pa ON pa.tx_hash = c.tx_hash
        ORDER BY c.timestamp DESC, c.rowid DESC
        LIMIT ?
        """,
        (RECENT_EVENTS_LIMIT,),
    ).fetchall()

    recent = []
    for row in rows:
        pay_n, chain_n = row["pay_n"] or 0, row["chain_n"] or 0
        audit_hash = row["audit_hash"] if isinstance(row["audit_hash"], str) and row["audit_hash"] else None
        if not pay_n:
            payment = None
        elif pay_n > 1 or chain_n > 1:
            # More than one candidate payment (or audit row) for this hash: attributing
            # an amount would be a guess.
            payment = {"source": "chain_payments", "status": "ambiguous", "payment_rows": pay_n,
                       "amount_usdc": None, "network": None, "tx_hash": None, "tx_hash_status": "unavailable"}
        else:
            settle_hash, settle_status = _settlement_status(row["settle"], audit_hash)
            payment = {"source": "chain_payments", "status": "recorded", "payment_rows": 1,
                       "amount_usdc": row["amount_usdc"], "network": row["network"] or None,
                       "tx_hash": settle_hash, "tx_hash_status": settle_status}
        entry = {
            "service": service_name,
            "timestamp": _ts_text(row["logged_at"], row["c_ts"]),
            "agent_id": row["agent_id"],
            "task_type": row["task_type"],
            "verdict": row["verdict"],
            "route": (row["p_route"] if payment and payment["status"] == "recorded" else None) or row["c_route"],
            "amount_usdc": payment["amount_usdc"] if payment else None,
            "record_kind": "legacy_chain_row",
            "audit_hash": audit_hash,
            "payment": payment,
            "canonical_link": "none",
        }
        match = _exact_canonical_match(canonical_index, audit_hash, row["agent_id"], row["verdict"], chain_n)
        if match is not None:
            entry["event_id"] = match["event_id"]
            entry["trace_id"] = match["trace_id"]
            entry["canonical_link"] = "exact_audit_hash"
        recent.append(entry)

    row_integrity = {
        "chain_rows_without_payment": c.execute(
            "SELECT COUNT(*) FROM chain c WHERE NOT EXISTS (SELECT 1 FROM chain_payments p WHERE p.tx_hash = c.tx_hash)"
        ).fetchone()[0],
        "payment_rows_without_chain": c.execute(
            "SELECT COUNT(*) FROM chain_payments p WHERE NOT EXISTS (SELECT 1 FROM chain c WHERE c.tx_hash = p.tx_hash)"
        ).fetchone()[0],
        "chain_rows_sharing_tx_hash": c.execute(
            "SELECT COALESCE(SUM(n), 0) FROM (SELECT COUNT(*) AS n FROM chain WHERE tx_hash IS NOT NULL GROUP BY tx_hash HAVING n > 1)"
        ).fetchone()[0],
        "payment_rows_sharing_tx_hash": c.execute(
            "SELECT COALESCE(SUM(n), 0) FROM (SELECT COUNT(*) AS n FROM chain_payments WHERE tx_hash IS NOT NULL GROUP BY tx_hash HAVING n > 1)"
        ).fetchone()[0],
    }

    conn.close()
    return {
        "available": True,
        "total_audits": total,
        "commit_count": commit_count,
        "no_commit_count": no_commit_count,
        "unique_agents": unique_agents,
        "usdc_protected": round(usdc_protected, 2),
        "network_distribution": network_distribution,
        "row_integrity": row_integrity,
        "recent_events": recent,
    }


def _read_sentinel(db_path: str) -> dict:
    if not os.path.exists(db_path):
        return {"available": False, "reason": f"{db_path} not found"}
    try:
        conn = _ro_connect(db_path)
        c = conn.cursor()
        total = c.execute("SELECT COUNT(*) FROM sentinel_events").fetchone()[0]
        commit_count = c.execute(
            "SELECT COUNT(*) FROM sentinel_events WHERE verdict='COMMIT'"
        ).fetchone()[0]
        usdc_collected = c.execute(
            "SELECT COALESCE(SUM(amount_paid), 0) FROM sentinel_events"
        ).fetchone()[0]
        recent = [
            {
                "service": "sentinel",
                "timestamp": row[SENTINEL_TS_COLUMN],
                "verdict": row["verdict"],
                "scan_type": row["scan_type"],
                "amount_usdc": row["amount_paid"],
            }
            for row in c.execute(
                f"""
                SELECT {SENTINEL_TS_COLUMN}, verdict, scan_type, amount_paid
                FROM sentinel_events ORDER BY {SENTINEL_TS_COLUMN} DESC
                """
            ).fetchall()
        ]
        conn.close()
        return {
            "available": True,
            "total_events": total,
            "commit_count": commit_count,
            "no_commit_count": total - commit_count,
            "usdc_collected": round(usdc_collected, 2),
            "recent_events": recent,
        }
    except Exception as e:
        print(f"[export] sentinel_events read failed (check SENTINEL_TS_COLUMN): {e}")
        return {"available": False, "reason": str(e)}


def _read_canonical_audit_events(path: str) -> dict:
    """Load frozen v1.0 events for the board's canonical panel.

    Accepts one event object, a list of event objects, or {"events": [...]}.
    These rows are not production chain traffic and are not added to totals.
    """
    if not path:
        return {
            "available": False,
            "reason": "Canonical audit events are not configured.",
        }
    if not os.path.exists(path):
        return {
            "available": False,
            "reason": f"{path} not found",
        }
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[export] canonical audit events read failed: {exc}")
        return {"available": False, "reason": "Canonical audit event file could not be read."}

    if isinstance(payload, dict) and isinstance(payload.get("events"), list):
        events = [event for event in payload["events"] if isinstance(event, dict)]
    elif isinstance(payload, dict) and payload.get("event_type") == "dcl.audit.evaluated":
        events = [payload]
    elif isinstance(payload, list):
        events = [event for event in payload if isinstance(event, dict)]
    else:
        return {
            "available": False,
            "reason": "Canonical audit event file is not a v1.0 event.",
        }
    return {"available": True, "total": len(events), "events": events}


def _event_list(payload) -> list:
    if isinstance(payload, dict) and isinstance(payload.get("events"), list):
        return [event for event in payload["events"] if isinstance(event, dict)]
    if isinstance(payload, dict) and isinstance(payload.get("canonical_audit_events"), dict):
        return _event_list(payload["canonical_audit_events"])
    if isinstance(payload, dict) and payload.get("event_type") == "dcl.audit.evaluated":
        return [payload]
    if isinstance(payload, list):
        return [event for event in payload if isinstance(event, dict)]
    return []


def _read_json_events(path: str) -> list:
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as handle:
            return _event_list(json.load(handle))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[export] canonical event read failed for {path}: {exc}")
        return []


def _merge_canonical_events(*groups: list) -> dict:
    """Keep earlier events, then add any later event whose event_id is new.

    Demo events belong only in this list. Callers must not copy them into
    recent_events or audit totals.
    """
    merged = []
    seen = set()
    for group in groups:
        for event in group:
            if not isinstance(event, dict):
                continue
            event_id = event.get("event_id")
            key = event_id if isinstance(event_id, str) and event_id else json.dumps(event, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            merged.append(event)
    if not merged:
        return {
            "available": False,
            "reason": "Canonical audit events are not configured.",
        }
    return {"available": True, "total": len(merged), "events": merged}


def main():
    webhook_db = os.environ.get("DCL_CHAIN_DB", "dcl_chain.db")
    bazaar_db = os.environ.get("DCL_CHAIN_BAZAAR_DB", "dcl_chain_bazaar.db")
    out_path = os.environ.get("METRICS_OUT_PATH", "metrics.json")
    canonical_path = os.environ.get("CANONICAL_AUDIT_EVENTS_PATH", "")
    demo_path = os.environ.get("CANONICAL_DEMO_EVENTS_PATH")
    if demo_path is None:
        demo_path = str(DEMO_EVENTS_PATH)

    canonical = _merge_canonical_events(
        _read_json_events(out_path),
        _read_json_events(canonical_path),
        _read_json_events(demo_path),
    )
    canonical_index = _canonical_index(canonical.get("events") or [])

    webhook = _read_chain_service(webhook_db, "webhook", canonical_index)
    bazaar = _read_chain_service(bazaar_db, "bazaar", canonical_index)
    sentinel = _read_sentinel(webhook_db)  # sentinel_events lives in the same db as webhook

    identity_guard = {
        "available": False,
        "status": "no_live_traffic",
        "note": "x402-identity-guard is currently a library with no deployed "
                "instance producing traffic — this section will populate once "
                "a reference/demo deployment exists.",
    }

    total_audits = sum(
        s.get("total_audits", 0) for s in (webhook, bazaar) if s.get("available")
    ) + (sentinel.get("total_events", 0) if sentinel.get("available") else 0)

    total_usdc = round(
        sum(s.get("usdc_protected", 0) for s in (webhook, bazaar) if s.get("available"))
        + (sentinel.get("usdc_collected", 0) if sentinel.get("available") else 0),
        2,
    )

    recent_all = sorted(
        (
            *(webhook.get("recent_events", []) if webhook.get("available") else []),
            *(bazaar.get("recent_events", []) if bazaar.get("available") else []),
            *(sentinel.get("recent_events", []) if sentinel.get("available") else []),
        ),
        key=lambda e: str(e.get("timestamp") or ""),
        reverse=True,
    )

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_audits": total_audits,
        "total_usdc_protected": total_usdc,
        "recent_events": recent_all,
        "canonical_audit_events": canonical,
        "services": {
            "webhook": webhook,
            "bazaar": bazaar,
            "sentinel": sentinel,
            "identity_guard": identity_guard,
        },
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    canonical_count = len(payload["canonical_audit_events"].get("events") or [])
    print(
        f"wrote {out_path}: {total_audits} total audits across services, "
        f"{canonical_count} canonical audit event(s)"
    )


if __name__ == "__main__":
    main()
