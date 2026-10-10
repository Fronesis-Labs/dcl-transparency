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
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# Verified demo events. metrics.json is regenerated; this file is the source of truth.
DEMO_EVENTS_PATH = Path(__file__).with_name("canonical_demo_events.json")

# TODO confirm against sentinel_db.py's actual schema
SENTINEL_TS_COLUMN = "created_at"


def _ro_connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _read_chain_service(db_path: str, service_name: str) -> dict:
    if not os.path.exists(db_path):
        return {"available": False, "reason": f"{db_path} not found"}

    conn = _ro_connect(db_path)
    c = conn.cursor()

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

    network_distribution = [
        {"network": row["network"] or "unknown", "count": row["cnt"]}
        for row in c.execute(
            """
            SELECT COALESCE(network, 'unknown') AS network, COUNT(*) AS cnt
            FROM chain_payments GROUP BY network
            """
        ).fetchall()
    ]

    recent = [
        {
            "service": service_name,
            "timestamp": datetime.fromtimestamp(row["timestamp"], tz=timezone.utc).isoformat(timespec="seconds"),
            "agent_id": row["agent_id"],
            "task_type": row["task_type"],
            "verdict": row["verdict"],
            "amount_usdc": row["amount_usdc"],
        }
        for row in c.execute(
            f"""
            SELECT c.timestamp, c.agent_id, c.task_type, c.verdict, p.amount_usdc
            FROM chain c LEFT JOIN chain_payments p ON p.tx_hash = c.tx_hash
            ORDER BY c.timestamp DESC
            """
        ).fetchall()
    ]

    conn.close()
    return {
        "available": True,
        "total_audits": total,
        "commit_count": commit_count,
        "no_commit_count": no_commit_count,
        "unique_agents": unique_agents,
        "usdc_protected": round(usdc_protected, 2),
        "network_distribution": network_distribution,
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

    webhook = _read_chain_service(webhook_db, "webhook")
    bazaar = _read_chain_service(bazaar_db, "bazaar")
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
        key=lambda e: e["timestamp"],
        reverse=True,
    )

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_audits": total_audits,
        "total_usdc_protected": total_usdc,
        "recent_events": recent_all,
        "canonical_audit_events": _merge_canonical_events(
            _read_json_events(out_path),
            _read_json_events(canonical_path),
            _read_json_events(demo_path),
        ),
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
