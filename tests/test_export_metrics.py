import pytest
from export_metrics import _settlement_status, _canonical_index, _exact_canonical_match


def test_settlement_status_unavailable_when_empty():
    tx, status = _settlement_status(None, None)
    assert tx is None and status == "unavailable"


def test_settlement_status_malformed():
    tx, status = _settlement_status("not-a-hash", "0xabc")
    assert tx is None and status == "malformed"


def test_settlement_status_same_as_audit_hash():
    audit = "0x" + "a" * 64
    tx, status = _settlement_status(audit, audit)
    # same as audit (case-insensitive)
    assert tx is None and status == "same_as_audit_hash"


def test_settlement_status_valid():
    audit = "0x" + "a" * 64
    settle = "0x" + "b" * 64
    tx, status = _settlement_status(settle, audit)
    assert tx == settle and status == "settlement"


def test_canonical_index_and_ambiguity():
    events = [
        {"proof": {"tx_hash": "0x" + "1" * 64}, "event_id": "e1"},
        {"proof": {"tx_hash": "0x" + "2" * 64}, "event_id": "e2"},
        {"proof": {"tx_hash": "0x" + "1" * 64}, "event_id": "e3"},  # duplicate hash
    ]
    idx = _canonical_index(events)
    # the duplicate hash should be removed from index
    assert ("0x" + "1" * 64) not in idx
    assert ("0x" + "2" * 64) in idx and idx[("0x" + "2" * 64)]["event_id"] == "e2"


def test_exact_canonical_match_requires_unique_hash_and_match():
    audit_hash = "0x" + "f" * 64
    events = [{"proof": {"tx_hash": audit_hash}, "event_id": "evt1", "trace_id": "tr1", "agent_id": "agent-x", "verdict": "COMMIT"}]
    idx = _canonical_index(events)
    # chain_n > 1 blocks match
    assert _exact_canonical_match(idx, audit_hash, "agent-x", "COMMIT", 2) is None
    # mismatch agent blocks
    assert _exact_canonical_match(idx, audit_hash, "other-agent", "COMMIT", 1) is None
    # correct match
    matched = _exact_canonical_match(idx, audit_hash, "agent-x", "COMMIT", 1)
    assert matched is not None and matched["event_id"] == "evt1"
