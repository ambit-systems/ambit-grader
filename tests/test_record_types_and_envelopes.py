# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Regressions for four defects found verifying against a captured ledger.

Each test pins a way the grader systematically misread real evidence: scoring
non-decision records as decision events, ignoring the nested envelopes that
carry authority on Ambit's native format, losing bare allows out of the
denominator, and certifying a corpus from a two-record chain inside it.
"""

from __future__ import annotations

from ambit_grader import Property, Sufficiency, grade_records
from ambit_grader.adapters.normalise import Normalised, is_decision_event, normalise
from ambit_grader.joins import chain_integrity, principal_authority


def _decision(seq, decision, prev, own, **extra):
    record = {
        "seq": seq,
        "ts": "2026-03-01T00:00:00Z",
        "record_type": "decision",
        "actor_id": "agent-1",
        "tool_name": "t",
        "action": {"type": "write", "boundary": "tool_execution"},
        "object": {"kind": "f", "id": "i", "domain": "d"},
        "governance_mode": "enforcement",
        "decision": decision,
        "prev_hash": prev,
        "record_hash": own,
    }
    record.update(extra)
    return record


def test_non_decision_record_types_are_not_decision_events():
    assert is_decision_event({"record_type": "decision", "decision": "ALLOW"})
    assert is_decision_event({"decision": "ALLOW"})  # legacy flat receipt
    for other in ("approval", "consequence_intent", "outcome", "observatory_score", "shutdown"):
        assert not is_decision_event({"record_type": other})


def test_fragment_records_do_not_drag_decision_properties_down():
    """An outcome record has no action or object; it must not score as one."""
    decision = _decision(0, "ALLOW", "0" * 64, "h1", policy_hash="9f2c41ab", matched_rule_id="r")
    fragments = [
        {"seq": 1, "record_type": "outcome", "prev_hash": "h1", "record_hash": "h2"},
        {"seq": 2, "record_type": "observatory_score", "prev_hash": "h2", "record_hash": "h3"},
    ]

    graded = grade_records("mixed", [decision, *fragments])
    assert graded.verdicts[Property.ACTION_BOUNDARY].sufficiency is Sufficiency.FULLY_FILLABLE
    assert graded.verdicts[Property.DATA_TOUCH].sufficiency is Sufficiency.FULLY_FILLABLE


def test_nested_approval_envelope_resolves_authority():
    """Real receipts carry the join result inside `approval`, not at top level."""
    resolved = _decision(
        0,
        "ESCALATE",
        "0" * 64,
        "h1",
        approval={"approver": "approver-alpha", "fingerprint_bound": True, "valid": True},
    )
    assert principal_authority([resolved]).sufficiency is Sufficiency.FULLY_FILLABLE


def test_empty_approval_envelope_does_not_resolve_authority():
    """`approver: null, fingerprint_bound: false` is an envelope, not evidence."""
    unresolved = _decision(
        0,
        "ESCALATE",
        "0" * 64,
        "h1",
        approval={"approver": None, "fingerprint_bound": False, "valid": False},
    )
    assert principal_authority([unresolved]).sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE


def test_hmac_delegation_without_issuer_is_capped_at_partial():
    """The envelope names the delegate, not the grantor — so not a named principal.

    A corpus of nothing but delegations must never report full attribution:
    that would be the grader flattering its own vendor's primary artifact,
    which is the one bias the independence argument cannot survive. HMAC
    cannot rescue it either — its verify key is its forge key.
    """
    delegated = _decision(
        0,
        "ALLOW",
        "0" * 64,
        "h1",
        delegation={
            "id": "deleg-risky-send-1",
            "jti": "deleg-risky-send-1",
            "kind": "hmac_token",
            "subject": "agent-risky",
            "valid": True,
        },
    )
    verdict = principal_authority([delegated])
    assert verdict.sufficiency is Sufficiency.PARTIALLY_FILLABLE
    assert "issuer is not evidenced" in (verdict.detail or "")
    assert "evidence the issuer" in (verdict.recommendation or "")


def test_invalid_delegation_is_not_authority_evidence():
    """`valid: false` is a delegation the runtime itself rejected."""
    rejected = _decision(
        0,
        "ALLOW",
        "0" * 64,
        "h1",
        delegation={"id": "d-1", "jti": "d-1", "kind": "hmac_token", "valid": False},
    )
    detail = principal_authority([rejected]).detail or ""
    assert "1 with no authority evidence at all" in detail


def test_revoked_delegation_is_not_authority_evidence():
    revoked = _decision(
        0,
        "ALLOW",
        "0" * 64,
        "h1",
        delegation={"id": "d-1", "jti": "d-1", "kind": "hmac_token", "revoked": True},
    )
    detail = principal_authority([revoked]).detail or ""
    assert "1 with no authority evidence at all" in detail


def test_asymmetric_delegation_with_a_trust_root_names_the_principal():
    """An asymmetric signature binds a trust root that identifies the issuer."""
    signed = _decision(
        0,
        "ALLOW",
        "0" * 64,
        "h1",
        delegation={
            "id": "d-1",
            "jti": "d-1",
            "kind": "ed25519_token",
            "trust_root_id": "ops-root",
            "valid": True,
        },
    )
    assert principal_authority([signed]).sufficiency is Sufficiency.FULLY_FILLABLE


def test_unknown_kind_delegation_envelope_is_not_evidence():
    empty = _decision(
        0, "ALLOW", "0" * 64, "h1", delegation={"id": None, "jti": None, "kind": "unknown"}
    )
    assert principal_authority([empty]).sufficiency is not Sufficiency.FULLY_FILLABLE


def test_bare_allow_cannot_be_lost_from_the_denominator():
    """One attributed escalation plus one bare allow is not full attribution."""
    attributed = _decision(
        0,
        "ESCALATE",
        "0" * 64,
        "h1",
        approval={"approver": "approver-alpha", "fingerprint_bound": True, "valid": True},
    )
    bare = _decision(1, "ALLOW", "h1", "h2")  # no policy identity, no principal

    verdict = principal_authority([attributed, bare])
    assert verdict.sufficiency is Sufficiency.PARTIALLY_FILLABLE
    assert "1 with no authority evidence at all" in (verdict.detail or "")
    assert "bare allow" in (verdict.recommendation or "")


def test_authority_counts_sum_to_the_permitted_total():
    records = [
        _decision(0, "ESCALATE", "0" * 64, "h1"),
        _decision(1, "ALLOW", "h1", "h2", policy_hash="9f2c41ab"),
        _decision(2, "ALLOW", "h2", "h3"),
        _decision(3, "DENY", "h3", "h4"),
    ]
    detail = principal_authority(records).detail or ""
    assert "3 permitted action(s)" in detail
    assert "1 denial(s) excluded" in detail


def test_unchained_records_stay_in_the_verification_denominator():
    """Two linked records must not certify a corpus of ten."""
    chained = [
        _decision(0, "ALLOW", "0" * 64, "h1"),
        _decision(1, "ALLOW", "h1", "h2"),
    ]
    unchained = [{"seq": i, "record_type": "decision", "decision": "ALLOW"} for i in range(2, 10)]

    verdict = chain_integrity([*chained, *unchained])
    assert verdict.sufficiency is Sufficiency.PARTIALLY_FILLABLE
    assert "8 outside it" in (verdict.detail or "")


def test_next_move_targets_the_weakest_spine_property_not_the_first():
    """A stronger but earlier-declared property must not win the recommendation."""
    signed = {
        "id": "d-1",
        "jti": "d-1",
        "kind": "ed25519_token",
        "trust_root_id": "ops-root",
        "valid": True,
    }
    records = [
        _decision(0, "ALLOW", "not-genesis", "h1", policy_hash="9f2c41ab", delegation=signed),
        _decision(1, "ALLOW", "h1", "h2", policy_hash="9f2c41ab", delegation=signed),
    ]
    graded = grade_records("x", records)
    assert graded.verdicts[Property.PRINCIPAL_AUTHORITY].sufficiency is Sufficiency.FULLY_FILLABLE
    assert graded.verdicts[Property.VERIFICATION_STRENGTH].sufficiency is not (
        Sufficiency.FULLY_FILLABLE
    )
    assert "chain" in graded.next_move() or "genesis" in graded.next_move()


def test_typeless_foreign_jsonl_falls_back_to_scoring_every_record():
    """Homegrown logs carry no record_type and no verdict field.

    With nothing to type on, the adapter cannot separate decision events from
    fragments, so every record is scored. The fallback is deliberate — the
    alternative is grading a foreign corpus as if it were empty — but it is
    silent, so it is pinned here rather than left to be discovered.
    """
    foreign = [
        {"actor_id": "svc-1", "tool_name": "charge", "ts": "2026-03-01T00:00:00Z", "seq": 0},
        {"actor_id": "svc-1", "tool_name": "refund", "ts": "2026-03-01T00:01:00Z", "seq": 1},
    ]
    assert not any(is_decision_event(r) for r in foreign)

    graded = grade_records("foreign.jsonl", foreign)
    assert graded.record_count == 2
    assert graded.unrecognised == 0
    assert "generic_jsonl" in graded.shapes
    # Scored, not skipped: actor identity is present in both records.
    assert graded.verdicts[Property.ACTOR_IDENTITY].sufficiency is Sufficiency.FULLY_FILLABLE
    # ...and no authority can be claimed from records that record no verdict.
    assert (
        graded.verdicts[Property.PRINCIPAL_AUTHORITY].sufficiency
        is Sufficiency.STRUCTURALLY_UNFILLABLE
    )


def test_mixed_corpus_does_not_trigger_the_fallback():
    """One typed decision event is enough to disable the fallback."""
    typed = _decision(0, "ALLOW", "0" * 64, "h1", policy_hash="9f2c41ab")
    fragment = {"record_type": "outcome", "seq": 1, "prev_hash": "h1", "record_hash": "h2"}

    graded = grade_records("mixed", [typed, fragment])
    # The fragment has no action; if it were scored the property would drop.
    assert graded.verdicts[Property.ACTION_BOUNDARY].sufficiency is Sufficiency.FULLY_FILLABLE


def test_receipt_payload_shape_does_not_crash_the_grader():
    """The engine's own raw receipt shape must grade, not raise.

    The Ambit decision ledger emits `decision: "ALLOW"`; the Ambit engine's raw
    receipt emits `decision: {"outcome": "allow", ...}`. The grader crashed
    with a TypeError on the second — its own vendor's current engine output —
    which is the worst available failure for a tool whose pitch is reading
    evidence honestly.
    """
    payload_shape = {
        "actor": {"id": "agent-1"},
        "action": {"type": "read", "boundary": "tool_execution"},
        "object": {"kind": "path", "id": "/tmp/a", "domain": "filesystem"},
        "decision": {
            "outcome": "allow",
            "reasons": [{"rule_id": "sandbox_boundary", "result": "pass", "details": None}],
        },
        "evidence": {"hashes": {"policy_hash": "9f2c41ab", "request_fingerprint": "fp-1"}},
        "delegation": {
            "id": "d-1",
            "jti": "d-1",
            "kind": "ed25519_token",
            "trust_root_id": "ops-root",
            "valid": True,
        },
    }
    graded = grade_records("payload", [payload_shape])

    assert graded.unrecognised == 0
    assert "ambit_receipt_payload" in graded.shapes
    # The object verdict was read, so the action counts as permitted.
    assert "1 permitted action(s)" in (graded.verdicts[Property.PRINCIPAL_AUTHORITY].detail or "")
    # Nested hashes and reasons were lifted onto canonical paths.
    assert graded.verdicts[Property.POLICY_BASIS].sufficiency is not (
        Sufficiency.STRUCTURALLY_UNFILLABLE
    )


def test_unreadable_records_are_counted_not_raised():
    """A record that says nothing is skipped and named, never a stack trace."""
    graded = grade_records("junk", [{"foo": 1}, {"bar": {"baz": 2}}])
    assert graded.unrecognised == 2
    assert "unrecognised" in graded.shapes


def test_summary_names_shapes_and_the_skipped_count():
    assert Normalised().summary() == "no records"
    ledger = _decision(0, "ALLOW", "0" * 64, "h1")
    approval = {"record_type": "approval", "approval_fingerprint": "fp-1"}
    assert normalise([ledger, approval]).summary() == "1 ambit_approval, 1 ambit_ledger"
    assert (
        normalise([ledger, {"nothing": True}]).summary()
        == "1 ambit_ledger, 1 unrecognised (skipped)"
    )


def test_mixed_shapes_are_reported_separately():
    ledger = _decision(0, "ALLOW", "0" * 64, "h1", policy_hash="9f2c41ab")
    payload = {"actor": {"id": "a"}, "decision": {"outcome": "deny", "reasons": []}}
    graded = grade_records("mixed", [ledger, payload, {"nothing": True}])
    assert "ambit_ledger" in graded.shapes
    assert "ambit_receipt_payload" in graded.shapes
    assert graded.unrecognised == 1


def test_adapter_specific_tool_name_keys_are_all_read():
    """Adapters disagree on the key; the fact is the same fact.

    HTTP and MCP write `name` into their raw provenance block; A2A writes
    `operation` for the protocol method it invoked. Reading only one of them
    reports a tool name as missing while it sits in the record — a false
    finding, which is worse than a strict one.
    """
    from ambit_grader.adapters.normalise import normalise_record

    for adapter, block in (
        ("http", {"name": "customer.read"}),
        ("mcp", {"name": "customer.read"}),
        ("a2a", {"operation": "message/send"}),
    ):
        record = {
            "record_type": "decision",
            "decision": "ALLOW",
            "actor_id": "agent-1",
            "action": {"type": "read", "boundary": "network_egress"},
            "evidence": {"raw": {adapter: block}},
        }
        mapped = normalise_record(record)
        assert mapped is not None
        assert mapped.get("tool_name"), f"{adapter} tool name not recovered"


def test_a_missing_tool_name_is_still_reported_missing():
    """The synonym list must not become a way to always find something."""
    from ambit_grader.adapters.normalise import normalise_record

    record = {
        "record_type": "decision",
        "decision": "ALLOW",
        "actor_id": "agent-1",
        "action": {"type": "read", "boundary": "network_egress"},
        "evidence": {"raw": {"http": {"arguments": {"route": "/v1"}}}},
    }
    mapped = normalise_record(record)
    assert mapped is not None
    assert "tool_name" not in mapped
