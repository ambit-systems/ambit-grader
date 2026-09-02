# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the corpus-level joins: chain integrity and principal authority."""

from __future__ import annotations

from ambit_grader.joins import chain_integrity, principal_authority
from ambit_grader.models import Sufficiency


def _decision(seq, decision, prev, own, **extra):
    record = {
        "seq": seq,
        "record_type": "decision",
        "actor_id": "agent-1",
        "decision": decision,
        "prev_hash": prev,
        "record_hash": own,
    }
    record.update(extra)
    return record


def test_chain_needs_two_linked_records():
    assert chain_integrity([]).sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE
    single = [_decision(0, "ALLOW", "0" * 64, "h1")]
    assert chain_integrity(single).sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE


def test_clean_chain_from_genesis_is_evidenced():
    records = [
        _decision(0, "ALLOW", "0" * 64, "h1"),
        _decision(1, "ALLOW", "h1", "h2"),
        _decision(2, "ALLOW", "h2", "h3"),
    ]
    verdict = chain_integrity(records)
    assert verdict.sufficiency is Sufficiency.FULLY_FILLABLE
    assert "3 records link cleanly" in (verdict.detail or "")


def test_unanchored_chain_is_partial_not_evidenced():
    records = [
        _decision(0, "ALLOW", "not-genesis", "h1"),
        _decision(1, "ALLOW", "h1", "h2"),
    ]
    verdict = chain_integrity(records)
    assert verdict.sufficiency is Sufficiency.PARTIALLY_FILLABLE
    assert "genesis" in (verdict.recommendation or "")


def test_broken_link_is_reported_with_a_count():
    records = [
        _decision(0, "ALLOW", "0" * 64, "h1"),
        _decision(1, "ALLOW", "WRONG", "h2"),
    ]
    verdict = chain_integrity(records)
    assert verdict.sufficiency is Sufficiency.PARTIALLY_FILLABLE
    assert "1 of 1 links broken" in (verdict.detail or "")


def test_resolved_escalations_evidence_authority():
    records = [
        _decision(0, "ESCALATE", "0" * 64, "h1", request_fingerprint="fp-1"),
        {
            "seq": 1,
            "record_type": "approval",
            "actor_id": "agent-1",
            "approval_fingerprint": "fp-1",
            "approval_approver": "approver-alpha",
            "prev_hash": "h1",
            "record_hash": "h2",
        },
    ]
    assert principal_authority(records).sufficiency is Sufficiency.FULLY_FILLABLE


def test_precomputed_fingerprint_bound_is_authoritative():
    """Ambit engine receipts state the join result; no fingerprint match needed."""
    records = [
        _decision(
            0,
            "ESCALATE",
            "0" * 64,
            "h1",
            fingerprint_bound=True,
            approver="approver-alpha",
        )
    ]
    assert principal_authority(records).sufficiency is Sufficiency.FULLY_FILLABLE


def test_unresolved_escalation_floors_authority_to_missing():
    records = [_decision(0, "ESCALATE", "0" * 64, "h1", request_fingerprint="fp-1")]
    verdict = principal_authority(records)
    assert verdict.sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE
    assert "unresolved escalation" in (verdict.recommendation or "")


def test_policy_permitted_allows_are_capped_at_partial():
    """Permission is not authority; an automatic allow names no principal."""
    records = [
        _decision(0, "ALLOW", "0" * 64, "h1", policy_hash="9f2c41ab"),
        _decision(1, "ALLOW", "h1", "h2", policy_hash="9f2c41ab"),
    ]
    verdict = principal_authority(records)
    assert verdict.sufficiency is Sufficiency.PARTIALLY_FILLABLE
    assert "attest the policy" in (verdict.recommendation or "")


def test_denials_alone_leave_nothing_to_attribute():
    records = [_decision(0, "DENY", "0" * 64, "h1")]
    verdict = principal_authority(records)
    assert verdict.sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE
    assert "no permitted actions" in (verdict.detail or "")


def test_unresolved_escalation_is_a_cross_stack_boundary_not_a_missing_write():
    """The reason changes the remedy, so it must be the right reason.

    An escalation implies an approval step happened somewhere. Reporting
    "evidence never persisted" would send an operator to instrument a field
    nobody emits; "cross-stack boundary" sends them to join the approval
    system that already holds it.
    """
    from ambit_grader.models import UnfillableReason

    records = [_decision(0, "ESCALATE", "0" * 64, "h1", request_fingerprint="fp-1")]
    verdict = principal_authority(records)
    assert verdict.sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE
    assert verdict.reason is UnfillableReason.CROSS_STACK_BOUNDARY


def test_absent_fields_are_reported_as_never_persisted():
    """A field the runtime could have written and did not is a different fault."""
    from ambit_grader import Property, grade_records
    from ambit_grader.models import UnfillableReason

    graded = grade_records("bare", [_decision(0, "ALLOW", "0" * 64, "h1")])
    data_touch = graded.verdicts[Property.DATA_TOUCH]
    assert data_touch.reason is UnfillableReason.EVIDENCE_NEVER_PERSISTED


def test_all_permitted_actions_unaccounted_is_unfillable_not_partial():
    """Nothing recoverable is not the same as partially recoverable.

    DEMM's partially_fillable means recoverable evidence plus a gap
    description. Where every permitted action lacks a principal, a policy and
    a delegation alike, there is nothing to partially recover.
    """
    records = [_decision(0, "ALLOW", "0" * 64, "h1")]
    verdict = principal_authority(records)
    assert verdict.sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE
    assert "1 with no authority evidence at all" in (verdict.detail or "")


def test_some_unaccounted_stays_partial():
    """A mixed corpus keeps its recoverable share."""
    attributed = _decision(
        0,
        "ESCALATE",
        "0" * 64,
        "h1",
        approval={"approver": "a", "fingerprint_bound": True, "valid": True},
    )
    bare = _decision(1, "ALLOW", "h1", "h2")
    assert principal_authority([attributed, bare]).sufficiency is (Sufficiency.PARTIALLY_FILLABLE)


def test_genuine_bound_approval_still_resolves_after_the_foreign_adapter_fix():
    """Guard against over-correction on Ambit's own native path.

    The foreign-adapter fix stops `fingerprint_bound` from being fabricated
    on formats with no binding evidence. Native records never pass through
    that adapter, and a genuinely bound approval — the engine's own resolved
    join — must still fully resolve exactly as before.
    """
    records = [
        _decision(
            0,
            "ESCALATE",
            "0" * 64,
            "h1",
            approval={"approver": "approver-alpha", "fingerprint_bound": True, "valid": True},
        )
    ]
    assert principal_authority(records).sufficiency is Sufficiency.FULLY_FILLABLE


def test_named_but_unbound_approver_is_distinguished_from_no_approver_at_all():
    """The second-cycle fix: two different gaps must not read as one.

    "No approver anywhere" and "an approver is named but nothing binds it to
    this action" are different findings with different remedies — collect a
    first approval versus bind the one already there. Before this fix both
    collapsed into the same generic "no authority evidence at all" bucket.
    """
    bare = _decision(0, "ALLOW", "0" * 64, "h1")
    named_unbound = _decision(
        1, "ALLOW", "h1", "h2", approval={"approver": "alice", "fingerprint_bound": False}
    )

    bare_verdict = principal_authority([bare])
    unbound_verdict = principal_authority([named_unbound])

    # Same Sufficiency semantics either way: an unbound name earns no more
    # credit than no name at all. DEMM's partial category means recoverable
    # evidence plus a gap description, and an unbound name is not recoverable
    # evidence, so no partial credit is invented for it.
    assert bare_verdict.sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE
    assert unbound_verdict.sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE

    assert "0 naming an approver not bound to this action" in (bare_verdict.detail or "")
    assert "1 with no authority evidence at all" in (bare_verdict.detail or "")

    assert "1 naming an approver not bound to this action" in (unbound_verdict.detail or "")
    assert "0 with no authority evidence at all" in (unbound_verdict.detail or "")


def test_unbound_approver_recommendation_says_bind_not_add():
    """The recommendation must point at the join, not at collecting a name.

    Recommending "add an approver" for a record that already names one would
    send an operator to gather evidence that is already sitting in the file.
    What is actually missing is the link from that name to this request.
    """
    named_unbound = _decision(
        0, "ALLOW", "0" * 64, "h1", approval={"approver": "alice", "fingerprint_bound": False}
    )
    recommendation = principal_authority([named_unbound]).recommendation or ""
    assert "bind" in recommendation
    assert "add an approver" not in recommendation.lower()


def test_mixed_bare_and_named_unbound_are_both_named_in_the_detail():
    """A corpus can carry both gaps at once; the counts must not merge."""
    bare = _decision(0, "ALLOW", "0" * 64, "h1")
    named_unbound = _decision(
        1, "ALLOW", "h1", "h2", approval={"approver": "alice", "fingerprint_bound": False}
    )
    detail = principal_authority([bare, named_unbound]).detail or ""
    assert "1 naming an approver not bound to this action" in detail
    assert "1 with no authority evidence at all" in detail
