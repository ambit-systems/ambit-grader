# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the corpus-level joins: chain integrity and principal authority."""

from __future__ import annotations

from ambit_grader import Property, grade_records
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
            "approval_jti": "approval-1",
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


def test_missing_or_invalid_authority_artifacts_do_not_resolve():
    missing_delegation_status = _decision(
        0,
        "ALLOW",
        "0" * 64,
        "h1",
        delegation={
            "id": "d-1",
            "kind": "ed25519_token",
            "trust_root_id": "alice",
        },
    )
    flat_invalid = _decision(
        0,
        "ESCALATE",
        "0" * 64,
        "h1",
        approver="alice",
        fingerprint_bound=True,
        valid=False,
    )
    flat_malformed = _decision(
        0,
        "ESCALATE",
        "0" * 64,
        "h1",
        approver="alice",
        fingerprint_bound=True,
        valid=0,
    )
    nested_invalid = _decision(
        0,
        "ESCALATE",
        "0" * 64,
        "h1",
        approval={
            "approver": "alice",
            "fingerprint_bound": True,
            "valid": False,
        },
    )
    separate_invalid = [
        _decision(0, "ESCALATE", "0" * 64, "h1", request_fingerprint="fp"),
        {
            "record_type": "approval",
            "approval_jti": "approval-1",
            "approval_fingerprint": "fp",
            "approval_approver": "alice",
            "valid": False,
        },
    ]
    separate_malformed = [
        _decision(0, "ESCALATE", "0" * 64, "h1", request_fingerprint="fp"),
        {
            "record_type": "approval",
            "approval_jti": "approval-1",
            "approval_fingerprint": "fp",
            "approval_approver": "alice",
            "valid": "invalid",
        },
    ]
    invalid_attestation = [
        _decision(0, "ALLOW", "0" * 64, "h1", policy_hash="policy"),
        {
            "record_type": "policy_attestation",
            "policy_hash": "policy",
            "approver": "alice",
            "trust_root_id": "root",
            "valid": False,
        },
    ]
    attestation_malformed = [
        _decision(0, "ALLOW", "0" * 64, "h1", policy_hash="policy"),
        {
            "record_type": "policy_attestation",
            "policy_hash": "policy",
            "approver": "alice",
            "trust_root_id": "root",
            "revoked": 1,
        },
    ]
    control_approver = _decision(
        0,
        "ESCALATE",
        "0" * 64,
        "h1",
        approval={
            "approver": "\ud800",
            "fingerprint_bound": True,
            "valid": True,
        },
    )
    unsupported_delegation_kinds = [
        [
            _decision(
                0,
                "ALLOW",
                "0" * 64,
                "h1",
                delegation={
                    "id": "d-1",
                    "kind": kind,
                    "trust_root_id": "alice",
                    "valid": True,
                },
            )
        ]
        for kind in ("UNKNOWN", "unsigned_blob")
    ]

    invalid_delegations = [
        [
            _decision(
                0,
                "ALLOW",
                "0" * 64,
                "h1",
                delegation={
                    "id": "d-1",
                    "kind": "ed25519_token",
                    "issuer": "alice",
                    "valid": True,
                    **invalid_status,
                },
            )
        ]
        for invalid_status in (
            {"valid": "yes"},
            {"revoked": 1},
            {"signature_valid": False},
            {"signature_valid": 0},
            {"signature_verified": False},
            {"status": 7},
            {"status": "revoked"},
            {"signature_status": "invalid"},
        )
    ]

    corpora = [
        [missing_delegation_status],
        [flat_invalid],
        [flat_malformed],
        [nested_invalid],
        separate_invalid,
        separate_malformed,
        invalid_attestation,
        attestation_malformed,
        [control_approver],
        *invalid_delegations,
        *unsupported_delegation_kinds,
    ]
    for corpus in corpora:
        verdict = principal_authority(corpus)
        assert verdict.sufficiency is not Sufficiency.FULLY_FILLABLE
        assert "0 attributable to a named principal" in (verdict.detail or "")


def test_flat_and_nested_approval_claims_are_reconciled_before_selection():
    claims = (
        {
            "approver": "alice",
            "fingerprint_bound": True,
            "approval": {
                "approver": "alice",
                "fingerprint_bound": True,
                "valid": False,
            },
        },
        {
            "approver": "alice",
            "fingerprint_bound": True,
            "valid": False,
            "approval": {
                "approver": "alice",
                "fingerprint_bound": True,
                "valid": True,
            },
        },
        {
            "approver": "alice",
            "fingerprint_bound": True,
            "approval": {
                "approver": "bob",
                "fingerprint_bound": True,
                "valid": True,
            },
        },
        {
            "approval_jti": "flat-id",
            "approver": "alice",
            "fingerprint_bound": True,
            "approval": {
                "jti": "nested-id",
                "approver": "alice",
                "fingerprint_bound": True,
                "valid": True,
            },
        },
        {
            "approval_fingerprint": "flat-fingerprint",
            "approver": "alice",
            "fingerprint_bound": True,
            "approval": {
                "fingerprint": "nested-fingerprint",
                "approver": "alice",
                "fingerprint_bound": True,
                "valid": True,
            },
        },
        {
            "approver": "alice",
            "fingerprint_bound": True,
            "approval": {
                "approver": "alice",
                "fingerprint_bound": False,
                "valid": True,
            },
        },
    )
    for claim in claims:
        record = _decision(0, "ALLOW", "0" * 64, "h1", **claim)
        forward = principal_authority([record])
        reversed_record = dict(reversed(tuple(record.items())))
        reversed_record["approval"] = dict(reversed(tuple(reversed_record["approval"].items())))
        reverse = principal_authority([reversed_record])
        assert forward.sufficiency is Sufficiency.CONFLICTING
        assert reverse.sufficiency is Sufficiency.CONFLICTING
        assert forward.detail == reverse.detail
        assert "0 attributable to a named principal" in (forward.detail or "")

    external = [
        _decision(0, "ESCALATE", "0" * 64, "h1", approval_jti="approval-1"),
        {
            "record_type": "approval",
            "approval_jti": "approval-1",
            "approval_approver": "alice",
            "approval": {
                "jti": "approval-1",
                "approver": "alice",
                "fingerprint_bound": True,
                "valid": False,
            },
        },
    ]
    verdict = principal_authority(external)
    assert verdict.sufficiency is Sufficiency.CONFLICTING
    assert "0 attributable to a named principal" in (verdict.detail or "")

    for nested_invalidity in ({"valid": False}, {"status": "expired"}):
        minimal_external = [
            _decision(0, "ESCALATE", "0" * 64, "h1", approval_jti="approval-1"),
            {
                "record_type": "approval",
                "approval_jti": "approval-1",
                "approval_approver": "alice",
                "approval": nested_invalidity,
            },
        ]
        minimal_decision = [
            _decision(
                0,
                "ESCALATE",
                "0" * 64,
                "h1",
                approval_jti="approval-1",
                approval=nested_invalidity,
            ),
            {
                "record_type": "approval",
                "approval_jti": "approval-1",
                "approval_approver": "alice",
            },
        ]
        minimal_request_fingerprint = [
            _decision(
                0,
                "ESCALATE",
                "0" * 64,
                "h1",
                request_fingerprint="fp",
                approval=nested_invalidity,
            ),
            {
                "record_type": "approval",
                "approval_jti": "approval-1",
                "approval_fingerprint": "fp",
                "approval_approver": "alice",
            },
        ]
        for corpus in (
            minimal_external,
            minimal_decision,
            minimal_request_fingerprint,
        ):
            verdict = principal_authority(corpus)
            assert verdict.sufficiency is Sufficiency.CONFLICTING
            assert "0 attributable to a named principal" in (verdict.detail or "")


def test_authority_status_and_delegation_kind_values_are_closed_sets():
    unsupported_values = ("expired", "disabled", "pending", "unknown", "custom")
    for status in unsupported_values:
        approval = _decision(
            0,
            "ALLOW",
            "0" * 64,
            "h1",
            approver="alice",
            fingerprint_bound=True,
            status=status,
        )
        signature_approval = _decision(
            0,
            "ALLOW",
            "0" * 64,
            "h1",
            approver="alice",
            fingerprint_bound=True,
            signature_status=status,
        )
        delegation = _decision(
            0,
            "ALLOW",
            "0" * 64,
            "h1",
            delegation={
                "id": "delegation-1",
                "kind": "ed25519_token",
                "issuer": "alice",
                "valid": True,
                "status": status,
            },
        )
        attested = [
            _decision(0, "ALLOW", "0" * 64, "h1", policy_hash="policy"),
            {
                "record_type": "policy_attestation",
                "policy_hash": "policy",
                "approver": "alice",
                "trust_root_id": "root",
                "status": status,
            },
        ]
        for corpus in ([approval], [signature_approval], [delegation], attested):
            verdict = principal_authority(corpus)
            assert verdict.sufficiency is not Sufficiency.FULLY_FILLABLE
            assert "0 attributable to a named principal" in (verdict.detail or "")

    for kind in ("bearer_token", "jwt", "custom_token"):
        verdict = principal_authority(
            [
                _decision(
                    0,
                    "ALLOW",
                    "0" * 64,
                    "h1",
                    delegation={
                        "id": "delegation-1",
                        "kind": kind,
                        "trust_root_id": "alice",
                        "valid": True,
                    },
                )
            ]
        )
        assert verdict.sufficiency is not Sufficiency.FULLY_FILLABLE
        assert "0 attributable to a named principal" in (verdict.detail or "")

    positive = _decision(
        0,
        "ALLOW",
        "0" * 64,
        "h1",
        approver="alice",
        fingerprint_bound=True,
        status="approved",
        signature_status="verified",
    )
    assert principal_authority([positive]).sufficiency is Sufficiency.FULLY_FILLABLE


def test_external_approval_needs_an_existing_positive_identity_marker():
    records = [
        _decision(0, "ESCALATE", "0" * 64, "h1", request_fingerprint="fp"),
        {
            "record_type": "approval",
            "approval_fingerprint": "fp",
            "approval_approver": "alice",
        },
    ]
    assert principal_authority(records).sufficiency is not Sufficiency.FULLY_FILLABLE


def test_one_approval_cannot_be_reused_for_distinct_actions():
    records = [
        _decision(0, "ESCALATE", "0" * 64, "h1", request_fingerprint="fp"),
        _decision(1, "ESCALATE", "h1", "h2", request_fingerprint="fp"),
        {
            "record_type": "approval",
            "approval_jti": "approval-1",
            "approval_fingerprint": "fp",
            "approval_approver": "alice",
        },
    ]
    verdict = principal_authority(records)
    assert verdict.sufficiency is Sufficiency.CONFLICTING
    assert "2 with an ambiguous approval join" in (verdict.detail or "")
    assert "0 attributable to a named principal" in (verdict.detail or "")


def test_one_approval_cannot_be_reused_across_id_and_fingerprint_handles():
    approval = {
        "record_type": "approval",
        "approval_jti": "approval-1",
        "approval_fingerprint": "fp-1",
        "approval_approver": "alice",
    }
    for embedded_envelope in (False, True):
        id_claim: dict[str, object] = (
            {
                "approval": {
                    "jti": "approval-1",
                    "approver": "alice",
                    "fingerprint_bound": True,
                    "valid": True,
                }
            }
            if embedded_envelope
            else {"approval_jti": "approval-1"}
        )
        decisions = [
            _decision(0, "ESCALATE", "0" * 64, "h1", **id_claim),
            _decision(1, "ESCALATE", "h1", "h2", request_fingerprint="fp-1"),
        ]
        for reverse in (False, True):
            ordered = list(reversed(decisions)) if reverse else decisions
            verdict = principal_authority([*ordered, approval])
            assert verdict.sufficiency is Sufficiency.CONFLICTING
            assert "2 with an ambiguous approval join" in (verdict.detail or "")
            assert "0 attributable to a named principal" in (verdict.detail or "")


def test_reused_embedded_approval_evidence_is_conflicting():
    shared_fingerprint = [
        _decision(
            seq,
            "ALLOW",
            "0" * 64 if seq == 0 else "h1",
            f"h{seq + 1}",
            request_fingerprint="fp",
            approver="alice",
            fingerprint_bound=True,
        )
        for seq in range(2)
    ]
    shared_id = [
        _decision(
            seq,
            "ALLOW",
            "0" * 64 if seq == 0 else "h1",
            f"h{seq + 1}",
            approval={
                "jti": "approval-1",
                "approver": "alice",
                "fingerprint_bound": True,
                "valid": True,
            },
        )
        for seq in range(2)
    ]
    for corpus in (shared_fingerprint, shared_id):
        verdict = principal_authority(corpus)
        assert verdict.sufficiency is Sufficiency.CONFLICTING
        assert "2 with an ambiguous approval join" in (verdict.detail or "")

    embedded_only = [
        _decision(
            seq,
            "ALLOW",
            "0" * 64 if seq == 0 else "h1",
            f"h{seq + 1}",
            approval_fingerprint="fp",
            approver="alice",
            fingerprint_bound=True,
        )
        for seq in range(2)
    ]
    verdict = principal_authority(embedded_only)
    assert verdict.sufficiency is Sufficiency.CONFLICTING
    assert "2 with an ambiguous approval join" in (verdict.detail or "")

    unique_ids_shared_fingerprint = [
        _decision(
            seq,
            "ALLOW",
            "0" * 64 if seq == 0 else "h1",
            f"h{seq + 1}",
            approval_jti=f"approval-{seq}",
            approval_fingerprint="fp",
            approver="alice",
            fingerprint_bound=True,
        )
        for seq in range(2)
    ]
    verdict = principal_authority(unique_ids_shared_fingerprint)
    assert verdict.sufficiency is Sufficiency.CONFLICTING
    assert "2 with an ambiguous approval join" in (verdict.detail or "")

    non_envelope_reuse = [
        *[
            _decision(
                seq,
                "ESCALATE",
                "0" * 64 if seq == 0 else "h1",
                f"h{seq + 1}",
                approval_jti=f"approval-{seq}",
                approval_fingerprint="fp",
            )
            for seq in range(2)
        ],
        *[
            {
                "record_type": "approval",
                "approval_jti": f"approval-{seq}",
                "approval_approver": "alice",
            }
            for seq in range(2)
        ],
    ]
    duplicate_candidate_fingerprints = [
        *[
            _decision(
                seq,
                "ESCALATE",
                "0" * 64 if seq == 0 else "h1",
                f"h{seq + 1}",
                approval_jti=f"approval-{seq}",
                request_fingerprint="fp",
            )
            for seq in range(2)
        ],
        *[
            {
                "record_type": "approval",
                "approval_jti": f"approval-{seq}",
                "approval_fingerprint": "fp",
                "approval_approver": "alice" if seq == 0 else "bob",
            }
            for seq in range(2)
        ],
    ]
    for corpus in (non_envelope_reuse, duplicate_candidate_fingerprints):
        verdict = principal_authority(corpus)
        assert verdict.sufficiency is Sufficiency.CONFLICTING
        assert "2 with an ambiguous approval join" in (verdict.detail or "")


def test_embedded_approval_conflict_with_external_record_is_not_ignored():
    records = [
        _decision(
            0,
            "ALLOW",
            "0" * 64,
            "h1",
            approval={
                "jti": "approval-1",
                "approver": "alice",
                "fingerprint_bound": True,
                "valid": True,
            },
        ),
        {
            "record_type": "approval",
            "approval_jti": "approval-1",
            "approval_approver": "bob",
        },
    ]
    verdict = principal_authority(records)
    assert verdict.sufficiency is Sufficiency.CONFLICTING
    assert "0 attributable to a named principal" in (verdict.detail or "")

    invalid_local = [
        _decision(
            0,
            "ALLOW",
            "0" * 64,
            "h1",
            approval={
                "jti": "approval-1",
                "approver": "alice",
                "fingerprint_bound": True,
                "valid": False,
            },
        ),
        {
            "record_type": "approval",
            "approval_jti": "approval-1",
            "approval_approver": "alice",
        },
    ]
    assert principal_authority(invalid_local).sufficiency is Sufficiency.CONFLICTING


def test_existing_approval_ids_override_absent_or_shared_fingerprints():
    records = [
        _decision(
            0,
            "ESCALATE",
            "0" * 64,
            "h1",
            request_fingerprint="fp",
            approval_jti="approval-1",
        ),
        _decision(
            1,
            "ESCALATE",
            "h1",
            "h2",
            request_fingerprint="fp",
            approval_jti="approval-2",
        ),
        {
            "record_type": "approval",
            "approval_jti": "approval-1",
            "approval_approver": "alice",
        },
        {
            "record_type": "approval",
            "approval_jti": "approval-2",
            "approval_fingerprint": "fp",
            "approval_approver": "bob",
        },
    ]
    verdict = principal_authority(records)
    assert verdict.sufficiency is Sufficiency.FULLY_FILLABLE
    assert "2 attributable to a named principal" in (verdict.detail or "")


def test_matching_approval_id_does_not_override_conflicting_fingerprints():
    records = [
        _decision(
            0,
            "ESCALATE",
            "0" * 64,
            "h1",
            request_fingerprint="new",
            approval_jti="approval-1",
        ),
        {
            "record_type": "approval",
            "approval_jti": "approval-1",
            "approval_fingerprint": "old",
            "approval_approver": "alice",
        },
    ]
    assert principal_authority(records).sufficiency is Sufficiency.CONFLICTING

    local_mismatch = [
        _decision(
            0,
            "ESCALATE",
            "0" * 64,
            "h1",
            request_fingerprint="new",
            approval_fingerprint="old",
            approval_jti="approval-1",
        ),
        {
            "record_type": "approval",
            "approval_jti": "approval-1",
            "approval_approver": "alice",
        },
    ]
    assert principal_authority(local_mismatch).sufficiency is Sufficiency.CONFLICTING


def test_conflicting_approvals_are_not_resolved_by_input_order():
    decision = _decision(0, "ESCALATE", "0" * 64, "h1", request_fingerprint="fp")
    approvals = [
        {
            "record_type": "approval",
            "approval_jti": f"approval-{approver}",
            "approval_fingerprint": "fp",
            "approval_approver": approver,
        }
        for approver in ("alice", "bob")
    ]
    forward = principal_authority([decision, *approvals])
    reverse = principal_authority([decision, *reversed(approvals)])
    assert forward.sufficiency is Sufficiency.CONFLICTING
    assert reverse.sufficiency is Sufficiency.CONFLICTING
    assert forward.detail == reverse.detail


def test_boolean_join_key_does_not_equal_integer_key():
    records = [
        _decision(0, "ESCALATE", "0" * 64, "h1", request_fingerprint=True),
        {
            "record_type": "approval",
            "approval_jti": "approval-1",
            "approval_fingerprint": 1,
            "approval_approver": "alice",
        },
    ]
    assert principal_authority(records).sufficiency is not Sufficiency.FULLY_FILLABLE


def test_non_text_policy_hash_cannot_join_an_attestation():
    for malformed_hash in (1, True, ["policy"], {"policy": 1}):
        records = [
            _decision(
                0,
                "ALLOW",
                "0" * 64,
                "h1",
                policy_hash=malformed_hash,
            ),
            {
                "record_type": "policy_attestation",
                "policy_hash": malformed_hash,
                "approver": "alice",
                "trust_root_id": "root",
            },
        ]
        verdict = principal_authority(records)
        assert verdict.sufficiency is not Sufficiency.FULLY_FILLABLE
        assert "0 attributable to a named principal" in (verdict.detail or "")


def test_unsupported_typed_verdicts_remain_in_authority_accounting():
    for verdict in ("ALOW", 1, ["ALLOW"]):
        grade = grade_records(
            "unsupported",
            [
                _decision(
                    0,
                    "ALLOW",
                    "0" * 64,
                    "h1",
                    approval={
                        "approver": "alice",
                        "fingerprint_bound": True,
                        "valid": True,
                    },
                ),
                _decision(1, verdict, "h1", "h2"),
            ],
        )
        authority = grade.verdicts[Property.PRINCIPAL_AUTHORITY]
        assert authority.sufficiency is Sufficiency.CONFLICTING
        assert "1 unsupported decision verdict(s)" in (authority.detail or "")
        assert grade.record_count == 2


def test_null_receipt_outcome_remains_in_authority_accounting():
    grade = grade_records(
        "unsupported-receipt",
        [
            _decision(
                0,
                "ALLOW",
                "0" * 64,
                "h1",
                approval={
                    "approver": "alice",
                    "fingerprint_bound": True,
                    "valid": True,
                },
            ),
            {
                "decision": {"outcome": None},
                "actor_id": "agent-1",
                "tool_name": "read",
            },
        ],
    )
    authority = grade.verdicts[Property.PRINCIPAL_AUTHORITY]
    assert authority.sufficiency is Sufficiency.CONFLICTING
    assert "1 unsupported decision verdict(s)" in (authority.detail or "")
    assert "1 ambit_receipt_payload" in grade.shapes
