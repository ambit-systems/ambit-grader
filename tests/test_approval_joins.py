# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the corpus-level joins: chain integrity and principal authority."""

from __future__ import annotations

from ambit_grader.joins import principal_authority
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
