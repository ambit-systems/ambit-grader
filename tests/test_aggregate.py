# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Tests for DEMM 3.5 completeness, the combiner, and the authority verdict."""

from __future__ import annotations

from typing import Any

import pytest

from ambit_grader import IMPLEMENTATION_ROWS, Property, Sufficiency, grade_records
from ambit_grader.aggregate import combine, completeness, partial_confidence
from ambit_grader.models import PropertyVerdict


def _record(**extra):
    base = {
        "seq": 0,
        "ts": "2026-02-01T00:00:00Z",
        "record_type": "decision",
        "actor_id": "a",
        "decision": "ALLOW",
        "prev_hash": "0" * 64,
        "record_hash": "h1",
    }
    base.update(extra)
    return base


def test_combine_is_uniform_or_partial():
    ff, su = Sufficiency.FULLY_FILLABLE, Sufficiency.STRUCTURALLY_UNFILLABLE
    assert combine([ff, ff]) is ff
    assert combine([su, su]) is su
    assert combine([ff, su]) is Sufficiency.PARTIALLY_FILLABLE
    assert combine([]) is su


def test_a_single_contradiction_poisons_the_property():
    results = [Sufficiency.FULLY_FILLABLE] * 99 + [Sufficiency.CONFLICTING]
    assert combine(results) is Sufficiency.CONFLICTING


def test_completeness_is_averaged_over_seven_rows_not_eight():
    """3.1: v0.1.0 collapses actor identity and principal authority.

    Eight fully fillable properties with one unfillable must average over
    seven rows, so the loss is 1/7 and not 1/8.
    """
    collapsed = next(props for name, props in IMPLEMENTATION_ROWS if len(props) == 2)
    assert set(collapsed) == {Property.ACTOR_IDENTITY, Property.PRINCIPAL_AUTHORITY}

    verdicts = {p: PropertyVerdict(p, Sufficiency.FULLY_FILLABLE) for p in Property}
    verdicts[Property.DATA_TOUCH] = PropertyVerdict(
        Property.DATA_TOUCH, Sufficiency.STRUCTURALLY_UNFILLABLE
    )
    assert completeness(verdicts) == pytest.approx(6 / 7)
    assert len(grade_records("x", [_record()]).row_verdicts()) == 7


def test_completeness_formula():
    """All rows fully fillable gives 1.0; all unfillable gives 0.0."""
    full = {p: PropertyVerdict(p, Sufficiency.FULLY_FILLABLE) for p in Property}
    assert completeness(full) == pytest.approx(1.0)

    empty = {p: PropertyVerdict(p, Sufficiency.STRUCTURALLY_UNFILLABLE) for p in Property}
    assert completeness(empty) == pytest.approx(0.0)


def test_collapsed_row_takes_the_weaker_constituent():
    """A merge must not manufacture strength neither property had."""
    verdicts = {p: PropertyVerdict(p, Sufficiency.FULLY_FILLABLE) for p in Property}
    verdicts[Property.PRINCIPAL_AUTHORITY] = PropertyVerdict(
        Property.PRINCIPAL_AUTHORITY, Sufficiency.STRUCTURALLY_UNFILLABLE
    )
    # One of seven rows drops to 0.0 while actor identity stays fully fillable.
    assert completeness(verdicts) == pytest.approx(6 / 7)


def test_reasoning_trace_is_opaque_by_construction():
    """3.4: reasoning trace is uniformly opaque and contributes 1.0."""
    grade = grade_records("x", [_record()])
    verdict = grade.verdicts[Property.DECISION_BASIS]
    assert verdict.sufficiency is Sufficiency.OPAQUE
    assert verdict.weight == 1.0


def test_authority_verdict_is_the_weakest_spine_property():
    """One floored spine property floors the verdict, however strong the rest."""
    records = [
        _record(
            decision="ESCALATE",
            tool_name="t",
            action={"type": "read", "boundary": "tool_execution"},
            request_fingerprint="fp-1",
        )
    ]
    grade = grade_records("one-record", records)
    assert grade.verdicts[Property.ACTION_BOUNDARY].sufficiency is Sufficiency.FULLY_FILLABLE
    assert (
        grade.verdicts[Property.PRINCIPAL_AUTHORITY].sufficiency
        is Sufficiency.STRUCTURALLY_UNFILLABLE
    )
    assert grade.authority is Sufficiency.STRUCTURALLY_UNFILLABLE


def test_unfillable_verdicts_carry_an_architectural_reason():
    """3.5 requires an annotated reason on structurally_unfillable."""
    grade = grade_records("x", [_record()])
    unfillable = [
        v for v in grade.verdicts.values() if v.sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE
    ]
    assert unfillable, "fixture no longer produces an unfillable property"
    assert all(v.reason is not None for v in unfillable)


def test_partial_confidence_is_not_a_flat_default(tmp_path):
    """3.5 defines the partial weight as a confidence, not the constant 0.5.

    A property fillable for one action in eight must not weigh the same as one
    fillable for six in eight — that blindness is what made completeness
    insensitive to a real five-action improvement.
    """
    from ambit_grader.models import DEFAULT_PARTIAL_CONFIDENCE, PropertyVerdict

    weak = PropertyVerdict(
        Property.PRINCIPAL_AUTHORITY, Sufficiency.PARTIALLY_FILLABLE, confidence=0.125
    )
    strong = PropertyVerdict(
        Property.PRINCIPAL_AUTHORITY, Sufficiency.PARTIALLY_FILLABLE, confidence=0.75
    )
    assert weak.weight == pytest.approx(0.125)
    assert strong.weight == pytest.approx(0.75)
    assert weak.weight < strong.weight

    # No principled fraction available -> the paper's v0.1.0 default.
    unknown = PropertyVerdict(Property.POLICY_BASIS, Sufficiency.PARTIALLY_FILLABLE)
    assert unknown.weight == pytest.approx(DEFAULT_PARTIAL_CONFIDENCE)

    # Confidence is meaningless for the fixed-weight categories.
    fixed = PropertyVerdict(Property.DATA_TOUCH, Sufficiency.FULLY_FILLABLE, confidence=0.1)
    assert fixed.weight == 1.0


class TestPartialConfidence:
    """Direct coverage for `partial_confidence`, the §3.5 confidence formula."""

    def test_empty_list_returns_zero(self):
        assert partial_confidence([]) == 0.0

    def test_single_fraction_returns_that_fraction(self):
        assert partial_confidence([0.4]) == pytest.approx(0.4)

    def test_is_the_mean_across_records(self):
        # One action of eight, then six of eight: (0.125 + 0.75) / 2.
        assert partial_confidence([0.125, 0.75]) == pytest.approx(0.4375)

    def test_uniform_fractions_return_that_value_unchanged(self):
        assert partial_confidence([0.5, 0.5, 0.5]) == pytest.approx(0.5)

    def test_boundary_value_zero(self):
        assert partial_confidence([0.0, 0.0]) == 0.0

    def test_boundary_value_one(self):
        assert partial_confidence([1.0, 1.0]) == 1.0

    def test_mixed_boundaries_average_to_the_midpoint(self):
        assert partial_confidence([0.0, 1.0]) == pytest.approx(0.5)


def test_confidence_is_clamped_to_the_unit_interval():
    from ambit_grader.models import PropertyVerdict

    assert (
        PropertyVerdict(Property.DATA_TOUCH, Sufficiency.PARTIALLY_FILLABLE, confidence=9.0).weight
        == 1.0
    )
    assert (
        PropertyVerdict(Property.DATA_TOUCH, Sufficiency.PARTIALLY_FILLABLE, confidence=-3.0).weight
        == 0.0
    )


def test_completeness_moves_when_attribution_improves():
    """The regression this fix exists for: a real improvement must show."""

    def corpus(attributed: int, delegated: int) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        prev: str = "0" * 64
        for i in range(attributed + delegated):
            named = i < attributed
            rec = {
                "seq": i,
                "ts": "2026-03-01T00:00:00Z",
                "record_type": "decision",
                "actor_id": "a",
                "tool_name": "t",
                "decision": "ALLOW",
                "prev_hash": prev,
                "record_hash": f"h{i}",
                "delegation": {
                    "id": "d",
                    "jti": "d",
                    "valid": True,
                    "kind": "ed25519_token" if named else "hmac_token",
                    **({"trust_root_id": "ops-root"} if named else {}),
                },
            }
            prev = str(rec["record_hash"])
            out.append(rec)
        return out

    before = grade_records("before", corpus(attributed=1, delegated=7))
    after = grade_records("after", corpus(attributed=6, delegated=2))
    assert after.completeness > before.completeness


@pytest.mark.parametrize(
    "field",
    ["record_type", "decision", "request_fingerprint", "approval_fingerprint", "policy_hash"],
)
@pytest.mark.parametrize("junk", [["x"], {"x": 1}])
def test_a_list_or_dict_in_a_scalar_field_is_graded_not_raised(field, junk):
    """A malformed field is a gap in the evidence, never a traceback.

    Each field is a dict key or a set member somewhere downstream. A corpus
    that carries the field as a list or dict must still grade, alongside the
    well-formed records that join on the same field.
    """
    approval = {
        "seq": 1,
        "record_type": "approval",
        "approval_fingerprint": "fp-1",
        "approval_approver": "alice",
    }
    attestation = {
        "seq": 2,
        "record_type": "policy_attestation",
        "policy_hash": "9f2c41ab",
        "approver": "bob",
        "trust_root_id": "ops-root",
    }
    good = _record(decision="ESCALATE", request_fingerprint="fp-1", policy_hash="9f2c41ab")
    bad = _record(seq=3, request_fingerprint="fp-1", policy_hash="9f2c41ab")
    for record in (approval, attestation, bad):
        record[field] = junk

    graded = grade_records("junk", [good, approval, attestation, bad])
    assert graded.record_count + graded.unrecognised == 4
    assert 0.0 <= graded.completeness <= 1.0
    # The well-formed escalation is still in the authority denominator.
    detail = graded.verdicts[Property.PRINCIPAL_AUTHORITY].detail or ""
    assert "permitted action(s)" in detail
