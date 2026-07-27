# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Tests for DEMM 3.5 completeness, the combiner, and the authority verdict."""

from __future__ import annotations

from typing import Any

import pytest

from ambit_grader import (
    AUTHORITY_SPINE,
    IMPLEMENTATION_ROWS,
    ROW_COUNT,
    WEIGHT,
    Property,
    Sufficiency,
    combine,
    completeness,
    grade_records,
)
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


def test_demm_weights_match_the_paper():
    """3.5: opaque is weighted 1.0, equal to fully fillable — not a penalty."""
    assert WEIGHT[Sufficiency.FULLY_FILLABLE] == 1.0
    assert WEIGHT[Sufficiency.OPAQUE] == 1.0
    assert WEIGHT[Sufficiency.PARTIALLY_FILLABLE] == 0.5
    assert WEIGHT[Sufficiency.STRUCTURALLY_UNFILLABLE] == 0.0


def test_completeness_is_averaged_over_seven_rows_not_eight():
    """3.1: v0.1.0 collapses actor identity and principal authority."""
    assert ROW_COUNT == 7
    assert len(IMPLEMENTATION_ROWS) == 7
    collapsed = next(props for name, props in IMPLEMENTATION_ROWS if len(props) == 2)
    assert set(collapsed) == {Property.ACTOR_IDENTITY, Property.PRINCIPAL_AUTHORITY}


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


def test_no_maturity_level_is_derived():
    """3.7 levels describe the evidence regime; a snapshot cannot reveal it."""
    grade = grade_records("x", [_record()])
    assert not hasattr(grade, "spine_level")
    assert not hasattr(grade, "level")


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


def test_authority_spine_is_the_three_documented_properties():
    assert AUTHORITY_SPINE == (
        Property.PRINCIPAL_AUTHORITY,
        Property.ACTION_BOUNDARY,
        Property.VERIFICATION_STRENGTH,
    )


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
