# Copyright (c) 2026 Ambit Systems Pty Ltd. All rights reserved.
# Proprietary and confidential. See LICENSE for terms.

"""The regression suite for the failure this grader exists to avoid.

Every assertion here encodes a mistake that was actually made while building
the tool, not a hypothetical one. The first implementation scored properties
per record, reported authority as unreconstructible over a corpus that carried
a complete approval chain, and used a count-based ladder that rated a corpus
with broken joins above one with intact joins.
"""

from __future__ import annotations

from pathlib import Path

from ambit_grader import Grade, Property, Sufficiency, grade_records
from ambit_grader.adapters import ambit_receipts

FIXTURES = Path(__file__).parent / "fixtures"


def _grade(name: str) -> Grade:
    path = FIXTURES / name
    return grade_records(name, ambit_receipts.load(path))


def test_complete_looking_records_with_broken_joins_never_score_evidenced():
    """Records that look complete individually must not pass on joined properties."""
    grade = _grade("complete_records_broken_joins.jsonl")

    assert (
        grade.verdicts[Property.PRINCIPAL_AUTHORITY].sufficiency
        is Sufficiency.STRUCTURALLY_UNFILLABLE
    )
    assert (
        grade.verdicts[Property.VERIFICATION_STRENGTH].sufficiency is not Sufficiency.FULLY_FILLABLE
    )

    # The per-record properties genuinely are strong — that is the trap.
    assert grade.verdicts[Property.ACTION_BOUNDARY].sufficiency is Sufficiency.FULLY_FILLABLE
    assert grade.verdicts[Property.DATA_TOUCH].sufficiency is Sufficiency.FULLY_FILLABLE


def test_sparse_records_with_complete_joins_score_the_joined_properties():
    """Thin records with intact joins must pass on exactly the joined properties."""
    grade = _grade("sparse_records_complete_joins.jsonl")

    assert grade.verdicts[Property.PRINCIPAL_AUTHORITY].sufficiency is Sufficiency.FULLY_FILLABLE
    assert grade.verdicts[Property.VERIFICATION_STRENGTH].sufficiency is Sufficiency.FULLY_FILLABLE

    # ...and must not be flattered on the properties they genuinely lack.
    assert grade.verdicts[Property.DATA_TOUCH].sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE


def test_joins_beat_field_richness_on_the_authority_verdict():
    """The corpus with more evidenced properties must still lose on authority.

    The broken-joins corpus has strictly more fully-fillable properties, and
    a higher DEMM completeness. The authority verdict must still rank it
    below the sparse corpus whose joins are intact — which is exactly why the
    two aggregates are reported separately and never blended.
    """
    rich_but_broken = _grade("complete_records_broken_joins.jsonl")
    sparse_but_joined = _grade("sparse_records_complete_joins.jsonl")

    rich_evidenced = sum(
        1 for v in rich_but_broken.verdicts.values() if v.sufficiency is Sufficiency.FULLY_FILLABLE
    )
    sparse_evidenced = sum(
        1
        for v in sparse_but_joined.verdicts.values()
        if v.sufficiency is Sufficiency.FULLY_FILLABLE
    )

    assert rich_evidenced > sparse_evidenced, "fixture no longer exercises the trap"
    assert rich_but_broken.completeness > sparse_but_joined.completeness
    assert rich_but_broken.authority is Sufficiency.STRUCTURALLY_UNFILLABLE
    assert sparse_but_joined.authority is not Sufficiency.STRUCTURALLY_UNFILLABLE


def test_next_move_targets_the_spine_floor():
    """The single next move must name the property holding the verdict down."""
    grade = _grade("complete_records_broken_joins.jsonl")
    assert "escalation" in grade.next_move()


def test_denials_are_excluded_from_the_authority_denominator():
    """A refused action owes no account of who authorised it."""
    grade = _grade("sparse_records_complete_joins.jsonl")
    detail = grade.verdicts[Property.PRINCIPAL_AUTHORITY].detail or ""
    assert "2 permitted action(s)" in detail
    assert "1 denial(s) excluded" in detail
