# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Aggregation of per-record and corpus verdicts into a grade.

Two aggregates are produced and they answer different questions.

**DEMM reconstruction completeness (§3.5)** is a weighted average over the
seven v0.1.0 implementation rows::

    completeness(r) = sum(w(p) for p in P) / |P|,  |P| = 7

with weights fully_fillable 1.0, opaque 1.0, partially_fillable 0.5 (the
uncalibrated v0.1.0 default confidence), structurally_unfillable 0.0. It is
faithful to the published formula and nothing Ambit authored sits inside it.

**The Ambit authority verdict** is the weakest of the three properties Ambit's
governance question actually tests. It is reported separately and labelled as
Ambit's, never blended into completeness.

No maturity level is derived. DEMM §3.7 levels describe the evidence *regime* —
manual on challenge, automated by design, exercised against a question battery,
monitored as an SLO — none of which is visible in a static evidence file.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from ambit_grader.adapters.ambit_receipts import is_decision_event
from ambit_grader.adapters.normalise import normalise
from ambit_grader.joins import CORPUS_CHECKS
from ambit_grader.models import (
    AUTHORITY_SPINE,
    IMPLEMENTATION_ROWS,
    ROW_COUNT,
    Grade,
    Property,
    PropertyVerdict,
    Sufficiency,
)
from ambit_grader.properties import RECOMMENDATIONS, RECORD_CHECKS, UNFILLABLE_REASONS


def combine(results: list[Sufficiency]) -> Sufficiency:
    """Combine per-record fillability categories for one property.

    Deliberately threshold-free, so the result is explainable without tuning:
    any contradiction poisons the property, uniform agreement carries through
    unchanged, and anything mixed is partially fillable.
    """
    if not results:
        return Sufficiency.STRUCTURALLY_UNFILLABLE
    counts = Counter(results)
    if counts[Sufficiency.CONFLICTING]:
        return Sufficiency.CONFLICTING
    if counts[Sufficiency.FULLY_FILLABLE] == len(results):
        return Sufficiency.FULLY_FILLABLE
    if counts[Sufficiency.STRUCTURALLY_UNFILLABLE] == len(results):
        return Sufficiency.STRUCTURALLY_UNFILLABLE
    return Sufficiency.PARTIALLY_FILLABLE


def partial_confidence(fractions: list[float]) -> float:
    """Return the §3.5 confidence for a partially-fillable property.

    The mean share of the property actually recoverable, across records. This
    is finer than the category alone in both directions: a property present on
    nineteen records of twenty differs from one present on one of twenty, and
    within a single record two parts of three differ from one of three. The
    flat 0.5 default can express neither.
    """
    if not fractions:
        return 0.0
    return sum(fractions) / len(fractions)


def _reasoning_trace_verdict() -> PropertyVerdict:
    """Return the fixed verdict for the reasoning-trace row (DEMM §3.4).

    Reasoning trace is classified opaque uniformly. Post-hoc reconstruction of
    internal model reasoning conflates governance with explainability, so the
    authorisation envelope is substituted and §3.5 weights it 1.0. This is not
    a measurement the grader makes; it is a boundary the method draws.
    """
    return PropertyVerdict(
        prop=Property.DECISION_BASIS,
        sufficiency=Sufficiency.OPAQUE,
        detail="reasoning trace is opaque by construction; authorisation envelope substituted",
    )


def completeness(verdicts: dict[Property, PropertyVerdict]) -> float:
    """Compute DEMM §3.5 reconstruction completeness over the seven rows.

    A collapsed row takes the weakest of its constituent properties, so the
    merge cannot manufacture strength neither property had.
    """
    total = 0.0
    for _row_name, props in IMPLEMENTATION_ROWS:
        # Per-verdict weight, not the category constant: a partially-fillable
        # property carries its own §3.5 confidence, and reading the category
        # table directly would discard it and flatten every partial to 0.5.
        weights = [verdicts[p].weight for p in props if p in verdicts]
        total += min(weights) if weights else 0.0
    return total / ROW_COUNT


def grade_records(source: str, records: list[dict[str, Any]]) -> Grade:
    """Grade an evidence set across the eight DEMM property classes.

    Args:
        source: A name for the evidence set, used in reports.
        records: Evidence records, already normalised by an adapter.

    Returns:
        The grade, carrying the per-property table, DEMM completeness over the
        seven implementation rows, and Ambit's separate authority verdict.
    """
    verdicts: dict[Property, PropertyVerdict] = {}

    # Normalise before grading. Evidence arrives in more than one shape even
    # from one vendor, and a record that matches none of them is counted and
    # named rather than raised — a grader that crashes on unfamiliar evidence
    # is answering the wrong question.
    read = normalise(records)
    records = read.records

    # The eight classes are properties *of a decision event*. An Ambit ledger
    # interleaves approvals, consequence intents, outcomes and observatory
    # scores, which are fragments about decisions rather than decisions; on a
    # captured demo ledger they are 48% of records. Scoring them as decision
    # events systematically understates the estate. Corpus checks below still
    # see every record, because the joins live in exactly those other types.
    decision_events = [r for r in records if is_decision_event(r)] or records

    for prop, check in RECORD_CHECKS.items():
        outcomes = [check(record) for record in decision_events]
        results = [category for category, _fraction in outcomes]
        sufficiency = combine(results)
        verdicts[prop] = PropertyVerdict(
            prop=prop,
            sufficiency=sufficiency,
            confidence=(
                partial_confidence([fraction for _category, fraction in outcomes])
                if sufficiency is Sufficiency.PARTIALLY_FILLABLE
                else None
            ),
            reason=(
                UNFILLABLE_REASONS[prop]
                if sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE
                else None
            ),
            recommendation=(
                None if sufficiency is Sufficiency.FULLY_FILLABLE else RECOMMENDATIONS[prop]
            ),
        )

    verdicts[Property.DECISION_BASIS] = _reasoning_trace_verdict()

    for prop, corpus_check in CORPUS_CHECKS.items():
        verdicts[prop] = corpus_check(records)

    authority = min(
        (verdicts[p] for p in AUTHORITY_SPINE if p in verdicts),
        key=lambda v: v.weight,
    ).sufficiency

    return Grade(
        source=source,
        record_count=len(records),
        shapes=read.summary(),
        unrecognised=read.unrecognised,
        verdicts=verdicts,
        completeness=completeness(verdicts),
        authority=authority,
    )
