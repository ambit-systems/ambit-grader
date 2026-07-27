# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Per-record checks for the property classes a single record can answer.

Three properties are absent from this module by design. ``principal_authority``
and ``verification_strength`` are corpus-level questions whose evidence spans
records — see :mod:`ambit_grader.joins`. ``decision_basis`` is fixed to opaque
by DEMM §3.4 and is emitted directly by :mod:`ambit_grader.aggregate`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ambit_grader.models import Property, Sufficiency, UnfillableReason
from ambit_grader.sufficiency import dig, interpretable

#: Per-record check signature: a record in, a category and the fraction of the
#: property's parts that were actually recoverable from that record.
#:
#: The fraction matters. A property two-thirds present is not as uncertain as
#: one a third present, and collapsing both to the category's flat 0.5 default
#: is the same blindness §3.5's "confidence in [0, 1]" exists to avoid — just
#: one level further down, inside a single record instead of across a corpus.
RecordCheck = Callable[[dict[str, Any]], "tuple[Sufficiency, float]"]


def _from_ratio(present: int, required: int) -> tuple[Sufficiency, float]:
    """Grade a property from how many of its required parts are interpretable."""
    fraction = present / required if required else 0.0
    if present == 0:
        return Sufficiency.STRUCTURALLY_UNFILLABLE, fraction
    if present == required:
        return Sufficiency.FULLY_FILLABLE, fraction
    return Sufficiency.PARTIALLY_FILLABLE, fraction


def _count(record: dict[str, Any], *paths: str) -> int:
    """Count how many of the given dotted paths hold interpretable values."""
    return sum(1 for path in paths if interpretable(dig(record, path)))


def actor_identity(record: dict[str, Any]) -> tuple[Sufficiency, float]:
    """Grade whether the acting agent can be named.

    Ambit receipts carry the actor both flat and nested. Two copies that
    disagree are a cross-fragment inconsistency, which DEMM classifies
    conflicting rather than merely incomplete.
    """
    flat = dig(record, "actor_id")
    nested = dig(record, "actor.id")
    if interpretable(flat) and interpretable(nested) and flat != nested:
        return Sufficiency.CONFLICTING, 0.0
    return _from_ratio(1 if interpretable(flat) or interpretable(nested) else 0, 1)


def action_boundary(record: dict[str, Any]) -> tuple[Sufficiency, float]:
    """Grade whether the action and the boundary it crossed are both recorded."""
    return _from_ratio(_count(record, "action.boundary", "action.type", "tool_name"), 3)


def policy_basis(record: dict[str, Any]) -> tuple[Sufficiency, float]:
    """Grade whether the governing policy can be identified.

    A placeholder digest is evidence that was never really persisted, not an
    opacity boundary — so it is unfillable, never opaque.
    """
    flat = dig(record, "policy_hash")
    nested = dig(record, "evidence.hashes.policy_hash")
    if interpretable(flat) and interpretable(nested) and flat != nested:
        return Sufficiency.CONFLICTING, 0.0
    rule = dig(record, "matched_rule_id") or dig(record, "evidence.naming.matched_rule_id")
    present = (1 if interpretable(flat) or interpretable(nested) else 0) + (
        1 if interpretable(rule) else 0
    )
    return _from_ratio(present, 2)


def data_touch(record: dict[str, Any]) -> tuple[Sufficiency, float]:
    """Grade whether the object the action touched can be identified."""
    return _from_ratio(_count(record, "object.kind", "object.id", "object.domain"), 3)


def lifecycle_context(record: dict[str, Any]) -> tuple[Sufficiency, float]:
    """Grade whether when, where in sequence, and under what mode are recorded."""
    timed = interpretable(dig(record, "ts")) or interpretable(dig(record, "timestamp_utc"))
    sequenced = dig(record, "seq") is not None
    moded = interpretable(dig(record, "governance_mode")) or dig(record, "dry_run") is not None
    return _from_ratio(sum((timed, sequenced, moded)), 3)


#: The property classes answerable from a single record.
RECORD_CHECKS: dict[Property, RecordCheck] = {
    Property.ACTOR_IDENTITY: actor_identity,
    Property.ACTION_BOUNDARY: action_boundary,
    Property.POLICY_BASIS: policy_basis,
    Property.DATA_TOUCH: data_touch,
    Property.LIFECYCLE_CONTEXT: lifecycle_context,
}

#: Gap-closing recommendations (DEMM §3.6). The paper's routing rule is
#: regime-specific rather than generic: policy and authorisation gaps route to
#: execution-contract or delegation records, action and state gaps to runtime
#: or firewall records, cross-stack gaps to trace-context propagation.
RECOMMENDATIONS: dict[Property, str] = {
    Property.ACTOR_IDENTITY: "emit a stable actor id on every record",
    Property.ACTION_BOUNDARY: "emit action.type and action.boundary alongside tool_name",
    Property.POLICY_BASIS: "emit a real policy_hash and the matched rule id",
    Property.DATA_TOUCH: "emit object.kind, object.id and object.domain for the target",
    Property.LIFECYCLE_CONTEXT: "emit timestamp, sequence number and governance mode",
}

#: Why an unfillable property is unfillable. Every property here is one the
#: runtime could have persisted and did not.
UNFILLABLE_REASONS: dict[Property, UnfillableReason] = dict.fromkeys(
    RECORD_CHECKS, UnfillableReason.EVIDENCE_NEVER_PERSISTED
)
