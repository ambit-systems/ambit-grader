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
from ambit_grader.sufficiency import (
    bounded_confidence,
    dig,
    is_identifier,
    is_sequence,
    is_substantive,
    is_text,
    timestamp_instant,
)

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


def _count(record: dict[str, Any], predicate: Callable[[Any], bool], *paths: str) -> int:
    """Count paths whose values satisfy the field's semantic type."""
    return sum(1 for path in paths if predicate(dig(record, path)))


def actor_identity(record: dict[str, Any]) -> tuple[Sufficiency, float]:
    """Grade whether the acting agent can be named.

    Ambit receipts carry the actor both flat and nested. Two copies that
    disagree are a cross-fragment inconsistency, which DEMM classifies
    conflicting rather than merely incomplete.
    """
    flat = dig(record, "actor_id")
    nested = dig(record, "actor.id")
    flat_valid = is_identifier(flat)
    nested_valid = is_identifier(nested)
    if flat_valid and nested_valid and flat != nested:
        return Sufficiency.CONFLICTING, 0.0
    return _from_ratio(1 if flat_valid or nested_valid else 0, 1)


def action_boundary(record: dict[str, Any]) -> tuple[Sufficiency, float]:
    """Grade whether the action and the boundary it crossed are both recorded."""
    return _from_ratio(_count(record, is_text, "action.boundary", "action.type", "tool_name"), 3)


def policy_basis(record: dict[str, Any]) -> tuple[Sufficiency, float]:
    """Grade whether the governing policy can be identified.

    A placeholder digest is evidence that was never really persisted, not an
    opacity boundary — so it is unfillable, never opaque.
    """
    flat = dig(record, "policy_hash")
    nested = dig(record, "evidence.hashes.policy_hash")
    flat_valid = is_text(flat)
    nested_valid = is_text(nested)
    if flat_valid and nested_valid and flat != nested:
        return Sufficiency.CONFLICTING, 0.0
    flat_rule = dig(record, "matched_rule_id")
    nested_rule = dig(record, "evidence.naming.matched_rule_id")
    flat_rule_valid = is_text(flat_rule)
    nested_rule_valid = is_text(nested_rule)
    if flat_rule_valid and nested_rule_valid and flat_rule != nested_rule:
        return Sufficiency.CONFLICTING, 0.0
    present = (1 if flat_valid or nested_valid else 0) + (
        1 if flat_rule_valid or nested_rule_valid else 0
    )
    category, fraction = _from_ratio(present, 2)
    if flat_valid or nested_valid:
        confidence = bounded_confidence(record.get("_policy_confidence", 1.0))
        confidence = 0.0 if confidence is None else confidence
        if confidence < 1.0:
            return Sufficiency.PARTIALLY_FILLABLE, min(fraction, confidence)
    return category, fraction


def data_touch(record: dict[str, Any]) -> tuple[Sufficiency, float]:
    """Grade whether the object the action touched can be identified."""
    present = _count(record, is_text, "object.kind", "object.domain")
    present += _count(record, is_identifier, "object.id")
    return _from_ratio(present, 3)


def lifecycle_context(record: dict[str, Any]) -> tuple[Sufficiency, float]:
    """Grade whether when, where in sequence, and under what mode are recorded."""
    if record.get("_conflicting_timestamp") is True:
        return Sufficiency.CONFLICTING, 0.0
    flat_value = dig(record, "ts")
    nested_value = dig(record, "timestamp_utc")
    flat_timestamp = timestamp_instant(flat_value)
    nested_timestamp = timestamp_instant(nested_value)
    malformed_beside_valid = (
        flat_timestamp is not None and nested_timestamp is None and is_substantive(nested_value)
    ) or (nested_timestamp is not None and flat_timestamp is None and is_substantive(flat_value))
    if malformed_beside_valid or (
        flat_timestamp is not None
        and nested_timestamp is not None
        and flat_timestamp != nested_timestamp
    ):
        return Sufficiency.CONFLICTING, 0.0
    timed = flat_timestamp is not None or nested_timestamp is not None
    sequenced = is_sequence(dig(record, "seq"))
    moded = is_text(dig(record, "governance_mode")) or isinstance(dig(record, "dry_run"), bool)
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
