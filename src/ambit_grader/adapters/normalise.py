# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Shape recognition and normalisation.

Evidence arrives in more than one shape even from a single vendor. Ambit alone
emits two: the decision-ledger record (`decision` is the string `"ALLOW"`) and
the engine's raw receipt payload (`decision` is an object whose `outcome` is
the lowercase `"allow"`). A grader that assumes one of them crashes on the
other — which is exactly what happened, with a `TypeError` on its own vendor's
current engine output.

Two rules follow, and they are the contract every adapter must meet:

1. **Never crash on an unrecognised shape.** A tool whose pitch is that it
   reads your evidence honestly cannot answer with a stack trace. Records that
   parse as JSON but match no known shape are counted and named, not raised.
2. **Normalise, do not reinterpret.** Normalisation maps known fields onto
   canonical paths. It never invents a value, and a field absent from the
   source stays absent — otherwise the grade measures the adapter rather than
   the evidence.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from ambit_grader.adapters import foreign
from ambit_grader.sufficiency import dig, interpretable, is_identifier, is_text

#: Canonical verdicts. Sources may spell them in any case.
_VERDICTS = frozenset({"ALLOW", "DENY", "ESCALATE"})

#: Reserved adapter output declaring whether a recognised record is scored as
#: a decision event. Normalisation overwrites any source-supplied value.
_DECISION_EVENT_ELIGIBLE = "_decision_event_eligible"

#: Record types the adapter tier declares to be decision events.
#:
#: DEMM §3.2 makes the adapter tier responsible for declaring the
#: fragment-to-property mapping, and the eight property classes are properties
#: *of a decision event*. An Ambit ledger interleaves several other record
#: types — approvals, consequence intents, outcomes, observatory scores — which
#: are fragments about decisions, not decisions. Scoring them as decision
#: events understates the estate: on a captured sample ledger they are 48% of
#: records and drag three properties from fully fillable down to partial.
DECISION_EVENT_TYPES: frozenset[str] = frozenset({"decision"})


def is_decision_event(record: dict[str, Any]) -> bool:
    """Return True if the record represents a decision event.

    A record with no ``record_type`` but a ``decision`` verdict is treated as a
    decision event, which keeps older flat receipts readable.

    Args:
        record: A normalised evidence record.

    Returns:
        True if the record is a decision event.
    """
    eligible = record.get(_DECISION_EVENT_ELIGIBLE)
    if isinstance(eligible, bool):
        return eligible
    if record.get("_unsupported_decision") is True:
        return True
    record_type = record.get("record_type")
    if record_type is None:
        return isinstance(record.get("decision"), str)
    return isinstance(record_type, str) and record_type in DECISION_EVENT_TYPES


@dataclass(frozen=True, slots=True)
class Normalised:
    """The result of normalising a batch of evidence records.

    Attributes:
        records: Records mapped onto canonical paths, in source order.
        shapes: How many records matched each recognised shape.
        unrecognised: Records that parsed but matched no known shape.
    """

    records: list[dict[str, Any]] = field(default_factory=list)
    shapes: Counter[str] = field(default_factory=Counter)
    unrecognised: int = 0

    def summary(self) -> str:
        """Return a one-line description of what was read, for the report."""
        if not self.records and not self.unrecognised:
            return "no records"
        parts = [f"{count} {name}" for name, count in sorted(self.shapes.items())]
        if self.unrecognised:
            parts.append(f"{self.unrecognised} unrecognised (skipped)")
        return ", ".join(parts)


def _verdict(record: dict[str, Any]) -> str | None:
    """Extract the verdict from either the ledger or receipt-payload shape."""
    for candidate in (record.get("decision"), dig(record, "decision.outcome")):
        if isinstance(candidate, str) and candidate.upper() in _VERDICTS:
            return candidate.upper()
    return None


def _tool_name(record: dict[str, Any]) -> str | None:
    """Find the invoked tool's name wherever the emitting adapter put it.

    Ambit receipts do not promote the call name to a top-level ``tool_name``;
    each protocol adapter files it under its own key in the raw provenance
    block (``evidence.raw.http.name``, ``evidence.raw.mcp.name``, and so on).
    The value is present and authoritative — only its path is adapter-specific,
    which is precisely what normalisation is for.
    """
    for path in (
        "tool_name",
        "evidence.naming.tool_name",
        "evidence.provenance.raw.tool_name",
    ):
        value = dig(record, path)
        if is_text(value):
            return value

    raw = dig(record, "evidence.raw")
    if isinstance(raw, dict):
        for block in raw.values():
            if isinstance(block, dict):
                # Adapters disagree on the key: HTTP and MCP write `name`, A2A
                # writes `operation` for the protocol method it invoked. Same
                # fact, different spelling. Reading both is mapping; refusing
                # to read `operation` would report a tool name as missing while
                # it sits in the record, which is a false finding rather than a
                # strict one.
                for key in ("name", "tool_name", "operation"):
                    name = block.get(key)
                    if is_text(name):
                        return name
    return None


def _shape_of(record: dict[str, Any]) -> tuple[str | None, foreign.Profile | None]:
    """Name the shape of a record and the third-party profile that matched it.

    Args:
        record: A raw evidence record.

    Returns:
        The shape name, or ``None`` if nothing recognisable is present, and
        the matching third-party profile, or ``None`` for Ambit shapes.
    """
    record_type = record.get("record_type")
    if isinstance(record_type, str):
        if record_type == "approval":
            return "ambit_approval", None
        if record_type == "decision":
            return "ambit_ledger", None
        # A typed Ambit fragment: consequence intent, outcome, observatory
        # score. Not a decision event, but recognised and kept for the joins.
        return f"ambit_{record_type}", None

    # Third-party formats are matched before the untyped Ambit shapes. A bare
    # string `decision` is not an Ambit marker — governance formats use it too,
    # and claiming those records as Ambit's would mislabel them and skip their
    # own field mapping.
    profile = foreign.match(record)
    if profile is not None:
        return profile.name, profile

    if isinstance(record.get("decision"), str):
        return "ambit_ledger", None
    decision = record.get("decision")
    if isinstance(decision, dict) and "outcome" in decision:
        return "ambit_receipt_payload", None
    # Homegrown logs carry no verdict and no type, but are still evidence if
    # they say who did what. Recognised so foreign JSONL can be graded; the
    # unrecognised bucket is reserved for records that say nothing at all.
    if any(
        interpretable(dig(record, path))
        for path in ("actor_id", "actor.id", "tool_name", "action.type", "object.id")
    ):
        return "generic_jsonl", None
    return None, None


def normalise_record(record: dict[str, Any]) -> dict[str, Any] | None:
    """Map one record onto canonical paths, or None if the shape is unknown.

    The canonical form is the decision-ledger shape, because that is what the
    property checks read: an uppercase string ``decision``, a top-level
    ``tool_name``, and ``policy_hash`` reachable at the top level. A
    ``record_type`` or ``decision`` that is not a string the checks can read
    is dropped, so downstream code never sees a list or dict in either field.

    Args:
        record: A raw evidence record.

    Returns:
        The normalised record, or ``None`` if no shape matched.
    """
    shape, profile = _shape_of(record)
    if shape is None:
        return None
    return _apply(record, profile, shape)


def _apply(record: dict[str, Any], profile: foreign.Profile | None, shape: str) -> dict[str, Any]:
    """Map a recognised record onto canonical paths."""
    out = profile.apply(record) if profile is not None else dict(record)
    out[_DECISION_EVENT_ELIGIBLE] = (
        profile.decision_event
        if profile is not None
        else shape in {"ambit_ledger", "ambit_receipt_payload", "generic_jsonl"}
    )
    if profile is None:
        out.pop("_unsupported_decision", None)
        out.pop("_conflicting_timestamp", None)
        out.pop("_policy_confidence", None)
    native_record = record if profile is None else {}

    if not isinstance(out.get("record_type"), str):
        out.pop("record_type", None)

    verdict = _verdict(out)
    if verdict is None and profile is None:
        verdict = _verdict(record)
    if verdict is not None:
        out["decision"] = verdict
        out.pop("_unsupported_decision", None)
    else:
        # Keep the event in every downstream denominator, while removing the
        # malformed value from the canonical verdict slot.
        out.pop("decision", None)
        if shape in {"ambit_ledger", "ambit_receipt_payload"}:
            out["_unsupported_decision"] = True

    # Structured per-rule reasoning lives under `decision.reasons` in the
    # receipt-payload shape and at the top level in the ledger shape.
    if not interpretable(out.get("decision_reasons")):
        nested = dig(record, "decision.reasons")
        if isinstance(nested, list) and nested:
            out["decision_reasons"] = [
                {
                    "rule_id": entry.get("rule_id"),
                    "outcome": entry.get("result", entry.get("outcome")),
                    "detail": entry.get("details", entry.get("detail")),
                }
                for entry in nested
                if isinstance(entry, dict)
            ]

    # Hashes are top-level in the ledger and nested under evidence in the
    # payload. Lift only what is genuinely present.
    for flat, nested_path, predicate in (
        ("policy_hash", "evidence.hashes.policy_hash", is_text),
        ("ontology_hash", "evidence.hashes.ontology_hash", is_text),
        ("request_fingerprint", "evidence.hashes.request_fingerprint", is_identifier),
    ):
        if not predicate(out.get(flat)):
            lifted = dig(native_record, nested_path)
            if predicate(lifted):
                out[flat] = lifted

    if not is_identifier(out.get("actor_id")):
        nested_actor = dig(native_record, "actor.id")
        if is_identifier(nested_actor):
            out["actor_id"] = nested_actor

    # The engine records the invoked tool in naming provenance when it is not
    # promoted to a top-level field.
    if not is_text(out.get("tool_name")):
        out["tool_name"] = _tool_name(native_record) or out.get("tool_name")
        if not is_text(out.get("tool_name")):
            out.pop("tool_name", None)

    if not is_text(out.get("matched_rule_id")):
        lifted = dig(native_record, "evidence.naming.matched_rule_id")
        if is_text(lifted):
            out["matched_rule_id"] = lifted

    return out


def normalise(records: list[dict[str, Any]]) -> Normalised:
    """Normalise a batch, counting shapes and skipping what cannot be read.

    Args:
        records: Raw evidence records.

    Returns:
        The normalised records with shape counts and the unrecognised total.
    """
    normalised: list[dict[str, Any]] = []
    shapes: Counter[str] = Counter()
    unrecognised = 0

    for record in records:
        shape, profile = _shape_of(record)
        if shape is None:
            unrecognised += 1
            continue
        shapes[shape] += 1
        normalised.append(_apply(record, profile, shape))

    return Normalised(records=normalised, shapes=shapes, unrecognised=unrecognised)
