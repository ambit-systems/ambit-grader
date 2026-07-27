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
from ambit_grader.sufficiency import dig, interpretable

#: Canonical verdicts. Sources may spell them in any case.
_VERDICTS = frozenset({"ALLOW", "DENY", "ESCALATE"})


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
        if interpretable(value) and isinstance(value, str):
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
                name = block.get("name") or block.get("tool_name") or block.get("operation")
                if isinstance(name, str) and name:
                    return name
    return None


def _shape_of(record: dict[str, Any]) -> str | None:
    """Name the shape of a record, or None if nothing recognisable is present."""
    record_type = record.get("record_type")
    if record_type == "approval":
        return "ambit_approval"
    if record_type == "decision":
        return "ambit_ledger"
    if record_type is not None:
        # A typed Ambit fragment: consequence intent, outcome, observatory
        # score. Not a decision event, but recognised and kept for the joins.
        return f"ambit_{record_type}"

    # Third-party formats are matched before the untyped Ambit shapes. A bare
    # string `decision` is not an Ambit marker — governance formats use it too,
    # and claiming those records as Ambit's would mislabel them and skip their
    # own field mapping.
    profile = foreign.match(record)
    if profile is not None:
        return profile.name

    if isinstance(record.get("decision"), str):
        return "ambit_ledger"
    if isinstance(record.get("decision"), dict) and dig(record, "decision.outcome") is not None:
        return "ambit_receipt_payload"
    # Homegrown logs carry no verdict and no type, but are still evidence if
    # they say who did what. Recognised so foreign JSONL can be graded; the
    # unrecognised bucket is reserved for records that say nothing at all.
    if any(
        interpretable(dig(record, path))
        for path in ("actor_id", "actor.id", "tool_name", "action.type", "object.id")
    ):
        return "generic_jsonl"
    return None


def normalise_record(record: dict[str, Any]) -> dict[str, Any] | None:
    """Map one record onto canonical paths, or None if the shape is unknown.

    The canonical form is the decision-ledger shape, because that is what the
    property checks read: an uppercase string ``decision``, a top-level
    ``tool_name``, and ``policy_hash`` reachable at the top level.
    """
    shape = _shape_of(record)
    if shape is None:
        return None

    profile = foreign.match(record)
    out = profile.apply(record) if profile is not None else dict(record)

    verdict = _verdict(out) or _verdict(record)
    if verdict is not None:
        out["decision"] = verdict
    elif isinstance(out.get("decision"), dict):
        # An object verdict we could not read: drop it rather than leave an
        # unhashable value where downstream code expects a verdict.
        out.pop("decision", None)

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
    for flat, nested_path in (
        ("policy_hash", "evidence.hashes.policy_hash"),
        ("ontology_hash", "evidence.hashes.ontology_hash"),
        ("request_fingerprint", "evidence.hashes.request_fingerprint"),
    ):
        if not interpretable(out.get(flat)):
            lifted = dig(record, nested_path)
            if interpretable(lifted):
                out[flat] = lifted

    if not interpretable(out.get("actor_id")):
        nested_actor = dig(record, "actor.id")
        if interpretable(nested_actor):
            out["actor_id"] = nested_actor

    # The engine records the invoked tool in naming provenance when it is not
    # promoted to a top-level field.
    if not interpretable(out.get("tool_name")):
        out["tool_name"] = _tool_name(record) or out.get("tool_name")
        if not interpretable(out.get("tool_name")):
            out.pop("tool_name", None)

    if not interpretable(out.get("matched_rule_id")):
        lifted = dig(record, "evidence.naming.matched_rule_id")
        if interpretable(lifted):
            out["matched_rule_id"] = lifted

    return out


def normalise(records: list[dict[str, Any]]) -> Normalised:
    """Normalise a batch, counting shapes and skipping what cannot be read."""
    normalised: list[dict[str, Any]] = []
    shapes: Counter[str] = Counter()
    unrecognised = 0

    for record in records:
        shape = _shape_of(record)
        if shape is None:
            unrecognised += 1
            continue
        mapped = normalise_record(record)
        if mapped is None:  # pragma: no cover - guarded by _shape_of above
            unrecognised += 1
            continue
        shapes[shape] += 1
        normalised.append(mapped)

    return Normalised(records=normalised, shapes=shapes, unrecognised=unrecognised)
