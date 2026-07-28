# Copyright (c) 2026 Ambit Systems Pty Ltd. All rights reserved.
# Proprietary and confidential. See LICENSE for terms.

"""Adapter for Ambit decision-ledger and receipt JSONL.

This is the only adapter this repository ships. Harness doctrine §3.1 makes
breadth an explicit anti-goal — connectors are added on observed demand, never
in anticipation of it — so a second adapter waits for a real estate that needs
one.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

#: Record types this adapter declares to be decision events.
#:
#: DEMM §3.2 makes the adapter tier responsible for declaring the
#: fragment-to-property mapping, and the eight property classes are properties
#: *of a decision event*. An Ambit ledger interleaves several other record
#: types — approvals, consequence intents, outcomes, observatory scores — which
#: are fragments about decisions, not decisions. Scoring them as decision
#: events understates the estate: on a captured demo ledger they are 48% of
#: records and drag three properties from fully fillable down to partial.
DECISION_EVENT_TYPES: frozenset[str] = frozenset({"decision"})


def is_decision_event(record: dict[str, Any]) -> bool:
    """Return True if the record represents a decision event.

    A record with no ``record_type`` but a ``decision`` verdict is treated as a
    decision event, which keeps older flat receipts readable.
    """
    record_type = record.get("record_type")
    if record_type is None:
        return bool(record.get("decision"))
    return record_type in DECISION_EVENT_TYPES


class EvidenceReadError(Exception):
    """Raised when an evidence file cannot be read as JSONL."""


def load(path: Path) -> list[dict[str, Any]]:
    """Read newline-delimited JSON records from a file.

    Blank lines are skipped. Every non-blank line must be a JSON object; a
    line that parses to anything else is a malformed evidence file rather
    than a record to be graded around, so it fails loudly.

    Args:
        path: Path to a ``.jsonl`` evidence file.

    Returns:
        The parsed records in file order.

    Raises:
        EvidenceReadError: If the file is unreadable or any line is not a
            JSON object.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise EvidenceReadError(f"cannot read {path}: {exc}") from exc

    records: list[dict[str, Any]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EvidenceReadError(f"{path}:{lineno} is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise EvidenceReadError(f"{path}:{lineno} is not a JSON object")
        records.append(parsed)
    return records
