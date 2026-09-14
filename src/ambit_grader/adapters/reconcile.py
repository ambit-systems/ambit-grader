# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Readers that reconcile a profile's declared field paths into one canonical value.

A profile can declare several paths for one field. These readers resolve each
path, accept flat dotted attribute keys, and return a value only when every
supplied alias agrees. A conflicting or malformed alias gives no value.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from ambit_grader.adapters.agt_bom import _agt_paths_unusable
from ambit_grader.sufficiency import (
    bounded_confidence,
    dig,
    interpretable,
    is_substantive,
    is_text,
    is_unix_nanoseconds,
    timestamp_instant,
)

#: Verdict spellings seen across governance-bearing formats.
_ALLOW = frozenset({"allow", "allowed", "permit", "permitted", "pass", "success", "ok"})
_DENY = frozenset({"deny", "denied", "block", "blocked", "reject", "rejected", "fail"})
_ESCALATE = frozenset({"escalate", "escalated", "review", "pending", "input-required"})


def _verdict_from(value: Any) -> str | None:
    """Map a foreign verdict spelling onto ALLOW / DENY / ESCALATE."""
    if not isinstance(value, str):
        return None
    token = value.strip().lower()
    if token in _ALLOW:
        return "ALLOW"
    if token in _DENY:
        return "DENY"
    if token in _ESCALATE:
        return "ESCALATE"
    return None


def _lookup(record: dict[str, Any], path: str) -> Any:
    """Resolve a dotted path, tolerating flat dotted attribute keys.

    OpenTelemetry and OpenInference put their conventions in a flat attribute
    map whose *keys contain dots* — ``attributes["gen_ai.tool.name"]``, not
    ``attributes.gen_ai.tool.name`` as a nested structure. Walking the path
    naively finds nothing, so each split point is also tried as a literal key.
    """
    value = dig(record, path)
    if interpretable(value):
        return value
    segments = path.split(".")
    for cut in range(1, len(segments)):
        container = dig(record, ".".join(segments[:cut]))
        if isinstance(container, dict):
            candidate = container.get(".".join(segments[cut:]))
            if interpretable(candidate):
                return candidate
    return None


def _first_matching(record: dict[str, Any], predicate: Callable[[Any], bool], *paths: str) -> Any:
    """Return the first value with the semantic type expected by its field."""
    for path in paths:
        value = _lookup(record, path)
        if predicate(value):
            return value
    return None


def _declared_values(record: dict[str, Any], path: str) -> list[Any]:
    """Return every supplied nested or flat-dotted representation of a path."""
    segments = path.split(".")
    values: list[Any] = []
    for cut in range(len(segments)):
        container: Any = record
        for segment in segments[:cut]:
            if not isinstance(container, dict) or segment not in container:
                break
            container = container[segment]
        else:
            key = ".".join(segments[cut:])
            if isinstance(container, dict) and key in container:
                values.append(container[key])
    return values


def _has_substantive_malformed_parent(record: dict[str, Any], path: str) -> bool:
    """Return whether a nested alias stops at a non-empty non-mapping parent."""
    current: Any = record
    for segment in path.split(".")[:-1]:
        if not isinstance(current, dict) or segment not in current:
            return False
        current = current[segment]
        if not isinstance(current, dict):
            return is_substantive(current)
    return False


def _reconciled_verdict(record: dict[str, Any], paths: tuple[str, ...]) -> str | None:
    """Return one unambiguous canonical verdict across every declared alias."""
    values_by_path = {path: _declared_values(record, path) for path in paths}
    canonical_paths = {
        path
        for path, values in values_by_path.items()
        if any(_verdict_from(value) is not None for value in values)
    }
    verdicts: set[str] = set()
    malformed = False
    for path, values in values_by_path.items():
        for value in values:
            if not is_substantive(value):
                continue
            verdict = _verdict_from(value)
            if verdict is not None:
                verdicts.add(verdict)
                continue
            structural_parent = isinstance(value, dict) and any(
                candidate in canonical_paths and candidate.startswith(f"{path}.")
                for candidate in paths
            )
            if not structural_parent:
                malformed = True
    if malformed or len(verdicts) != 1:
        return None
    return next(iter(verdicts))


def _rfc3339_from_unix_nanoseconds(value: str | int) -> str:
    """Canonicalise a validated Unix-nanosecond instant without losing precision."""
    seconds, nanoseconds = divmod(int(value), 1_000_000_000)
    instant = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
    return (
        f"{instant.year:04d}-{instant.month:02d}-{instant.day:02d}"
        f"T{instant.hour:02d}:{instant.minute:02d}:{instant.second:02d}"
        f".{nanoseconds:09d}Z"
    )


def _reconciled_timestamp(
    record: dict[str, Any],
    timestamp_paths: tuple[str, ...],
    unix_nanosecond_paths: tuple[str, ...],
) -> tuple[str | None, bool]:
    """Return one timestamp spelling and whether declared aliases conflict."""
    instants: list[tuple[tuple[int, int, int, int, int, int, int], str]] = []
    malformed = False
    for path in timestamp_paths:
        for value in _declared_values(record, path):
            if not is_substantive(value):
                continue
            instant = timestamp_instant(value)
            if instant is None:
                malformed = True
            else:
                instants.append((instant, value))
    for path in unix_nanosecond_paths:
        for value in _declared_values(record, path):
            if not is_substantive(value):
                continue
            if not is_unix_nanoseconds(value):
                malformed = True
                continue
            canonical = _rfc3339_from_unix_nanoseconds(value)
            instant = timestamp_instant(canonical)
            if instant is not None:
                instants.append((instant, canonical))

    distinct = {instant for instant, _value in instants}
    conflicting = len(distinct) > 1 or (malformed and bool(instants))
    if conflicting or not instants:
        return None, conflicting
    return instants[0][1], False


def _first_matching_confident_claim(
    record: dict[str, Any],
    predicate: Callable[[Any], bool],
    paths: tuple[str, ...],
) -> tuple[Any, float | None]:
    """Return the first claim whose AGT confidence is positive and valid."""
    if _agt_paths_unusable(record, paths):
        return None, None
    for path in paths:
        value = _lookup(record, path)
        if not predicate(value):
            continue
        if not path.startswith("_agt_observed."):
            return value, None
        entry = _lookup(record, path.rsplit(".", 1)[0])
        confidence = (
            bounded_confidence(entry.get("confidence")) if isinstance(entry, dict) else None
        )
        if confidence is not None and confidence > 0.0:
            return value, confidence
    return None, None


def _reconciled_policy(
    record: dict[str, Any], paths: tuple[str, ...]
) -> tuple[str | None, float | None]:
    """Return one stable policy identity and its least supporting confidence."""
    if _agt_paths_unusable(record, paths):
        return None, None
    claims: list[tuple[str, float]] = []
    malformed = False
    for path in paths:
        if _has_substantive_malformed_parent(record, path):
            malformed = True
        for value in _declared_values(record, path):
            if not is_substantive(value):
                continue
            if not is_text(value):
                malformed = True
                continue
            confidence = 1.0
            if path.startswith("_agt_observed."):
                entry = _lookup(record, path.rsplit(".", 1)[0])
                confidence_value = (
                    bounded_confidence(entry.get("confidence")) if isinstance(entry, dict) else None
                )
                if confidence_value is None:
                    malformed = True
                    continue
                confidence = confidence_value
            claims.append((value, confidence))
    identities = {value for value, _confidence in claims}
    if malformed or len(identities) != 1:
        return None, None
    return next(iter(identities)), min(confidence for _value, confidence in claims)
