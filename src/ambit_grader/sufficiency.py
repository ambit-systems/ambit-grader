# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Value-level predicates shared by the property checks.

The distinction this module exists to enforce: a field being *present* is not
the same as a field being *interpretable*. DEMM names the conflation of the
two the container fallacy, and it is the single most common way an evidence
grader overstates what a deployment can prove.
"""

from __future__ import annotations

import math
import re
import unicodedata
from datetime import datetime, timedelta
from typing import Any, TypeGuard

#: A digest-shaped string of one repeated character — "aaaa…", "0000…".
#: Fixtures and stubs are full of these; they are presence without content.
_PLACEHOLDER = re.compile(r"^(.)\1{7,}$")

#: An all-zero string, which is the legitimate genesis marker for a hash chain
#: and must not be treated as a placeholder in that position.
_ALL_ZERO = re.compile(r"^0+$")

_NON_TEXT_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_RFC3339_UTC = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?(?:Z|\+00:00)$"
)
_UNIX_NANO = re.compile(r"^-?(?:0|[1-9][0-9]*)$")
_MIN_UNIX_NANOSECONDS = -62_135_596_800_000_000_000
_MAX_UNIX_NANOSECONDS = 253_402_300_799_999_999_999


def is_placeholder(value: str) -> bool:
    """Return True if the string is a single character repeated — a stub digest."""
    return bool(_PLACEHOLDER.match(value))


def is_genesis(value: object) -> bool:
    """Return True if the value is an all-zero digest, the chain genesis marker."""
    return isinstance(value, str) and bool(_ALL_ZERO.match(value))


def interpretable(value: Any) -> bool:
    """Return True if the value is present *and* carries usable content.

    Empty containers, empty strings and placeholder digests are all present
    and all useless. Booleans are treated as content, including ``False``,
    because a recorded negative is evidence.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return True
    if isinstance(value, (str, bytes, list, tuple, dict, set)) and len(value) == 0:
        return False
    return not (isinstance(value, str) and is_placeholder(value))


def is_substantive(value: Any) -> bool:
    """Return True when an alias was supplied with non-empty content."""
    return value is not None and not (
        isinstance(value, (str, bytes, list, tuple, dict, set)) and len(value) == 0
    )


def bounded_confidence(value: Any) -> float | None:
    """Return a finite JSON-number confidence in the closed unit interval."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return float(value) if 0 <= value <= 1 else None
    if isinstance(value, float):
        return value if math.isfinite(value) and 0.0 <= value <= 1.0 else None
    return None


def is_text(value: Any) -> TypeGuard[str]:
    """Return True for usable scalar text without control-like characters."""
    return (
        isinstance(value, str)
        and bool(value.strip())
        and not is_placeholder(value)
        and all(unicodedata.category(character) not in _NON_TEXT_CATEGORIES for character in value)
    )


def is_identifier(value: Any) -> bool:
    """Return True for a textual or integer identifier, never a boolean."""
    return is_text(value) or (isinstance(value, int) and not isinstance(value, bool))


def is_sequence(value: Any) -> bool:
    """Return True for an integer sequence value, excluding booleans."""
    return isinstance(value, int) and not isinstance(value, bool)


def timestamp_instant(value: Any) -> tuple[int, int, int, int, int, int, int] | None:
    """Return a validated UTC timestamp as a nanosecond-precision instant."""
    if not is_text(value):
        return None
    match = _RFC3339_UTC.fullmatch(value)
    if match is None:
        return None
    normalised = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalised)
    except ValueError:
        return None
    if parsed.utcoffset() != timedelta(0):
        return None
    fraction = match.group("fraction") or ""
    nanosecond = int(fraction.ljust(9, "0")) if fraction else 0
    return (
        parsed.year,
        parsed.month,
        parsed.day,
        parsed.hour,
        parsed.minute,
        parsed.second,
        nanosecond,
    )


def is_timestamp(value: Any) -> bool:
    """Return True for a semantically valid RFC 3339 UTC timestamp."""
    return timestamp_instant(value) is not None


def is_unix_nanoseconds(value: Any) -> bool:
    """Return True for an explicitly labelled Unix-nanosecond UTC instant."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        nanoseconds = value
    elif isinstance(value, str) and len(value) <= 21 and _UNIX_NANO.fullmatch(value) is not None:
        nanoseconds = int(value)
    else:
        return False
    return _MIN_UNIX_NANOSECONDS <= nanoseconds <= _MAX_UNIX_NANOSECONDS


def dig(record: dict[str, Any], path: str) -> Any:
    """Return the value at a dotted path in a nested mapping, or None.

    Args:
        record: The evidence record to read from.
        path: A dotted path such as ``"evidence.hashes.policy_hash"``.

    Returns:
        The value at that path, or ``None`` if any segment is absent or the
        traversal hits a non-mapping.
    """
    current: Any = record
    for segment in path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return None
        current = current[segment]
    return current
