# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Value-level predicates shared by the property checks.

The distinction this module exists to enforce: a field being *present* is not
the same as a field being *interpretable*. DEMM names the conflation of the
two the container fallacy, and it is the single most common way an evidence
grader overstates what a deployment can prove.
"""

from __future__ import annotations

import re
from typing import Any

#: A digest-shaped string of one repeated character — "aaaa…", "0000…".
#: Fixtures and stubs are full of these; they are presence without content.
_PLACEHOLDER = re.compile(r"^(.)\1{7,}$")

#: An all-zero string, which is the legitimate genesis marker for a hash chain
#: and must not be treated as a placeholder in that position.
_ALL_ZERO = re.compile(r"^0+$")


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
