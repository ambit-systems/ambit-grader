# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Loader for JSONL evidence files.

The loader reads newline-delimited JSON of any shape. Shape recognition lives
in :mod:`ambit_grader.adapters.normalise`.
"""

from __future__ import annotations

import json
import math
import os
import stat
from pathlib import Path
from typing import Any, BinaryIO

# These are admission limits, not grading policy. Keeping them module-level
# makes boundary behavior directly testable without allocating production-size
# fixtures.
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 4 * 1024 * 1024
MAX_RECORDS = 100_000
MAX_JSON_DEPTH = 100
MAX_JSON_VALUES = 250_000


class EvidenceReadError(Exception):
    """Raised when an evidence file cannot be read as JSONL."""


def _reject_constant(token: str) -> None:
    """Reject Python's non-standard NaN and Infinity JSON extensions."""
    raise ValueError(f"non-standard numeric constant {token}")


def _finite_float(token: str) -> float:
    """Parse a JSON float only when its finite value is representable."""
    value = float(token)
    if not math.isfinite(value):
        raise ValueError(f"numeric value {token} is not finite")
    return value


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build an object while refusing ambiguous duplicate member names."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def _check_structure(value: Any) -> None:
    """Bound nesting and traversal work after a line has parsed."""
    pending: list[tuple[Any, int]] = [(iter((value,)), 1)]
    visited = 0
    while pending:
        values, depth = pending[-1]
        try:
            current = next(values)
        except StopIteration:
            pending.pop()
            continue
        visited += 1
        if visited > MAX_JSON_VALUES:
            raise ValueError(f"JSON value count exceeds {MAX_JSON_VALUES}")
        if depth > MAX_JSON_DEPTH:
            raise ValueError(f"JSON nesting depth exceeds {MAX_JSON_DEPTH}")
        if isinstance(current, dict):
            pending.append((iter(current.values()), depth + 1))
        elif isinstance(current, list):
            pending.append((iter(current), depth + 1))


def _open_regular(path: Path) -> BinaryIO:
    """Open ``path`` without blocking on a FIFO, then verify the descriptor."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceReadError(f"cannot read {path}: {exc}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise EvidenceReadError(f"cannot read {path}: not a regular file")
        if info.st_size > MAX_FILE_BYTES:
            raise EvidenceReadError(f"cannot read {path}: file exceeds {MAX_FILE_BYTES} byte limit")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def load(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Read bounded newline-delimited JSON records from a regular file.

    Lines are separated by LF; a trailing CR is removed. Other
    line-terminator characters (U+2028, U+0085, ...) are data, because JSON
    permits them raw inside strings. A leading UTF-8 byte order mark is
    skipped. Blank lines are skipped. Every non-blank line must be a JSON
    object with unique keys and only standard, finite JSON numbers.

    Args:
        path: Path to a ``.jsonl`` evidence file.

    Returns:
        The parsed records in file order.

    Raises:
        EvidenceReadError: If the path is not a bounded regular UTF-8 file, or
            any line is outside the admitted JSON domain.
    """
    path = Path(path)
    records: list[dict[str, Any]] = []
    total_bytes = 0
    try:
        with _open_regular(path) as stream:
            lineno = 0
            while True:
                raw = stream.readline(MAX_LINE_BYTES + 2)
                if not raw:
                    break
                lineno += 1
                total_bytes += len(raw)
                if total_bytes > MAX_FILE_BYTES:
                    raise EvidenceReadError(
                        f"cannot read {path}: file exceeds {MAX_FILE_BYTES} byte limit"
                    )

                line_bytes = raw[:-1] if raw.endswith(b"\n") else raw
                if line_bytes.endswith(b"\r"):
                    line_bytes = line_bytes[:-1]
                if len(line_bytes) > MAX_LINE_BYTES:
                    raise EvidenceReadError(
                        f"{path}:{lineno} exceeds {MAX_LINE_BYTES} byte line limit"
                    )
                try:
                    encoding = "utf-8-sig" if lineno == 1 else "utf-8"
                    line = line_bytes.decode(encoding)
                except UnicodeDecodeError as exc:
                    raise EvidenceReadError(f"{path} is not UTF-8: {exc}") from exc
                if not line.strip(" \t\r"):
                    continue
                if len(records) >= MAX_RECORDS:
                    raise EvidenceReadError(f"{path} exceeds {MAX_RECORDS} record limit")
                try:
                    parsed = json.loads(
                        line,
                        parse_constant=_reject_constant,
                        parse_float=_finite_float,
                        object_pairs_hook=_object_without_duplicates,
                    )
                    _check_structure(parsed)
                except (ValueError, RecursionError) as exc:
                    raise EvidenceReadError(f"{path}:{lineno} is not valid JSON: {exc}") from exc
                if not isinstance(parsed, dict):
                    raise EvidenceReadError(f"{path}:{lineno} is not a JSON object")
                records.append(parsed)
    except EvidenceReadError:
        raise
    except OSError as exc:
        raise EvidenceReadError(f"cannot read {path}: {exc}") from exc
    return records
