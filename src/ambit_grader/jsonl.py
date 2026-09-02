# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Loader for JSONL evidence files.

The loader reads newline-delimited JSON of any shape. Shape recognition lives
in :mod:`ambit_grader.adapters.normalise`.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


class EvidenceReadError(Exception):
    """Raised when an evidence file cannot be read as JSONL."""


def load(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Read newline-delimited JSON records from a file.

    Lines are separated by LF; a trailing CR is removed. Other
    line-terminator characters (U+2028, U+0085, ...) are data, because JSON
    permits them raw inside strings. A leading UTF-8 byte order mark is
    skipped. Blank lines are skipped. Every non-blank line must be a JSON
    object; a line that parses to anything else is a malformed evidence file
    rather than a record to be graded around, so it fails loudly.

    Args:
        path: Path to a ``.jsonl`` evidence file.

    Returns:
        The parsed records in file order.

    Raises:
        EvidenceReadError: If the file is unreadable, is not UTF-8, or any
            line is not a JSON object.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise EvidenceReadError(f"cannot read {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise EvidenceReadError(f"{path} is not UTF-8: {exc}") from exc

    records: list[dict[str, Any]] = []
    for lineno, raw in enumerate(text.split("\n"), start=1):
        line = raw.rstrip("\r")
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except (ValueError, RecursionError) as exc:
            raise EvidenceReadError(f"{path}:{lineno} is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise EvidenceReadError(f"{path}:{lineno} is not a JSON object")
        records.append(parsed)
    return records
