# Copyright (c) 2026 Ambit Systems Pty Ltd. All rights reserved.
# Proprietary and confidential. See LICENSE for terms.

"""Command-line entry point for the grader.

Offline by construction: the grader reads files, and does nothing else. There
is no network call, no subprocess, and nothing is executed from the evidence
it reads. That is a property of the design, not a configuration option.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from ambit_grader.adapters import ambit_receipts
from ambit_grader.aggregate import grade_records
from ambit_grader.report import render_json, render_text

EXIT_OK = 0
"""Every path graded and no completeness gate was breached."""

EXIT_READ_ERROR = 1
"""At least one path could not be read or parsed."""

EXIT_BELOW_THRESHOLD = 5
"""A grade fell below ``--min-completeness``. Distinct from a read error.

A CI gate needs to tell "your evidence is thin" apart from "I could not read
your file". They are different problems with different remedies, so they get
different codes.
"""


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="ambit-grade",
        description=(
            "Grade what execution evidence can and cannot prove about who "
            "authorised an action. Reads local files only."
        ),
    )
    parser.add_argument("paths", nargs="+", type=Path, help="JSONL evidence files to grade")
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--min-completeness",
        type=float,
        default=None,
        metavar="FRACTION",
        help="exit non-zero if any DEMM completeness is below FRACTION (0-1)",
    )
    return parser


def run_grade(
    paths: Sequence[Path],
    *,
    output_format: str,
    min_completeness: float | None,
) -> int:
    """Grade every path, render what succeeded, and return an exit code.

    Shared by the standalone ``ambit-grade`` entry point and by ``ambit grade``
    in ambit-cli, so the two cannot drift apart on exit codes or on how partial
    failures are handled.

    Every path is attempted. A path that cannot be read is reported on stderr
    and the remaining paths are still graded: discarding a completed grade
    because a sibling file was malformed would throw away work the operator
    asked for and can act on.

    Args:
        paths: Evidence files to grade.
        output_format: ``"json"`` or anything else for text.
        min_completeness: Fail below this DEMM completeness, or ``None``.

    Returns:
        ``EXIT_READ_ERROR`` if any path failed to load, otherwise
        ``EXIT_BELOW_THRESHOLD`` if a grade breached the gate, otherwise
        ``EXIT_OK``.
    """
    grades = []
    read_failed = False
    for path in paths:
        try:
            records = ambit_receipts.load(path)
        except ambit_receipts.EvidenceReadError as exc:
            # stderr, never stdout: stdout carries the report, and with
            # --format json an error line there would corrupt the document
            # the caller is parsing.
            print(f"error: {exc}", file=sys.stderr)
            read_failed = True
            continue
        grades.append(grade_records(path.name, records))

    if grades:
        renderer = render_json if output_format == "json" else render_text
        print(renderer(grades), end="")

    if read_failed:
        return EXIT_READ_ERROR
    if min_completeness is not None and any(g.completeness < min_completeness for g in grades):
        return EXIT_BELOW_THRESHOLD
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """Run the grader and return a process exit code."""
    args = build_parser().parse_args(argv)
    return run_grade(
        args.paths,
        output_format=args.output_format,
        min_completeness=args.min_completeness,
    )


if __name__ == "__main__":
    raise SystemExit(main())
