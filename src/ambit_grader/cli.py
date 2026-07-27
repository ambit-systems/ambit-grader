# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Command-line entry point for the grader.

Offline by construction: the grader reads files, and does nothing else. There
is no network call, no subprocess, and nothing is executed from the evidence
it reads. That is a property of the design, not a configuration option.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from ambit_grader.adapters import ambit_receipts
from ambit_grader.aggregate import grade_records
from ambit_grader.report import render_json, render_text

_EXIT_OK = 0
_EXIT_ERROR = 1


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


def main(argv: list[str] | None = None) -> int:
    """Run the grader and return a process exit code."""
    args = build_parser().parse_args(argv)

    grades = []
    for path in args.paths:
        try:
            records = ambit_receipts.load(path)
        except ambit_receipts.EvidenceReadError as exc:
            print(f"error: {exc}")
            return _EXIT_ERROR
        grades.append(grade_records(path.name, records))

    renderer = render_json if args.output_format == "json" else render_text
    print(renderer(grades), end="")

    if args.min_completeness is not None and any(
        g.completeness < args.min_completeness for g in grades
    ):
        return _EXIT_ERROR
    return _EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
