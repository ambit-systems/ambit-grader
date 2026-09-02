# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Grade what execution evidence can and cannot prove about who authorised an action.

Public API, the names in ``__all__``:

    from ambit_grader import grade_records, load_jsonl, render_text

    records = load_jsonl("receipts.jsonl")
    grade = grade_records("receipts.jsonl", records)
    print(render_text([grade]))

Two outputs, never blended: DEMM reconstruction completeness (3.5) over the
seven v0.1.0 implementation rows, faithful to the published formula; and
Ambit's own authority verdict over the three properties its governance
question tests. No DEMM maturity level is derived — 3.7 levels describe the
evidence regime, not the contents of a file.
"""

from ambit_grader.aggregate import grade_records
from ambit_grader.jsonl import EvidenceReadError
from ambit_grader.jsonl import load as load_jsonl
from ambit_grader.models import (
    AUTHORITY_SPINE,
    IMPLEMENTATION_ROWS,
    Grade,
    Property,
    PropertyVerdict,
    Sufficiency,
    UnfillableReason,
)
from ambit_grader.report import render_json, render_text, to_dict

__all__ = [
    "AUTHORITY_SPINE",
    "IMPLEMENTATION_ROWS",
    "EvidenceReadError",
    "Grade",
    "Property",
    "PropertyVerdict",
    "Sufficiency",
    "UnfillableReason",
    "grade_records",
    "load_jsonl",
    "render_json",
    "render_text",
    "to_dict",
]
