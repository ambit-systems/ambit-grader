# Copyright (c) 2026 Ambit Systems Pty Ltd. All rights reserved.
# Proprietary and confidential. See LICENSE for terms.

"""Grade what execution evidence can and cannot prove about who authorised an action.

Public API:

    from ambit_grader import grade_records, render_text
    from ambit_grader.adapters import ambit_receipts

    records = ambit_receipts.load(Path("receipts.jsonl"))
    grade = grade_records("receipts.jsonl", records)
    print(render_text([grade]))

Two outputs, never blended: DEMM reconstruction completeness (3.5) over the
seven v0.1.0 implementation rows, faithful to the published formula; and
Ambit's own authority verdict over the three properties its governance
question tests. No DEMM maturity level is derived — 3.7 levels describe the
evidence regime, not the contents of a file.
"""

from ambit_grader.aggregate import combine, completeness, grade_records
from ambit_grader.models import (
    AUTHORITY_SPINE,
    IMPLEMENTATION_ROWS,
    LEVEL_DESCRIPTIONS,
    ROW_COUNT,
    WEIGHT,
    Grade,
    Property,
    PropertyVerdict,
    Sufficiency,
    UnfillableReason,
)
from ambit_grader.report import headline, render_json, render_text, to_dict

__all__ = [
    "AUTHORITY_SPINE",
    "IMPLEMENTATION_ROWS",
    "LEVEL_DESCRIPTIONS",
    "ROW_COUNT",
    "WEIGHT",
    "Grade",
    "Property",
    "PropertyVerdict",
    "Sufficiency",
    "UnfillableReason",
    "combine",
    "completeness",
    "grade_records",
    "headline",
    "render_json",
    "render_text",
    "to_dict",
]
