# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Rendering of grades.

The plain sentence comes first because it is the only format with evidence
behind it: specificity plus a single defaulted next action is what moves
people, and a ranked list of gaps is what they ignore.

The two aggregates are always printed as two, and always labelled. DEMM
completeness is comparable to any other implementation of the published
formula; the authority verdict is Ambit's own scoping and says so.
"""

from __future__ import annotations

import json
from typing import Any

from ambit_grader.models import AUTHORITY_SPINE, Grade, Property

_COLUMN = 24
_LABEL = 30


def headline(grade: Grade) -> str:
    """Return the one-sentence finding a human acts on."""
    authority = grade.verdicts[Property.PRINCIPAL_AUTHORITY]
    detail = authority.detail or "authority not assessed"
    return f"{detail}. Next: {grade.next_move()}."


def render_text(grades: list[Grade]) -> str:
    """Render one or more grades as a plain-text report."""
    if not grades:
        return "no evidence sets graded\n"

    lines: list[str] = []
    for grade in grades:
        shapes = f" [{grade.shapes}]" if grade.shapes else ""
        lines.append(f"{grade.source} — {grade.record_count} record(s){shapes}")
        lines.append(f"  {headline(grade)}")
        lines.append("")

    # The tail of a path is the distinguishing part; keep it.
    columns = "".join(f"{g.source[-(_COLUMN - 1) :]:>{_COLUMN}}" for g in grades)
    header = f"{'DEMM property class':<{_LABEL}}{columns}"
    lines.append(header)
    lines.append("-" * len(header))
    for prop in Property:
        row = f"{prop.value:<{_LABEL}}"
        row += "".join(f"{g.verdicts[prop].sufficiency.value:>{_COLUMN}}" for g in grades)
        lines.append(row)
    lines.append("-" * len(header))
    lines.append(
        f"{'DEMM completeness (7 rows)':<{_LABEL}}"
        + "".join(f"{g.completeness:>{_COLUMN}.1%}" for g in grades)
    )
    lines.append(
        f"{'Ambit authority verdict':<{_LABEL}}"
        + "".join(f"{g.authority.value:>{_COLUMN}}" for g in grades)
    )
    lines.append("")
    lines.append(
        "DEMM completeness is the 3.5 weighted average over the seven v0.1.0 "
        "implementation rows. A partially-fillable property carries its own 3.5 "
        "confidence — the share of cases it is actually fillable for — rather than "
        "the reference implementation's flat 0.5 default, which the paper states is "
        "uncalibrated. Completeness is therefore protocol-relative and comparable "
        "across runs of this tool, not an absolute score."
    )
    lines.append(
        "The Ambit authority verdict is the weakest of "
        + ", ".join(p.value for p in AUTHORITY_SPINE)
        + ". It is Ambit's scoping, not a DEMM output, and no DEMM maturity level is "
        "derived here — DEMM levels describe the evidence regime, which a static file "
        "does not reveal."
    )
    return "\n".join(lines) + "\n"


def to_dict(grade: Grade) -> dict[str, Any]:
    """Convert a grade to a JSON-serialisable mapping."""
    return {
        "source": grade.source,
        "record_count": grade.record_count,
        "shapes": grade.shapes,
        "unrecognised": grade.unrecognised,
        "demm": {
            "completeness": round(grade.completeness, 4),
            "row_verdicts": dict(grade.row_verdicts()),
            "properties": {
                prop.value: {
                    "sufficiency": verdict.sufficiency.value,
                    "weight": verdict.weight,
                    "reason": verdict.reason.value if verdict.reason else None,
                    "recommendation": verdict.recommendation,
                    "detail": verdict.detail,
                }
                for prop, verdict in grade.verdicts.items()
            },
        },
        "ambit": {
            "authority_verdict": grade.authority.value,
            "spine": [p.value for p in AUTHORITY_SPINE],
            "headline": headline(grade),
            "next_move": grade.next_move(),
        },
    }


def render_json(grades: list[Grade]) -> str:
    """Render grades as JSON."""
    return json.dumps([to_dict(g) for g in grades], indent=2, sort_keys=True) + "\n"
