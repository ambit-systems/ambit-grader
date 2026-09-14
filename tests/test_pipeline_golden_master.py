# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Golden-master lock on the grading pipeline, pinned before any refactor.

``golden/pipeline_cases.jsonl`` holds every distinct input that the rest of
this suite passed to the pipeline stages below, recorded at the lock commit,
with the complete output that code produced for it. Each test replays one
stage over its cases and compares the full serialised output: key order, value
types, float values, and verdict text. The other tests assert selected parts
of these outputs; this lock pins all of it. An unexplained diff is a found bug,
never a golden to update.
"""

from __future__ import annotations

import base64
import dataclasses
import functools
import json
import math
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ambit_grader import aggregate, joins, report
from ambit_grader.adapters import foreign, normalise
from ambit_grader.adapters.normalise import Normalised
from ambit_grader.models import Grade, Property, PropertyVerdict, Sufficiency, UnfillableReason

GOLDEN_PATH = Path(__file__).parent / "golden" / "pipeline_cases.jsonl"

_TAG = "$t"
_ENUMS: dict[str, type[Property | Sufficiency | UnfillableReason]] = {
    "Property": Property,
    "Sufficiency": Sufficiency,
    "UnfillableReason": UnfillableReason,
}
_DATACLASSES: dict[str, type[PropertyVerdict | Grade | Normalised]] = {
    "PropertyVerdict": PropertyVerdict,
    "Grade": Grade,
    "Normalised": Normalised,
}


def encode(value: Any) -> Any:
    """Encode a value as JSON that keeps its exact type, order, and content."""
    if isinstance(value, Property | Sufficiency | UnfillableReason):
        return {_TAG: "enum", "v": f"{type(value).__name__}.{value.name}"}
    if value is None or type(value) in (bool, str, int):
        return value
    if type(value) is float:
        return value if math.isfinite(value) else {_TAG: "float", "v": repr(value)}
    if type(value) is list:
        return [encode(item) for item in value]
    if type(value) is tuple:
        return {_TAG: "tuple", "v": [encode(item) for item in value]}
    if type(value) is dict:
        if all(type(key) is str for key in value) and _TAG not in value:
            return {key: encode(item) for key, item in value.items()}
        return {_TAG: "dict", "v": [[encode(key), encode(item)] for key, item in value.items()]}
    if type(value) is Counter:
        return {_TAG: "Counter", "v": [[encode(key), count] for key, count in value.items()]}
    if type(value) in (set, frozenset):
        items = sorted((encode(item) for item in value), key=json.dumps)
        return {_TAG: type(value).__name__, "v": items}
    if type(value) is bytes:
        return {_TAG: "bytes", "v": base64.b64encode(value).decode("ascii")}
    if type(value) in _DATACLASSES.values():
        fields = {
            field.name: encode(getattr(value, field.name)) for field in dataclasses.fields(value)
        }
        return {_TAG: type(value).__name__, "v": fields}
    if isinstance(value, foreign.Profile):
        return _encode_profile(value)
    raise TypeError(f"cannot encode {type(value).__name__}")


def _encode_profile(profile: foreign.Profile) -> dict[str, Any]:
    if any(profile is shipped for shipped in foreign.PROFILES):
        return {_TAG: "profile", "v": profile.name}
    if profile.expand is not None and profile.expand is not foreign.expand_agt_bom_fields:
        raise TypeError("custom profile with an unrecognised expand pre-pass")
    fields = {
        field.name: encode(getattr(profile, field.name))
        for field in dataclasses.fields(profile)
        if field.name not in ("detect", "expand")
    }
    fields["expand"] = None if profile.expand is None else "expand_agt_bom_fields"
    return {_TAG: "custom_profile", "v": fields}


def _detect_is_not_called(record: dict[str, Any]) -> bool:
    raise AssertionError("Profile.apply does not call detect")


def decode(value: Any) -> Any:
    """Rebuild the value that :func:`encode` encoded, as a fresh object."""
    if isinstance(value, list):
        return [decode(item) for item in value]
    if not isinstance(value, dict):
        return value
    if _TAG not in value:
        return {key: decode(item) for key, item in value.items()}
    tag, payload = value[_TAG], value["v"]
    if tag == "enum":
        enum_name, member = payload.split(".")
        return _ENUMS[enum_name][member]
    if tag == "float":
        return float(payload)
    if tag == "tuple":
        return tuple(decode(item) for item in payload)
    if tag == "dict":
        return {decode(key): decode(item) for key, item in payload}
    if tag == "Counter":
        counter: Counter[Any] = Counter()
        for key, count in payload:
            counter[decode(key)] = count
        return counter
    if tag == "set":
        return {decode(item) for item in payload}
    if tag == "frozenset":
        return frozenset(decode(item) for item in payload)
    if tag == "bytes":
        return base64.b64decode(payload)
    if tag in _DATACLASSES:
        return _DATACLASSES[tag](**{name: decode(item) for name, item in payload.items()})
    if tag == "profile":
        return next(profile for profile in foreign.PROFILES if profile.name == payload)
    if tag == "custom_profile":
        fields = {name: decode(item) for name, item in payload.items() if name != "expand"}
        expand = None if payload["expand"] is None else foreign.expand_agt_bom_fields
        return foreign.Profile(detect=_detect_is_not_called, expand=expand, **fields)
    raise ValueError(f"unknown tag {tag!r}")


def _grade_records(source: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    grade = aggregate.grade_records(source, records)
    return {"grade": grade, "text": report.render_text([grade])}


def _profile_apply(profile: foreign.Profile, record: dict[str, Any]) -> dict[str, Any]:
    return profile.apply(record)


def _match(record: dict[str, Any]) -> str | None:
    profile = foreign.match(record)
    return None if profile is None else profile.name


STAGES: dict[str, Callable[..., Any]] = {
    "chain_integrity": joins.chain_integrity,
    "expand_agt_bom_fields": foreign.expand_agt_bom_fields,
    "grade_records": _grade_records,
    "match": _match,
    "normalise": normalise.normalise,
    "normalise_record": normalise.normalise_record,
    "principal_authority": joins.principal_authority,
    "profile_apply": _profile_apply,
    "render_json": report.render_json,
    "render_text": report.render_text,
}


@functools.cache
def golden_cases() -> dict[str, list[tuple[int, dict[str, Any]]]]:
    """Return the golden cases grouped by stage, with their line numbers."""
    grouped: dict[str, list[tuple[int, dict[str, Any]]]] = {kind: [] for kind in STAGES}
    lines = GOLDEN_PATH.read_text(encoding="ascii").splitlines()
    for number, line in enumerate(lines, start=1):
        case = json.loads(line)
        grouped[case["kind"]].append((number, case))
    return grouped


def replay(kind: str, encoded_args: list[Any]) -> str:
    """Run one stage on freshly decoded arguments and serialise its output."""
    output = STAGES[kind](*decode(encoded_args))
    return json.dumps(encode(output), ensure_ascii=True)


@pytest.mark.parametrize("kind", sorted(STAGES))
def test_stage_output_matches_golden(kind: str) -> None:
    cases = golden_cases()[kind]
    assert cases, f"no golden cases recorded for {kind}"
    mismatched = [
        number
        for number, case in cases
        if replay(kind, case["args"]) != json.dumps(case["expected"], ensure_ascii=True)
    ]
    assert not mismatched, (
        f"{kind}: {len(mismatched)} of {len(cases)} cases differ; golden lines {mismatched[:20]}"
    )
