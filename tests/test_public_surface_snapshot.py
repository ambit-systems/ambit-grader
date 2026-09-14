# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Characterization lock for the public surface, pinned before any refactor.

``golden/public_surface.json`` records every module's ``__all__`` (or its
absence) and a description of each public name the module defined at the lock
commit: the ``inspect.signature`` of a function, the signature and public
methods of a class, the members of an enum, or the ``repr`` of a constant.
Each name must stay reachable from its original module with the same
description. A diff means the public surface changed; the refactor this lock
guards must not do that.
"""

from __future__ import annotations

import enum
import functools
import importlib
import inspect
import json
import re
from pathlib import Path
from typing import Any

import pytest

import ambit_grader.jsonl as jsonl_module
from ambit_grader import joins

GOLDEN_PATH = Path(__file__).parent / "golden" / "public_surface.json"
MODULES = (
    "ambit_grader",
    "ambit_grader.adapters",
    "ambit_grader.adapters.foreign",
    "ambit_grader.adapters.normalise",
    "ambit_grader.aggregate",
    "ambit_grader.cli",
    "ambit_grader.joins",
    "ambit_grader.jsonl",
    "ambit_grader.models",
    "ambit_grader.properties",
    "ambit_grader.report",
    "ambit_grader.sufficiency",
)
_ADDRESS = re.compile(r" at 0x[0-9a-fA-F]+")


@functools.cache
def golden() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    return data


def _signature(obj: Any) -> str:
    try:
        return str(inspect.signature(obj))
    except TypeError, ValueError:
        return "<no signature>"


def describe(obj: Any) -> str:
    """Describe one public name so that any change to its surface changes the text."""
    if inspect.isclass(obj):
        if issubclass(obj, enum.Enum):
            members = ", ".join(f"{member.name}={member.value!r}" for member in obj)
            return f"enum {obj.__name__}[{members}]"
        methods = []
        for name, member in sorted(vars(obj).items()):
            if name.startswith("_"):
                continue
            if isinstance(member, property):
                methods.append(f"{name}: property")
            elif callable(member):
                methods.append(f"{name}{_signature(member)}")
        return f"class {obj.__name__}{_signature(obj)} {{{'; '.join(methods)}}}"
    if inspect.isfunction(obj):
        return f"function{_signature(obj)}"
    if inspect.ismodule(obj):
        return f"module {obj.__name__}"
    return _ADDRESS.sub(" at 0x?", f"{type(obj).__name__}={obj!r}")


def test_golden_covers_every_module() -> None:
    assert sorted(golden()["modules"]) == sorted(MODULES)


@pytest.mark.parametrize("module_name", MODULES)
def test_module_all_is_unchanged(module_name: str) -> None:
    module = importlib.import_module(module_name)
    assert getattr(module, "__all__", None) == golden()["modules"][module_name]["__all__"]


@pytest.mark.parametrize("module_name", MODULES)
def test_module_public_names_are_unchanged(module_name: str) -> None:
    module = importlib.import_module(module_name)
    expected = golden()["modules"][module_name]["members"]
    missing = sorted(name for name in expected if not hasattr(module, name))
    assert not missing
    assert {name: describe(getattr(module, name)) for name in expected} == expected


def test_joins_still_exposes_the_private_name_the_tests_cite() -> None:
    """``tests/test_foreign_bom.py`` cites ``joins._delegation_is_live`` by name."""
    assert callable(joins._delegation_is_live)


def test_jsonl_limits_stay_with_the_functions_that_read_them() -> None:
    """``tests/test_cli.py`` monkeypatches these limits on ``ambit_grader.jsonl``.

    A patched module global only reaches a function whose own globals are that
    module, so every function that reads a limit must stay defined there.
    """
    for name in ("load", "_check_structure", "_open_regular"):
        assert getattr(jsonl_module, name).__module__ == "ambit_grader.jsonl", name
    limits = {
        "MAX_FILE_BYTES": 64 * 1024 * 1024,
        "MAX_LINE_BYTES": 4 * 1024 * 1024,
        "MAX_RECORDS": 100_000,
        "MAX_JSON_DEPTH": 100,
        "MAX_JSON_VALUES": 250_000,
    }
    assert {name: getattr(jsonl_module, name) for name in limits} == limits
