# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Golden-master lock on ``ambit-grade``'s stdout, stderr, and exit code.

Pins the CLI's observable behaviour before any structural change: the text and
JSON reports on the shipped fixtures, the completeness gate, read errors,
usage errors, and help. Fixture paths are relative to the repository root. A
temporary directory in any output is masked as ``<TMP>``. ``COLUMNS`` and
``PYTHON_COLORS`` are fixed because argparse reads both.
"""

from __future__ import annotations

import contextlib
import functools
import io
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ambit_grader.cli import main

REPO = Path(__file__).resolve().parents[1]
GOLDEN_PATH = Path(__file__).parent / "golden" / "cli_outputs.json"
SPARSE = "tests/fixtures/sparse_records_complete_joins.jsonl"
BROKEN = "tests/fixtures/complete_records_broken_joins.jsonl"
MISSING = "tests/fixtures/definitely-missing.jsonl"
CLI_ENVIRONMENT = {"COLUMNS": "80", "PYTHON_COLORS": "0"}
SUBPROCESS_CASE = "subprocess_json_two_fixtures"
SUBPROCESS_ARGV = [SPARSE, BROKEN, "--format", "json"]

_UNTRUSTED_RECORD = {
    "record_type": "outcome\x1b]52;c;Zm9yZ2Vk\x07\u2028\u202e\ud800",
    "actor_id": "a",
}


def _file(workdir: Path, name: str, data: bytes) -> str:
    path = workdir / name
    path.write_bytes(data)
    return str(path)


CASES: dict[str, Callable[[Path], list[str]]] = {
    "text_two_fixtures": lambda _: [SPARSE, BROKEN],
    "json_two_fixtures": lambda _: [SPARSE, BROKEN, "--format", "json"],
    "text_gate_breach": lambda _: [BROKEN, "--min-completeness", "0.99"],
    "json_gate_pass": lambda _: [SPARSE, "--format", "json", "--min-completeness", "0.5"],
    "text_read_error_beside_a_grade": lambda _: [SPARSE, MISSING],
    "json_read_error_only": lambda _: [MISSING, "--format", "json"],
    "read_error_outranks_gate": lambda _: [BROKEN, MISSING, "--min-completeness", "0.99"],
    "directory_is_not_a_regular_file": lambda _: ["tests/fixtures"],
    "non_utf8_file": lambda w: [_file(w, "latin1.jsonl", b'{"actor_id": "caf\xe9"}\n')],
    "invalid_json_line": lambda w: [_file(w, "bad.jsonl", b'{"a": 1}\n{not json}\n')],
    "non_object_line": lambda w: [_file(w, "array.jsonl", b"[1, 2, 3]\n")],
    "duplicate_key": lambda w: [_file(w, "duplicate.jsonl", b'{"outer": {"a": 1, "a": 2}}\n')],
    "non_finite_number": lambda w: [
        _file(w, "nan.jsonl", b'{"value": NaN}\n'),
        "--format",
        "json",
    ],
    "empty_file_text": lambda w: [_file(w, "empty-evidence-file.jsonl", b"")],
    "empty_file_json": lambda w: [_file(w, "empty-evidence-file.jsonl", b""), "--format", "json"],
    "control_characters_in_path": lambda w: [_file(w, "bad\n\x1b[31m.jsonl", b"{not json}\n")],
    "untrusted_text_in_report": lambda w: [
        _file(
            w,
            "untrusted-control-characters.jsonl",
            json.dumps(_UNTRUSTED_RECORD).encode("ascii") + b"\n",
        )
    ],
    "usage_threshold_out_of_range": lambda _: [SPARSE, "--min-completeness", "2"],
    "usage_threshold_not_a_number": lambda _: [SPARSE, "--min-completeness", "abc"],
    "usage_unknown_format": lambda _: [SPARSE, "--format", "xml"],
    "usage_no_paths": lambda _: [],
    "help": lambda _: ["--help"],
}


@functools.cache
def golden() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    return data


def _mask(text: str, workdir: Path) -> str:
    return text.replace(str(workdir), "<TMP>")


def run_cli(argv: list[str], workdir: Path) -> dict[str, Any]:
    """Run ``main`` in-process; return its exit code and masked stdout and stderr."""
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            code: Any = main(argv)
        except SystemExit as exc:
            code = exc.code
    return {
        "exit": code,
        "stdout": _mask(stdout.getvalue(), workdir),
        "stderr": _mask(stderr.getvalue(), workdir),
    }


def run_cli_subprocess() -> dict[str, Any]:
    """Run ``python -m ambit_grader.cli`` in a fresh process from the repository root."""
    env = {**os.environ, **CLI_ENVIRONMENT, "PYTHONPATH": str(REPO / "src")}
    result = subprocess.run(
        [sys.executable, "-m", "ambit_grader.cli", *SUBPROCESS_ARGV],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return {"exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


@pytest.fixture
def cli_workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(REPO)
    for name, value in CLI_ENVIRONMENT.items():
        monkeypatch.setenv(name, value)
    return tmp_path


def test_golden_covers_every_case() -> None:
    assert sorted(golden()) == sorted([*CASES, SUBPROCESS_CASE])


@pytest.mark.parametrize("case", sorted(CASES))
def test_cli_output_matches_golden(case: str, cli_workdir: Path) -> None:
    assert run_cli(CASES[case](cli_workdir), cli_workdir) == golden()[case]


def test_cli_module_in_a_fresh_process_matches_golden() -> None:
    assert run_cli_subprocess() == golden()[SUBPROCESS_CASE]
