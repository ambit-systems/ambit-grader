# Copyright (c) 2026 Ambit Systems Pty Ltd. All rights reserved.
# Proprietary and confidential. See LICENSE for terms.

"""Tests for the adapter and the command-line surface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ambit_grader.adapters import ambit_receipts
from ambit_grader.cli import EXIT_BELOW_THRESHOLD, EXIT_READ_ERROR, main

FIXTURES = Path(__file__).parent / "fixtures"


def test_adapter_skips_blank_lines(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_text('{"a": 1}\n\n{"b": 2}\n', encoding="utf-8")
    assert ambit_receipts.load(path) == [{"a": 1}, {"b": 2}]


def test_adapter_rejects_malformed_json(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text("{not json}\n", encoding="utf-8")
    with pytest.raises(ambit_receipts.EvidenceReadError, match="not valid JSON"):
        ambit_receipts.load(path)


def test_adapter_rejects_non_object_lines(tmp_path):
    path = tmp_path / "arr.jsonl"
    path.write_text("[1, 2, 3]\n", encoding="utf-8")
    with pytest.raises(ambit_receipts.EvidenceReadError, match="not a JSON object"):
        ambit_receipts.load(path)


def test_adapter_reports_missing_file(tmp_path):
    with pytest.raises(ambit_receipts.EvidenceReadError, match="cannot read"):
        ambit_receipts.load(tmp_path / "absent.jsonl")


def test_cli_text_output(capsys):
    exit_code = main([str(FIXTURES / "sparse_records_complete_joins.jsonl")])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "principal_authority" in out
    assert "DEMM completeness" in out
    assert "Ambit authority verdict" in out


def test_cli_json_output_is_parseable(capsys):
    exit_code = main([str(FIXTURES / "sparse_records_complete_joins.jsonl"), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert 0.0 <= payload[0]["demm"]["completeness"] <= 1.0
    assert "principal_authority" in payload[0]["demm"]["properties"]
    assert payload[0]["ambit"]["next_move"]


def test_cli_min_completeness_gates(capsys):
    # 5, not 1: a thin-evidence gate breach is a different problem from an
    # unreadable file, and `ambit grade` in ambit-cli returns the same code.
    args = [str(FIXTURES / "complete_records_broken_joins.jsonl"), "--min-completeness", "0.99"]
    assert main(args) == EXIT_BELOW_THRESHOLD
    capsys.readouterr()


def test_cli_min_completeness_passes_when_grade_meets_threshold(capsys):
    args = [str(FIXTURES / "sparse_records_complete_joins.jsonl"), "--min-completeness", "0.5"]
    assert main(args) == 0
    capsys.readouterr()


def test_cli_min_completeness_passes_at_the_exact_boundary(capsys):
    # sparse_records_complete_joins.jsonl grades to exactly 4/7; the gate is
    # `completeness < threshold`, so a threshold equal to the grade must pass.
    threshold = 4 / 7
    args = [
        str(FIXTURES / "sparse_records_complete_joins.jsonl"),
        "--min-completeness",
        str(threshold),
    ]
    assert main(args) == 0
    capsys.readouterr()


def test_cli_reports_unreadable_file(capsys):
    assert main(["definitely-not-here.jsonl"]) == EXIT_READ_ERROR
    captured = capsys.readouterr()
    # stderr, so that --format json on stdout stays a parseable document.
    assert "error:" in captured.err
    assert "error:" not in captured.out


def test_cli_accepts_multiple_paths_and_grades_each(capsys):
    args = [
        str(FIXTURES / "sparse_records_complete_joins.jsonl"),
        str(FIXTURES / "complete_records_broken_joins.jsonl"),
        "--format",
        "json",
    ]
    exit_code = main(args)
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert [item["source"] for item in payload] == [
        "sparse_records_complete_joins.jsonl",
        "complete_records_broken_joins.jsonl",
    ]


def test_cli_renders_grades_that_succeeded_when_a_later_path_fails(capsys):
    """A readable file is still graded and reported when a sibling is unreadable.

    Previously the loop returned on the first `EvidenceReadError`, before the
    renderer ran, so an already-graded file produced no output at all — the
    operator lost work they had asked for and could act on, with no signal it
    had happened. Every path is now attempted; the failure is reported on
    stderr and still sets a non-zero exit code.
    """
    args = [
        str(FIXTURES / "sparse_records_complete_joins.jsonl"),
        "definitely-not-here.jsonl",
    ]
    exit_code = main(args)
    captured = capsys.readouterr()

    assert exit_code == EXIT_READ_ERROR
    assert "sparse_records_complete_joins.jsonl" in captured.out
    assert "error:" in captured.err


def test_cli_read_error_outranks_a_threshold_breach(capsys):
    """An unreadable path reports as a read error even if a grade also fails the gate."""
    args = [
        str(FIXTURES / "complete_records_broken_joins.jsonl"),
        "definitely-not-here.jsonl",
        "--min-completeness",
        "0.99",
    ]
    assert main(args) == EXIT_READ_ERROR
