# Copyright (c) 2026 Ambit Systems Pty Ltd. All rights reserved.
# Proprietary and confidential. See LICENSE for terms.

"""Tests for the adapter and the command-line surface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ambit_grader.adapters import ambit_receipts
from ambit_grader.cli import main

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
    args = [str(FIXTURES / "complete_records_broken_joins.jsonl"), "--min-completeness", "0.99"]
    assert main(args) == 1
    capsys.readouterr()


def test_cli_reports_unreadable_file(capsys):
    assert main(["definitely-not-here.jsonl"]) == 1
    assert "error:" in capsys.readouterr().out
