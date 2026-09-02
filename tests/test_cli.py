# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the JSONL loader and the command-line surface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ambit_grader import EvidenceReadError, load_jsonl
from ambit_grader.cli import EXIT_BELOW_THRESHOLD, EXIT_READ_ERROR, main

FIXTURES = Path(__file__).parent / "fixtures"
SPARSE = FIXTURES / "sparse_records_complete_joins.jsonl"
BROKEN = FIXTURES / "complete_records_broken_joins.jsonl"


def test_loader_skips_blank_lines(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_text('{"a": 1}\n\n{"b": 2}\n', encoding="utf-8")
    assert load_jsonl(path) == [{"a": 1}, {"b": 2}]


def test_loader_accepts_a_str_path(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_text('{"a": 1}\n', encoding="utf-8")
    assert load_jsonl(str(path)) == [{"a": 1}]


def test_loader_returns_no_records_for_an_empty_file(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_bytes(b"")
    assert load_jsonl(path) == []


def test_loader_rejects_malformed_json(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text("{not json}\n", encoding="utf-8")
    with pytest.raises(EvidenceReadError, match="not valid JSON"):
        load_jsonl(path)


def test_loader_rejects_non_object_lines(tmp_path):
    path = tmp_path / "arr.jsonl"
    path.write_text("[1, 2, 3]\n", encoding="utf-8")
    with pytest.raises(EvidenceReadError, match="not a JSON object"):
        load_jsonl(path)


def test_loader_reports_missing_file(tmp_path):
    with pytest.raises(EvidenceReadError, match="cannot read"):
        load_jsonl(tmp_path / "absent.jsonl")


def test_loader_reports_a_directory_as_unreadable(tmp_path):
    with pytest.raises(EvidenceReadError, match="cannot read"):
        load_jsonl(tmp_path)


def test_loader_reports_non_utf8_bytes_with_the_path(tmp_path):
    """A Latin-1 byte is a read error naming the file, never a traceback."""
    path = tmp_path / "latin1.jsonl"
    path.write_bytes(b'{"actor_id": "caf\xe9"}\n')
    with pytest.raises(EvidenceReadError, match=r"latin1\.jsonl is not UTF-8"):
        load_jsonl(path)


def test_loader_skips_a_utf8_byte_order_mark(tmp_path):
    path = tmp_path / "bom.jsonl"
    path.write_bytes(b'\xef\xbb\xbf{"a": 1}\n')
    assert load_jsonl(path) == [{"a": 1}]


def test_loader_splits_on_newline_only(tmp_path):
    """U+2028 inside a JSON string is data, and later line numbers stay right."""
    path = tmp_path / "ls.jsonl"
    path.write_text('{"reason": "a\u2028b"}\r\n{"reason": "c\u0085d"}\nnope\n', encoding="utf-8")
    with pytest.raises(EvidenceReadError, match=r"ls\.jsonl:3 is not valid JSON"):
        load_jsonl(path)
    path.write_text('{"reason": "a\u2028b"}\r\n{"reason": "c\u0085d"}\n', encoding="utf-8")
    assert load_jsonl(path) == [{"reason": "a\u2028b"}, {"reason": "c\u0085d"}]


def test_cli_text_output(capsys):
    exit_code = main([str(SPARSE), str(BROKEN)])
    out = capsys.readouterr().out.splitlines()
    assert exit_code == 0
    # One header and one headline per file.
    assert out[0] == f"{SPARSE} — 5 record(s) [2 ambit_approval, 3 ambit_ledger]"
    assert out[1].startswith("  2 permitted action(s): 2 attributable to a named principal")
    assert out[3] == f"{BROKEN} — 4 record(s) [1 ambit_approval, 3 ambit_ledger]"
    # One column per file, and a verdict that differs between them.
    authority = next(line for line in out if line.startswith("principal_authority"))
    assert authority.split() == ["principal_authority", "fully_fillable", "structurally_unfillable"]
    completeness = next(line for line in out if line.startswith("DEMM completeness"))
    assert completeness.split()[-2:] == ["57.1%", "78.6%"]
    verdict = next(line for line in out if line.startswith("Ambit authority verdict"))
    assert verdict.split()[-2:] == ["partially_fillable", "structurally_unfillable"]


def test_cli_json_output_is_parseable(capsys):
    exit_code = main([str(SPARSE), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert 0.0 <= payload[0]["demm"]["completeness"] <= 1.0
    assert "principal_authority" in payload[0]["demm"]["properties"]
    assert payload[0]["ambit"]["next_move"]


def test_cli_min_completeness_gates(capsys):
    # 5, not 1: a thin-evidence gate breach is a different problem from an
    # unreadable file, and `ambit grade` in the Ambit CLI returns the same code.
    args = [str(BROKEN), "--min-completeness", "0.99"]
    assert main(args) == EXIT_BELOW_THRESHOLD
    capsys.readouterr()


def test_cli_min_completeness_passes_when_grade_meets_threshold(capsys):
    args = [str(SPARSE), "--min-completeness", "0.5"]
    assert main(args) == 0
    capsys.readouterr()


def test_cli_min_completeness_passes_at_the_exact_boundary(capsys):
    # sparse_records_complete_joins.jsonl grades to exactly 4/7; the gate is
    # `completeness < threshold`, so a threshold equal to the grade must pass.
    threshold = 4 / 7
    args = [str(SPARSE), "--min-completeness", str(threshold)]
    assert main(args) == 0
    capsys.readouterr()


@pytest.mark.parametrize("value", ["2", "-1", "nan", "abc"])
def test_cli_min_completeness_rejects_values_outside_the_unit_interval(capsys, value):
    """A typo in a CI gate is a usage error, not a silently disabled gate."""
    with pytest.raises(SystemExit) as excinfo:
        main([str(SPARSE), "--min-completeness", value])
    assert excinfo.value.code == 2
    assert "--min-completeness" in capsys.readouterr().err


def test_cli_reports_unreadable_file(capsys):
    assert main(["definitely-not-here.jsonl"]) == EXIT_READ_ERROR
    captured = capsys.readouterr()
    # stderr, so that --format json on stdout stays a parseable document.
    assert "error:" in captured.err
    assert "error:" not in captured.out


def test_cli_reports_non_utf8_file_without_a_traceback(tmp_path, capsys):
    path = tmp_path / "latin1.jsonl"
    path.write_bytes(b'{"actor_id": "caf\xe9"}\n')
    assert main([str(path)]) == EXIT_READ_ERROR
    captured = capsys.readouterr()
    assert f"error: {path} is not UTF-8" in captured.err
    assert captured.out == "no evidence sets graded\n"


def test_cli_json_with_no_readable_path_prints_an_empty_list(tmp_path, capsys):
    assert main([str(tmp_path / "missing.jsonl"), "--format", "json"]) == EXIT_READ_ERROR
    assert capsys.readouterr().out == "[]\n"


def test_cli_grades_an_empty_file(tmp_path, capsys):
    """An empty file is an evidence set with nothing in it, not a read error."""
    path = tmp_path / "empty.jsonl"
    path.write_bytes(b"")
    assert main([str(path), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["record_count"] == 0
    assert payload[0]["shapes"] == "no records"
    # Only the opaque reasoning-trace row scores: 1/7, rounded by the renderer.
    assert payload[0]["demm"]["completeness"] == 0.1429


def test_cli_accepts_multiple_paths_and_grades_each(capsys):
    args = [str(SPARSE), str(BROKEN), "--format", "json"]
    exit_code = main(args)
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert [item["source"] for item in payload] == [str(SPARSE), str(BROKEN)]


def test_cli_source_distinguishes_paths_with_the_same_basename(tmp_path, capsys):
    a = tmp_path / "a" / "e.jsonl"
    b = tmp_path / "b" / "e.jsonl"
    for path in (a, b):
        path.parent.mkdir()
        path.write_text('{"decision": "ALLOW", "actor_id": "x"}\n', encoding="utf-8")
    assert main([str(a), str(b), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [item["source"] for item in payload] == [str(a), str(b)]


def test_cli_renders_grades_that_succeeded_when_a_later_path_fails(capsys):
    """A readable file is still graded and reported when a sibling is unreadable.

    Previously the loop returned on the first `EvidenceReadError`, before the
    renderer ran, so an already-graded file produced no output at all — the
    operator lost work they had asked for and could act on, with no signal it
    had happened. Every path is now attempted; the failure is reported on
    stderr and still sets a non-zero exit code.
    """
    args = [str(SPARSE), "definitely-not-here.jsonl"]
    exit_code = main(args)
    captured = capsys.readouterr()

    assert exit_code == EXIT_READ_ERROR
    assert "sparse_records_complete_joins.jsonl" in captured.out
    assert "error:" in captured.err


def test_cli_read_error_outranks_a_threshold_breach(capsys):
    """An unreadable path reports as a read error even if a grade also fails the gate."""
    args = [str(BROKEN), "definitely-not-here.jsonl", "--min-completeness", "0.99"]
    assert main(args) == EXIT_READ_ERROR


def test_cli_survives_hostile_json_values(tmp_path, capsys):
    deep = tmp_path / "deep.jsonl"
    deep.write_text('{"a": ' + "[" * 100000 + "]" * 100000 + "}\n")
    huge = tmp_path / "huge.jsonl"
    huge.write_text('{"seq": ' + "9" * 5000 + "}\n")
    assert main([str(deep), str(huge)]) == EXIT_READ_ERROR
    err = capsys.readouterr().err
    assert f"error: {deep}:1 is not valid JSON" in err
    assert f"error: {huge}:1 is not valid JSON" in err
