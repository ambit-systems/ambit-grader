# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the JSONL loader and the command-line surface."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import ambit_grader.jsonl as jsonl_module
from ambit_grader import EvidenceReadError, grade_records, load_jsonl
from ambit_grader.cli import EXIT_BELOW_THRESHOLD, EXIT_READ_ERROR, main
from ambit_grader.report import render_json, render_text, terminal_safe

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


@pytest.mark.parametrize("non_json_whitespace", ["\u2028", "\u0085", "\u00a0"])
def test_loader_does_not_skip_non_json_unicode_whitespace(tmp_path, non_json_whitespace):
    path = tmp_path / "unicode-whitespace.jsonl"
    path.write_text('{"a":1}\n' + non_json_whitespace + "\n", encoding="utf-8")
    with pytest.raises(EvidenceReadError, match=r":2 is not valid JSON"):
        load_jsonl(path)


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
    verdict = next(line for line in out if line.startswith("Ambit Authority verdict"))
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


def test_loader_enforces_file_line_record_and_structure_limits(tmp_path, monkeypatch):
    exact = tmp_path / "exact.jsonl"
    payload = b'{"a":1}\n'
    exact.write_bytes(payload)
    monkeypatch.setattr(jsonl_module, "MAX_FILE_BYTES", len(payload))
    monkeypatch.setattr(jsonl_module, "MAX_LINE_BYTES", len(payload) - 1)
    assert load_jsonl(exact) == [{"a": 1}]

    oversized = tmp_path / "oversized.jsonl"
    with oversized.open("wb") as stream:
        stream.truncate(len(payload) + 1)
    with pytest.raises(EvidenceReadError, match="file exceeds"):
        load_jsonl(oversized)

    monkeypatch.setattr(jsonl_module, "MAX_FILE_BYTES", 1024)
    long_line = tmp_path / "long.jsonl"
    long_line.write_bytes(b'{"value":10}\n')
    monkeypatch.setattr(jsonl_module, "MAX_LINE_BYTES", 8)
    with pytest.raises(EvidenceReadError, match="line limit"):
        load_jsonl(long_line)

    monkeypatch.setattr(jsonl_module, "MAX_LINE_BYTES", 1024)
    monkeypatch.setattr(jsonl_module, "MAX_RECORDS", 1)
    two = tmp_path / "two.jsonl"
    two.write_bytes(b'{"a":1}\n{"b":2}\n')
    with pytest.raises(EvidenceReadError, match="record limit"):
        load_jsonl(two)

    monkeypatch.setattr(jsonl_module, "MAX_RECORDS", 10)
    monkeypatch.setattr(jsonl_module, "MAX_JSON_DEPTH", 2)
    nested = tmp_path / "nested.jsonl"
    nested.write_bytes(b'{"a":{"b":1}}\n')
    with pytest.raises(EvidenceReadError, match="nesting depth"):
        load_jsonl(nested)

    monkeypatch.setattr(jsonl_module, "MAX_JSON_DEPTH", 100)
    monkeypatch.setattr(jsonl_module, "MAX_JSON_VALUES", 2)
    wide = tmp_path / "wide.jsonl"
    wide.write_bytes(b'{"a":1,"b":2}\n')
    with pytest.raises(EvidenceReadError, match="value count"):
        load_jsonl(wide)


def test_loader_rejects_fifo_promptly(tmp_path):
    fifo = tmp_path / "evidence.fifo"
    os.mkfifo(fifo)
    script = (
        "from ambit_grader import EvidenceReadError, load_jsonl\n"
        f"p = {str(fifo)!r}\n"
        "try:\n"
        "    load_jsonl(p)\n"
        "except EvidenceReadError:\n"
        "    raise SystemExit(1)\n"
        "raise SystemExit(0)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).parents[1],
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")},
        timeout=2,
        check=False,
    )
    assert result.returncode == EXIT_READ_ERROR


@pytest.mark.parametrize(
    "value",
    ["NaN", "Infinity", "-Infinity", "1e400", '{"nested":NaN}'],
)
def test_loader_and_json_cli_reject_non_finite_numbers(tmp_path, capsys, value):
    path = tmp_path / "non-finite.jsonl"
    path.write_text(f'{{"value":{value}}}\n', encoding="utf-8")
    with pytest.raises(EvidenceReadError, match=r":1 is not valid JSON"):
        load_jsonl(path)
    assert main([str(path), "--format", "json"]) == EXIT_READ_ERROR
    captured = capsys.readouterr()
    assert json.loads(captured.out) == []
    assert f"{path}:1" in captured.err


def test_loader_rejects_duplicate_keys_at_every_depth(tmp_path):
    path = tmp_path / "duplicate.jsonl"
    path.write_text('{"outer":{"a":1,"a":2}}\n', encoding="utf-8")
    with pytest.raises(EvidenceReadError, match="duplicate object key"):
        load_jsonl(path)


def test_text_output_escapes_untrusted_controls_and_surrogates():
    record = {
        "record_type": "outcome\x1b]52;c;Zm9yZ2Vk\x07\u2028\u202e\ud800",
        "actor_id": "a",
    }
    grade = grade_records("source\nname\u202e", [record])
    text = render_text([grade])
    assert "\x1b" not in text
    assert "\nname" not in text
    assert "\u202e" not in text
    assert "\u2028" not in text
    assert "\ud800" not in text
    assert "\\x1b" in text
    assert "\\x0a" in text
    assert "\\u202e" in text
    assert "\\u2028" in text
    assert "\\ud800" in text
    assert terminal_safe("\x1b") == "\\x1b"
    assert terminal_safe("\\x1b") == "\\\\x1b"
    text.encode("utf-8", errors="strict")

    machine = json.loads(render_json([grade]))
    assert machine[0]["source"] == "source\nname\u202e"
    assert "\ud800" in machine[0]["shapes"]


def test_cli_stderr_escapes_control_characters_in_paths(tmp_path, capsys):
    path = tmp_path / "bad\n\x1b[31m.jsonl"
    path.write_text("{not json}\n", encoding="utf-8")
    assert main([str(path)]) == EXIT_READ_ERROR
    error = capsys.readouterr().err
    assert "\x1b" not in error
    assert str(path) not in error
    assert "\\x0a" in error
    assert "\\x1b" in error


def test_text_report_includes_each_stored_reason_and_action():
    grade = grade_records(
        "gaps",
        [{"record_type": "decision", "decision": "ESCALATE", "actor_id": "agent"}],
    )
    text = render_text([grade])
    assert (
        "actor_identity: reason=not recorded; "
        "action=give the 1 permitted action(s) an authority basis"
    ) not in text
    assert (
        "action_boundary: reason=evidence_never_persisted; "
        "action=emit action.type and action.boundary alongside tool_name"
    ) in text
    assert (
        "principal_authority: reason=cross_stack_boundary; "
        "action=link the 1 unresolved escalation(s) to an approval record"
    ) in text


def test_high_completeness_gate_rejects_semantically_malformed_evidence(tmp_path, capsys):
    path = tmp_path / "malformed-types.jsonl"
    record = {
        "record_type": "decision",
        "decision": "ALLOW",
        "actor_id": True,
        "tool_name": True,
        "action": {"type": True, "boundary": True},
        "object": {"kind": True, "id": True, "domain": True},
        "policy_hash": True,
        "matched_rule_id": True,
        "ts": True,
        "seq": True,
        "governance_mode": True,
    }
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    assert main([str(path), "--min-completeness", "0.99"]) == EXIT_BELOW_THRESHOLD
    capsys.readouterr()


def test_malformed_timestamp_cannot_raise_completeness_past_a_gate(tmp_path, capsys):
    record = {
        "record_type": "decision",
        "decision": "ALLOW",
        "actor_id": "agent-1",
        "tool_name": "read",
        "action": {"type": "read", "boundary": "tool_execution"},
        "object": {"kind": "file", "id": "/tmp/input", "domain": "filesystem"},
        "policy_hash": "policy-1",
        "matched_rule_id": "rule-1",
        "ts": "not-a-time",
        "seq": 0,
        "governance_mode": "enforcement",
        "approval": {
            "approver": "alice",
            "fingerprint_bound": True,
            "valid": True,
        },
    }
    valid_record = {**record, "ts": "2026-01-01T00:00:00Z"}
    invalid_score = grade_records("invalid", [record]).completeness
    valid_score = grade_records("valid", [valid_record]).completeness
    assert invalid_score < valid_score

    path = tmp_path / "malformed-timestamp.jsonl"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    threshold = (invalid_score + valid_score) / 2
    assert main([str(path), "--min-completeness", str(threshold)]) == EXIT_BELOW_THRESHOLD
    capsys.readouterr()


@pytest.mark.parametrize(
    "conflict",
    [
        {
            "matched_rule_id": "rule-flat",
            "evidence": {"naming": {"matched_rule_id": "rule-nested"}},
        },
        {
            "ts": "2026-01-01T00:00:00Z",
            "timestamp_utc": "2026-01-01T00:00:01+00:00",
        },
    ],
)
def test_semantic_alias_conflicts_cannot_raise_completeness_past_gate(tmp_path, capsys, conflict):
    valid_record = {
        "record_type": "decision",
        "decision": "ALLOW",
        "actor_id": "agent-1",
        "tool_name": "read",
        "action": {"type": "read", "boundary": "tool_execution"},
        "object": {"kind": "file", "id": "/tmp/input", "domain": "filesystem"},
        "policy_hash": "policy-1",
        "matched_rule_id": "rule-1",
        "ts": "2026-01-01T00:00:00Z",
        "seq": 0,
        "governance_mode": "enforcement",
        "approval": {
            "approver": "alice",
            "fingerprint_bound": True,
            "valid": True,
        },
    }
    conflicted_record = {**valid_record, **conflict}
    valid_score = grade_records("valid", [valid_record]).completeness
    conflicted_score = grade_records("conflicting", [conflicted_record]).completeness
    assert conflicted_score < valid_score

    path = tmp_path / "conflicting-aliases.jsonl"
    path.write_text(json.dumps(conflicted_record) + "\n", encoding="utf-8")
    threshold = (conflicted_score + valid_score) / 2
    assert main([str(path), "--min-completeness", str(threshold)]) == EXIT_BELOW_THRESHOLD
    capsys.readouterr()
