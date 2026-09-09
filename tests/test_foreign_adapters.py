# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Conformance tests for the third-party trace-format adapters.

Fixtures are shaped after each emitter's published export format. The recurring
assertion across all of them is the finding: every mainstream agent-trace
format scores `structurally_unfillable` on principal authority, because none of
them records on whose authority an action was taken.
"""

from __future__ import annotations

from typing import Any

import pytest

from ambit_grader import Property, Sufficiency, grade_records
from ambit_grader.adapters import foreign

OTEL_SPAN: dict[str, Any] = {
    "name": "execute_tool refund.issue",
    "startTimeUnixNano": "1785148029563000000",
    "attributes": {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": "refund.issue",
        "gen_ai.tool.call.id": "call_abc123",
        "gen_ai.agent.id": "agent-support",
        "gen_ai.provider.name": "anthropic",
        "gen_ai.usage.input_tokens": 412,
    },
}

OPENINFERENCE_SPAN: dict[str, Any] = {
    "name": "ToolCall",
    "start_time": "2026-07-27T09:00:00Z",
    "attributes": {
        "openinference.span.kind": "TOOL",
        "tool.name": "drop_customer_table",
        "tool.call.id": "tc-77",
        "agent.name": "agent-risky",
        "llm.model_name": "claude-opus-5",
    },
}

LANGFUSE_OBSERVATION: dict[str, Any] = {
    "id": "obs-1",
    "traceId": "trace-9",
    "type": "SPAN",
    "name": "issue_refund",
    "startTime": "2026-07-27T09:01:00Z",
    "userId": "agent-support",
    "input": {"charge": "ch_1"},
    "output": {"refund": "re_1"},
    "metadata": {},
}

LANGSMITH_RUN: dict[str, Any] = {
    "id": "run-1",
    "trace_id": "tr-1",
    "run_type": "tool",
    "name": "send_wire",
    "start_time": "2026-07-27T09:02:00Z",
    "inputs": {"account": "ACC-1", "amount": 50000},
    "outputs": {"ok": True},
    "extra": {"metadata": {}},
}

WEAVE_CALL: dict[str, Any] = {
    "id": "call-1",
    "op_name": "weave:///acme/agent/op/issue_refund",
    "started_at": "2026-07-27T09:03:00Z",
    "inputs": {"charge": "ch_2"},
    "output": {"ok": True},
    "attributes": {},
}

AGT_DECISION: dict[str, Any] = {
    "agent_id": "agent-ops",
    "policy_id": "pol-42",
    "action": "delete",
    "tool": "storage.delete",
    "resource": "s3://bucket/key",
    "decision": "deny",
    "timestamp": "2026-07-27T09:04:00Z",
}

ALL_FIXTURES: list[tuple[str, dict[str, Any]]] = [
    ("otel_genai", OTEL_SPAN),
    ("openinference", OPENINFERENCE_SPAN),
    ("langfuse", LANGFUSE_OBSERVATION),
    ("langsmith", LANGSMITH_RUN),
    ("weave", WEAVE_CALL),
    ("microsoft_agt", AGT_DECISION),
]


def test_every_format_is_detected_as_itself():
    for expected, record in ALL_FIXTURES:
        profile = foreign.match(record)
        assert profile is not None, f"{expected} not detected"
        assert profile.name == expected


def test_no_format_is_reported_as_unrecognised():
    graded = grade_records("all", [record for _name, record in ALL_FIXTURES])
    assert graded.unrecognised == 0
    for name, _record in ALL_FIXTURES:
        assert name in graded.shapes


@pytest.mark.parametrize(
    ("name", "record"),
    [
        ("otel", OTEL_SPAN),
        ("openinference", OPENINFERENCE_SPAN),
        ("langfuse", LANGFUSE_OBSERVATION),
        ("langsmith", LANGSMITH_RUN),
        ("weave", WEAVE_CALL),
        (
            "generic",
            {
                "actor_id": "agent-generic",
                "tool_name": "storage.read",
                "action": {"type": "read"},
            },
        ),
    ],
)
def test_no_verdict_action_remains_in_authority_denominator(name, record):
    attributed = {
        "record_type": "decision",
        "decision": "ALLOW",
        "approval": {
            "approver": "alice",
            "fingerprint_bound": True,
            "valid": True,
        },
    }
    standalone = grade_records(name, [record]).verdicts[Property.PRINCIPAL_AUTHORITY]
    assert standalone.sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE

    mixed = grade_records(name, [attributed, record]).verdicts[Property.PRINCIPAL_AUTHORITY]
    assert mixed.sufficiency is Sufficiency.PARTIALLY_FILLABLE
    assert "1 attributable to a named principal" in (mixed.detail or "")
    assert "1 eligible action(s) without a verdict" in (mixed.detail or "")
    assert "1 with no authority evidence at all" in (mixed.detail or "")


def test_denial_stays_excluded_beside_no_verdict_action():
    denied = {"record_type": "decision", "decision": "DENY"}
    verdict = grade_records("denied-and-otel", [denied, OTEL_SPAN]).verdicts[
        Property.PRINCIPAL_AUTHORITY
    ]
    assert verdict.sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE
    assert "1 denial(s) excluded" in (verdict.detail or "")
    assert "1 eligible action(s) without a verdict" in (verdict.detail or "")


@pytest.mark.parametrize(
    "timestamp",
    ("not-a-time", " 2026-01-01T00:00:00Z ", "2026-02-30T00:00:00Z"),
)
def test_foreign_rfc3339_timestamp_fields_reject_semantic_junk(timestamp):
    mapped = foreign.OPENINFERENCE.apply(
        {
            "name": "ToolCall",
            "start_time": timestamp,
            "attributes": {"openinference.span.kind": "TOOL"},
        }
    )
    assert "ts" not in mapped


@pytest.mark.parametrize(
    "timestamp",
    ("not-a-time", "1٢", "-62135596800000000001", "253402300800000000000"),
)
def test_otel_unix_nanosecond_timestamp_is_explicit_and_bounded(timestamp):
    mapped = foreign.OTEL_GENAI.apply(
        {
            "name": "ToolCall",
            "startTimeUnixNano": timestamp,
            "attributes": {"gen_ai.operation.name": "execute_tool"},
        }
    )
    assert "ts" not in mapped


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    (
        ("-62135596800000000000", "0001-01-01T00:00:00.000000000Z"),
        ("253402300799999999999", "9999-12-31T23:59:59.999999999Z"),
    ),
)
def test_otel_unix_nanosecond_boundaries_canonicalise_to_rfc3339(timestamp, expected):
    mapped = foreign.OTEL_GENAI.apply(
        {
            "name": "ToolCall",
            "startTimeUnixNano": timestamp,
            "attributes": {"gen_ai.operation.name": "execute_tool"},
        }
    )
    assert mapped["ts"] == expected


def test_otel_valid_unix_nanosecond_timestamp_earns_lifecycle_credit():
    mapped = foreign.OTEL_GENAI.apply(OTEL_SPAN)
    assert mapped["ts"] == "2026-07-27T10:27:09.563000000Z"
    graded = grade_records("otel", [OTEL_SPAN])
    assert graded.verdicts[Property.LIFECYCLE_CONTEXT].sufficiency is (
        Sufficiency.PARTIALLY_FILLABLE
    )


@pytest.mark.parametrize(
    "timestamp_fields",
    [
        {
            "start_time": "2026-07-27T10:27:09.563000000Z",
            "timestamp": "2026-07-27T10:27:10.563000000Z",
        },
        {
            "start_time": "2026-07-27T10:27:09.563000000Z",
            "startTimeUnixNano": "1785148029563000001",
        },
        {
            "start_time": "2026-07-27T10:27:09.563000000Z",
            "timestamp": "not-a-time",
        },
    ],
)
def test_otel_timestamp_alias_conflicts_receive_zero_lifecycle_credit(
    timestamp_fields,
):
    record = {
        "attributes": {"gen_ai.operation.name": "execute_tool"},
        "seq": 1,
        "governance_mode": "enforcement",
        **timestamp_fields,
    }
    verdict = grade_records("otel-time-conflict", [record]).verdicts[Property.LIFECYCLE_CONTEXT]
    assert verdict.sufficiency is Sufficiency.CONFLICTING
    assert verdict.weight == 0.0


def test_otel_equivalent_timestamp_aliases_collapse_to_one_instant():
    record = {
        "attributes": {"gen_ai.operation.name": "execute_tool"},
        "start_time": "2026-07-27T10:27:09.563Z",
        "timestamp": "2026-07-27T10:27:09.563000000+00:00",
        "startTimeUnixNano": "1785148029563000000",
        "seq": 1,
        "governance_mode": "enforcement",
    }
    verdict = grade_records("otel-equivalent-time", [record]).verdicts[Property.LIFECYCLE_CONTEXT]
    assert verdict.sufficiency is Sufficiency.FULLY_FILLABLE


def test_openinference_timestamp_alias_conflict_is_not_selected_by_precedence():
    record = {
        "name": "ToolCall",
        "start_time": "2026-01-01T00:00:00Z",
        "timestamp": "2026-01-01T00:00:01+00:00",
        "attributes": {"openinference.span.kind": "TOOL"},
        "seq": 1,
        "governance_mode": "enforcement",
    }
    verdict = grade_records("openinference-time-conflict", [record]).verdicts[
        Property.LIFECYCLE_CONTEXT
    ]
    assert verdict.sufficiency is Sufficiency.CONFLICTING
    assert verdict.weight == 0.0


def test_the_invoked_tool_is_recoverable_from_every_format():
    """Every format records what was called. That much is universal."""
    for name, record in ALL_FIXTURES:
        graded = grade_records(name, [record])
        assert graded.verdicts[Property.ACTION_BOUNDARY].sufficiency is not (
            Sufficiency.STRUCTURALLY_UNFILLABLE
        ), name


def test_langsmith_and_weave_exports_carry_no_actor_identity():
    """Not every format names who acted, and the grader must not pretend.

    LangSmith runs and Weave calls describe the operation without a standard
    field for the acting agent. Inventing one from `session_name` or the op
    path would be the adapter scoring itself.
    """
    for name, record in (("langsmith", LANGSMITH_RUN), ("weave", WEAVE_CALL)):
        graded = grade_records(name, [record])
        assert (
            graded.verdicts[Property.ACTOR_IDENTITY].sufficiency
            is Sufficiency.STRUCTURALLY_UNFILLABLE
        ), name

    for name, record in (
        ("otel_genai", OTEL_SPAN),
        ("openinference", OPENINFERENCE_SPAN),
        ("langfuse", LANGFUSE_OBSERVATION),
        ("microsoft_agt", AGT_DECISION),
    ):
        graded = grade_records(name, [record])
        assert graded.verdicts[Property.ACTOR_IDENTITY].sufficiency is not (
            Sufficiency.STRUCTURALLY_UNFILLABLE
        ), name


def test_langsmith_session_name_is_not_an_actor_but_explicit_metadata_is():
    session_only = {
        "run_type": "tool",
        "name": "send_wire",
        "session_name": "production-project",
        "inputs": {"amount": 50_000},
    }
    session_verdict = grade_records("langsmith-session", [session_only]).verdicts[
        Property.ACTOR_IDENTITY
    ]
    assert session_verdict.sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE

    explicit_actor = {
        **session_only,
        "extra": {"metadata": {"actor_id": "agent-payments"}},
    }
    actor_verdict = grade_records("langsmith-actor", [explicit_actor]).verdicts[
        Property.ACTOR_IDENTITY
    ]
    assert actor_verdict.sufficiency is Sufficiency.FULLY_FILLABLE


def test_no_mainstream_trace_format_can_evidence_a_principal():
    """The finding, made executable.

    OpenTelemetry's GenAI conventions define zero authorisation attributes;
    OpenInference, Langfuse, LangSmith and Weave describe what happened, never
    on whose authority. An estate on any of them cannot answer the question,
    however rich its traces are.
    """
    for name, record in ALL_FIXTURES:
        graded = grade_records(name, [record])
        assert (
            graded.verdicts[Property.PRINCIPAL_AUTHORITY].sufficiency
            is Sufficiency.STRUCTURALLY_UNFILLABLE
        ), f"{name} unexpectedly evidenced a principal"


def test_agt_carries_a_verdict_but_still_names_no_principal():
    """AGT is the only one of the six that decides — and still cannot attribute."""
    graded = grade_records("agt", [AGT_DECISION])
    detail = graded.verdicts[Property.PRINCIPAL_AUTHORITY].detail or ""
    # The DENY was read, so it lands in the denominator as an excluded denial.
    assert "1 denial(s) excluded" in detail


def test_operator_supplied_metadata_is_read_where_it_exists():
    """Nothing stops an operator putting an approver in trace metadata.

    The adapters read it — the finding is that emitters do not populate it by
    default, not that the field could never be filled. Note what is still
    missing even then: a trace with an approver but no verdict cannot say the
    action was *permitted*, so authority stays unevidenced. Both halves have
    to be present, which is the deeper reason traces are not decision records.
    """
    from ambit_grader.adapters.normalise import normalise_record

    enriched = {
        **LANGFUSE_OBSERVATION,
        "metadata": {"approver": "ops-lead@example", "policy_hash": "9f2c41ab"},
    }
    mapped = normalise_record(enriched)
    assert mapped is not None
    assert mapped["approval"]["approver"] == "ops-lead@example"
    assert mapped["policy_hash"] == "9f2c41ab"

    # ...and yet authority is still unevidenced, because nothing says the
    # action was permitted.
    graded = grade_records("langfuse+meta", [enriched])
    assert (
        graded.verdicts[Property.PRINCIPAL_AUTHORITY].sufficiency
        is Sufficiency.STRUCTURALLY_UNFILLABLE
    )


def test_langfuse_bare_approver_does_not_bind_principal_authority():
    """The diagnosed bug, pinned exactly as reported.

    Before the fix, `Profile.apply()` hardcoded `fingerprint_bound: True` on
    every approver it found, so this record — an ALLOW with nothing but a
    bare `metadata.approver` — graded `fully_fillable`. A name in a metadata
    blob is not evidence that anyone authorised this specific action, and
    must not resolve as bound principal authority.
    """
    record = {
        "traceId": "t1",
        "type": "TOOL",
        "name": "pay",
        "decision": "ALLOW",
        "metadata": {"approver": "alice"},
    }
    graded = grade_records("langfuse-bare-approver", [record])
    assert (
        graded.verdicts[Property.PRINCIPAL_AUTHORITY].sufficiency
        is Sufficiency.STRUCTURALLY_UNFILLABLE
    )


def test_langsmith_approved_by_alone_does_not_bind_principal_authority():
    """Same bug, different field name: LangSmith spells it `approved_by`."""
    record = {
        "id": "run-9",
        "trace_id": "tr-9",
        "run_type": "tool",
        "name": "send_wire",
        "start_time": "2026-07-27T09:10:00Z",
        "decision": "ALLOW",
        "extra": {"metadata": {"approved_by": "bob"}},
    }
    graded = grade_records("langsmith-bare-approved-by", [record])
    assert (
        graded.verdicts[Property.PRINCIPAL_AUTHORITY].sufficiency
        is Sufficiency.STRUCTURALLY_UNFILLABLE
    )


def test_agt_observed_approver_alone_does_not_bind_principal_authority():
    """An AGT `identity.approver` field, with no policy field alongside it.

    `test_agt_with_an_observed_approver_can_name_a_principal` below still
    grades better than unfillable after this fix, but only because that
    fixture also carries an observed `policy_id` — a second, independent
    route to partial credit. Stripped to just the approver, the record must
    fall all the way to unfillable: naming someone is not binding them.
    """
    bare_approver = {
        "decision_id": "d-bare-approver",
        "timestamp": "2026-07-28T09:00:00Z",
        "agent_id": "agent-ops",
        "action_requested": "storage.delete",
        "outcome": "allow",
        "fields": [
            {
                "name": "approver",
                "category": "identity",
                "value": "ops-lead@example",
                "source": "audit_source",
                "confidence": 1.0,
                "inferred": False,
            },
        ],
    }
    graded = grade_records("agt-bare-approver", [bare_approver])
    assert (
        graded.verdicts[Property.PRINCIPAL_AUTHORITY].sufficiency
        is Sufficiency.STRUCTURALLY_UNFILLABLE
    )


def test_approval_binding_gates_fingerprint_bound_not_approver_presence():
    """The extensibility mechanism: only a declared binding path can set it.

    A synthetic profile with an `approval_binding` path proves the field is
    load-bearing — naming an approver is not enough; the binding path itself
    must resolve to something interpretable before `fingerprint_bound` may
    be True. A profile with no `approval_binding` path can never set it,
    regardless of what the record contains.
    """
    bound_profile = foreign.Profile(
        name="synthetic-bound",
        detect=lambda r: True,
        decision_event=True,
        approver=("approver",),
        approval_binding=("request_fingerprint",),
    )
    unbound_profile = foreign.Profile(
        name="synthetic-unbound",
        detect=lambda r: True,
        decision_event=True,
        approver=("approver",),
    )

    named_and_bound = {"approver": "alice", "request_fingerprint": "fp-1"}
    named_only = {"approver": "alice"}

    assert bound_profile.apply(named_and_bound)["approval"]["fingerprint_bound"] is True
    assert bound_profile.apply(named_only)["approval"]["fingerprint_bound"] is False
    assert unbound_profile.apply(named_and_bound)["approval"]["fingerprint_bound"] is False


def test_match_prefers_the_governance_profile_on_an_ambiguous_record():
    """`PROFILES` order is load-bearing: the most specific marker wins.

    An untyped record with `decision` and `agent_id` plus a LangSmith
    `run_type` and a Weave `op_name` satisfies three detectors. AGT is first
    because it alone carries a verdict, which must be mapped rather than left
    as an unread string. Without the governance markers, the span-convention
    profile beats the platform exports.
    """
    ambiguous = {"decision": "allow", "agent_id": "a", "run_type": "tool", "op_name": "r"}
    assert foreign.match(ambiguous) is foreign.MS_AGT
    assert grade_records("ambiguous", [ambiguous]).shapes == "1 microsoft_agt"

    span = {"attributes": {"gen_ai.tool.name": "refund"}, "run_type": "tool", "op_name": "r"}
    assert foreign.match(span) is foreign.OTEL_GENAI


def test_no_foreign_profile_can_populate_a_top_level_fingerprint_bound():
    """Guards the first branch of `_approval_envelope_resolves`.

    That branch is reserved for Ambit's own native receipts, which
    precompute the join at the top level. `Profile.apply()` must never write
    a top-level `fingerprint_bound` — only the nested `approval` envelope —
    or a foreign record could counterfeit the native fast path.
    """
    for _name, record in ALL_FIXTURES:
        profile = foreign.match(record)
        assert profile is not None
        mapped = profile.apply(record)
        assert mapped.get("fingerprint_bound") is not True


def test_profiles_never_invent_absent_fields():
    """A field absent from the source must stay absent after mapping."""
    sparse = {"attributes": {"gen_ai.operation.name": "chat"}}
    profile = foreign.match(sparse)
    assert profile is not None
    mapped = profile.apply(sparse)
    assert "actor_id" not in mapped
    assert "policy_hash" not in mapped
    assert "decision" not in mapped
