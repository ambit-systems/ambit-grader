# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Conformance tests for the third-party trace-format adapters.

Fixtures are shaped after each emitter's published export format. The recurring
assertion across all of them is the one that matters commercially: every
mainstream agent-trace format scores `structurally_unfillable` on principal
authority, because none of them records on whose authority an action was taken.
"""

from __future__ import annotations

from typing import Any

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


def test_no_mainstream_trace_format_can_evidence_a_principal():
    """The commercial finding, made executable.

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


def test_profiles_never_invent_absent_fields():
    """A field absent from the source must stay absent after mapping."""
    sparse = {"attributes": {"gen_ai.operation.name": "chat"}}
    profile = foreign.match(sparse)
    assert profile is not None
    mapped = profile.apply(sparse)
    assert "actor_id" not in mapped
    assert "policy_hash" not in mapped
    assert "decision" not in mapped


# --- Microsoft AGT Decision BOM -------------------------------------------
# Shaped after agent-governance-python/agent-mesh/.../governance/decision_bom.py:
# DecisionBOM(decision_id, timestamp, agent_id, action_requested, outcome,
# fields[BOMField(name, category, value, source, confidence, inferred)],
# reconstructed_at, sources_queried, completeness_score).

AGT_BOM_BARE: dict[str, Any] = {
    "decision_id": "d-1",
    "timestamp": "2026-07-28T09:00:00Z",
    "agent_id": "agent-ops",
    "action_requested": "storage.delete",
    "outcome": "allow",
    "fields": [
        {
            "name": "trust_score",
            "category": "trust",
            "value": 0.91,
            "source": "trust_source",
            "confidence": 1.0,
            "inferred": False,
        },
    ],
    "completeness_score": 0.4,
}

AGT_BOM_WITH_OBSERVED_APPROVER: dict[str, Any] = {
    **AGT_BOM_BARE,
    "decision_id": "d-2",
    "fields": [
        {
            "name": "approver",
            "category": "identity",
            "value": "ops-lead@example",
            "source": "audit_source",
            "confidence": 1.0,
            "inferred": False,
        },
        {
            "name": "policy_id",
            "category": "policy",
            "value": "pol-42",
            "source": "policy_source",
            "confidence": 1.0,
            "inferred": False,
        },
    ],
}

AGT_BOM_WITH_INFERRED_APPROVER: dict[str, Any] = {
    **AGT_BOM_BARE,
    "decision_id": "d-3",
    "fields": [
        {
            "name": "approver",
            "category": "identity",
            "value": "ops-lead@example",
            "source": "trace_source",
            "confidence": 0.6,
            "inferred": True,
        },
    ],
}


def test_agt_bom_is_detected_and_its_nested_fields_are_read():
    """A flat-path lookup cannot see inside AGT's `fields` list."""
    from ambit_grader.adapters.normalise import normalise_record

    profile = foreign.match(AGT_BOM_WITH_OBSERVED_APPROVER)
    assert profile is not None and profile.name == "microsoft_agt"

    mapped = normalise_record(AGT_BOM_WITH_OBSERVED_APPROVER)
    assert mapped is not None
    assert mapped["policy_hash"] == "pol-42"
    assert mapped["approval"]["approver"] == "ops-lead@example"


def test_agt_with_an_observed_approver_can_name_a_principal():
    """If AGT's evidence really names an approver, the grader must say so.

    Refusing to read it would be the grader wrong in its own favour, pointed
    at a competitor's evidence — and it would make the headline finding a
    false negative rather than a finding.
    """
    graded = grade_records("agt-observed", [AGT_BOM_WITH_OBSERVED_APPROVER])
    assert (
        graded.verdicts[Property.PRINCIPAL_AUTHORITY].sufficiency
        is not Sufficiency.STRUCTURALLY_UNFILLABLE
    )


def test_agt_inferred_approver_is_never_credited_as_a_principal():
    """`inferred: true` is AGT reconstructing, not witnessing.

    Crediting it would accept a competitor's inference as our observation —
    the container fallacy borrowed from someone else's tool.
    """
    graded = grade_records("agt-inferred", [AGT_BOM_WITH_INFERRED_APPROVER])
    assert (
        graded.verdicts[Property.PRINCIPAL_AUTHORITY].sufficiency
        is Sufficiency.STRUCTURALLY_UNFILLABLE
    )


def test_agt_without_identity_fields_still_reports_the_finding():
    """The headline finding survives: a bare BOM names no principal."""
    graded = grade_records("agt-bare", [AGT_BOM_BARE])
    assert (
        graded.verdicts[Property.PRINCIPAL_AUTHORITY].sufficiency
        is Sufficiency.STRUCTURALLY_UNFILLABLE
    )


def test_agt_expansion_separates_observed_from_inferred():
    expanded = foreign.expand_agt_bom_fields(AGT_BOM_WITH_INFERRED_APPROVER)
    assert "_agt_inferred" in expanded
    assert "_agt_observed" not in expanded
    assert expanded["_agt_inferred"]["identity"]["approver"]["confidence"] == 0.6
