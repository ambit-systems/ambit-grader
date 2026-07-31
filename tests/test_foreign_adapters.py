# Copyright (c) 2026 Ambit Systems Pty Ltd. All rights reserved.
# Proprietary and confidential. See LICENSE for terms.

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
        approver=("approver",),
        approval_binding=("request_fingerprint",),
    )
    unbound_profile = foreign.Profile(
        name="synthetic-unbound", detect=lambda r: True, approver=("approver",)
    )

    named_and_bound = {"approver": "alice", "request_fingerprint": "fp-1"}
    named_only = {"approver": "alice"}

    assert bound_profile.apply(named_and_bound)["approval"]["fingerprint_bound"] is True
    assert bound_profile.apply(named_only)["approval"]["fingerprint_bound"] is False
    assert unbound_profile.apply(named_and_bound)["approval"]["fingerprint_bound"] is False


def test_no_foreign_profile_declares_an_approval_binding_path():
    """The absence is the product finding, pinned so it cannot regress silently.

    None of the six shipped formats records anything that ties a named
    approver to the specific request it approves, so none may declare an
    `approval_binding` path. If one starts to, this test should be updated
    deliberately, alongside the format's own binding-path fixture.
    """
    for profile in foreign.PROFILES:
        assert profile.approval_binding == (), profile.name


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
    """AGT's evidence is read, but naming an approver alone earns nothing.

    CORRECTED: this test previously asserted only "not
    structurally_unfillable", which the pre-fix adapter satisfied by wrongly
    crediting the bare observed approver as a bound principal
    (`fully_fillable`, via a hardcoded `fingerprint_bound: True` — see
    `foreign.py`). AGT never carries binding evidence for any approver it
    names (`MS_AGT.approval_binding` is empty, like every shipped profile),
    so an unbound name earns no more than `partially_fillable` — and this
    fixture reaches even that only because it also carries an observed
    `policy_id`, a second and independent route to partial credit. See
    `test_agt_observed_approver_alone_does_not_bind_principal_authority` for
    the same approver with no policy alongside it, which is unfillable. The
    old loose assertion passed for the wrong reason and would not have
    caught the bug it was named for; it is tightened here to the specific
    verdict and the specific reason.
    """
    graded = grade_records("agt-observed", [AGT_BOM_WITH_OBSERVED_APPROVER])
    verdict = graded.verdicts[Property.PRINCIPAL_AUTHORITY]
    assert verdict.sufficiency is Sufficiency.PARTIALLY_FILLABLE
    assert "1 policy-permitted only" in (verdict.detail or "")


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


AGT_BOM_AS_SHIPPED: dict[str, Any] = {
    "decision_id": "d-4",
    "timestamp": "2026-07-28T09:00:00Z",
    "agent_id": "agent-ops",
    "action_requested": "storage.delete",
    "outcome": "allow",
    "fields": [
        # Required field, un-inferred — real policy-evaluation content.
        {
            "name": "policy_rules_evaluated",
            "category": "policy",
            "value": ["deny_public_write", "require_review"],
            "source": "policy",
            "confidence": 1.0,
            "inferred": False,
        },
        # Optional field, and AGT sets inferred=True on it (decision_bom.py:580).
        {
            "name": "delegation_chain",
            "category": "lineage",
            "value": ["did:agent:planner", "did:agent:ops"],
            "source": "audit",
            "confidence": 1.0,
            "inferred": True,
        },
    ],
}


def test_agt_required_policy_field_fills_policy_basis():
    """`policy_rules_evaluated` is required and un-inferred — read it."""
    from ambit_grader.adapters.normalise import normalise_record

    mapped = normalise_record(AGT_BOM_AS_SHIPPED)
    assert mapped is not None
    # The rule half of policy basis, not a policy identity.
    assert mapped["matched_rule_id"] == ["deny_public_write", "require_review"]
    assert "policy_hash" not in mapped

    graded = grade_records("agt", [AGT_BOM_AS_SHIPPED])
    assert graded.verdicts[Property.POLICY_BASIS].sufficiency is not (
        Sufficiency.STRUCTURALLY_UNFILLABLE
    )


def test_agt_delegation_chain_as_shipped_is_not_credited():
    """AGT marks its own delegation_chain inferred, so it is not evidence.

    The chain is reconstructed from multiple agent DIDs appearing in audit
    entries — AGT saying it worked out who delegated to whom, not that it
    witnessed a delegation. Crediting it would accept a competitor's
    reconstruction as our observation.
    """
    from ambit_grader.adapters.normalise import normalise_record

    mapped = normalise_record(AGT_BOM_AS_SHIPPED)
    assert mapped is not None
    assert "delegation" not in mapped

    graded = grade_records("agt", [AGT_BOM_AS_SHIPPED])
    # The action is policy-permitted, so authority is capped rather than named.
    detail = graded.verdicts[Property.PRINCIPAL_AUTHORITY].detail or ""
    assert "0 under a delegation whose issuer is not evidenced" in detail
    assert "1 policy-permitted only" in detail


def test_an_observed_delegation_chain_would_be_read_as_issuerless():
    """If AGT ever emits an observed chain, the ordinary rule applies.

    Every entry is an agent DID — a subject. None is an issuer, which is the
    same shape Ambit's own delegation envelope had before it carried a trust
    root. So it caps at partial, exactly as our own HMAC delegations do.
    """
    observed_chain = {
        **AGT_BOM_AS_SHIPPED,
        "decision_id": "d-5",
        "fields": [
            {
                "name": "delegation_chain",
                "category": "lineage",
                "value": ["did:agent:planner", "did:agent:ops"],
                "source": "audit",
                "confidence": 1.0,
                "inferred": False,
            },
        ],
    }
    graded = grade_records("agt-observed-chain", [observed_chain])
    verdict = graded.verdicts[Property.PRINCIPAL_AUTHORITY]
    assert verdict.sufficiency is Sufficiency.PARTIALLY_FILLABLE
    assert "1 under a delegation whose issuer is not evidenced" in (verdict.detail or "")


def test_agt_chain_expansion_does_not_claim_a_validity_the_source_never_gave():
    """AGT's delegation_chain carries no validity signal, so we must not add one.

    The chain is a list of agent DIDs. Nothing in it states that the delegation
    was valid, accepted, or unrevoked — AGT has no field that says so. Writing
    ``valid: True`` while expanding it is the adapter asserting a fact the
    source never gave: the same defect that let a bare approver name read as a
    bound approval, in the same file.

    It is inert today, because :func:`joins._delegation_is_live` tests
    ``valid is not False`` and so treats an absent key and ``True`` alike. That
    is precisely why it is worth closing now: the moment that check is tightened
    to ``is True`` — mirroring the tightening principal authority just received
    — a synthesised ``True`` would start granting credit no evidence supports.
    """
    expanded = foreign.expand_agt_bom_fields(
        {
            "decision_id": "d-9",
            "fields": [
                {
                    "name": "delegation_chain",
                    "category": "lineage",
                    "value": ["did:agent:planner", "did:agent:ops"],
                    "source": "audit",
                    "confidence": 1.0,
                    "inferred": False,
                },
            ],
        }
    )
    delegation = expanded["delegation"]
    assert delegation["kind"] == "agt_delegation_chain"
    assert "valid" not in delegation
