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


def _agt_observed_field(name, category, value, confidence=1.0):
    return {
        "name": name,
        "category": category,
        "value": value,
        "source": "test",
        "confidence": confidence,
        "inferred": False,
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


@pytest.mark.parametrize("confidence", [0.0, 0])
def test_zero_confidence_agt_approver_is_not_promoted_as_named(confidence):
    from ambit_grader.adapters.normalise import normalise_record

    record = {
        **AGT_BOM_BARE,
        "fields": [_agt_observed_field("approver", "identity", "alice", confidence)],
    }
    mapped = normalise_record(record)
    assert mapped is not None
    assert "approval" not in mapped

    verdict = grade_records("zero-confidence-approver", [record]).verdicts[
        Property.PRINCIPAL_AUTHORITY
    ]
    assert verdict.sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE
    assert "0 naming an approver not bound to this action" in (verdict.detail or "")


def test_subunit_confidence_agt_approver_preserves_source_confidence():
    from ambit_grader.adapters.normalise import normalise_record

    record = {
        **AGT_BOM_BARE,
        "fields": [_agt_observed_field("approver", "identity", "alice", 0.4)],
    }
    mapped = normalise_record(record)
    assert mapped is not None
    assert mapped["approval"]["approver"] == "alice"
    assert mapped["approval"]["confidence"] == pytest.approx(0.4)


def test_agt_inferred_approver_is_never_credited_as_a_principal():
    """`inferred: true` is AGT reconstructing, not witnessing.

    Crediting it would accept a third-party format's inference as Ambit's
    observation — the container fallacy borrowed from someone else's tool.
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


@pytest.mark.parametrize("reverse", [False, True])
def test_conflicting_duplicate_agt_policy_claims_never_join_by_list_order(reverse):
    from ambit_grader.adapters.normalise import normalise_record

    policy_fields = [
        _agt_observed_field("policy_id", "policy", "policy-A"),
        _agt_observed_field("policy_id", "policy", "policy-B"),
    ]
    if reverse:
        policy_fields.reverse()
    record = {**AGT_BOM_BARE, "fields": policy_fields}
    attestation = {
        "record_type": "policy_attestation",
        "policy_hash": "policy-B",
        "approver": "alice",
        "trust_root_id": "root-1",
    }

    expanded = foreign.expand_agt_bom_fields(record)
    assert isinstance(expanded["_agt_observed"]["policy"]["policy_id"], list)
    mapped = normalise_record(record)
    assert mapped is not None
    assert "policy_hash" not in mapped

    verdict = grade_records("duplicate-policy", [record, attestation]).verdicts[
        Property.PRINCIPAL_AUTHORITY
    ]
    assert verdict.sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE
    assert "0 attributable to a named principal" in (verdict.detail or "")


def test_equal_duplicate_agt_policy_claims_may_collapse_and_join():
    from ambit_grader.adapters.normalise import normalise_record

    record = {
        **AGT_BOM_BARE,
        "fields": [
            _agt_observed_field("policy_id", "policy", "policy-A"),
            _agt_observed_field("policy_id", "policy", "policy-A"),
        ],
    }
    mapped = normalise_record(record)
    assert mapped is not None
    assert mapped["policy_hash"] == "policy-A"

    attestation = {
        "record_type": "policy_attestation",
        "policy_hash": "policy-A",
        "approver": "alice",
        "trust_root_id": "root-1",
    }
    verdict = grade_records("equal-policy", [record, attestation]).verdicts[
        Property.PRINCIPAL_AUTHORITY
    ]
    assert verdict.sufficiency is Sufficiency.FULLY_FILLABLE


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize(
    ("nested_policy", "bom_policy"),
    [("policy-B", "policy-A"), ("policy-A", "policy-B")],
)
def test_agt_policy_identity_reconciles_top_nested_and_bom(reverse, nested_policy, bom_policy):
    from ambit_grader.adapters.normalise import normalise_record

    entries = [
        ("policy_id", "policy-A"),
        ("policy", {"id": nested_policy}),
        ("fields", [_agt_observed_field("policy_id", "policy", bom_policy)]),
    ]
    if reverse:
        entries.reverse()
    record = {**AGT_BOM_BARE, **dict(entries)}
    mapped = normalise_record(record)
    assert mapped is not None
    assert "policy_hash" not in mapped

    attestation = {
        "record_type": "policy_attestation",
        "policy_hash": "policy-A",
        "approver": "alice",
        "trust_root_id": "root-1",
    }
    verdict = grade_records("policy-conflict", [record, attestation]).verdicts[
        Property.PRINCIPAL_AUTHORITY
    ]
    assert verdict.sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE
    assert "0 attributable to a named principal" in (verdict.detail or "")


def test_equal_agt_policy_identity_representations_join_with_bom_confidence():
    from ambit_grader.adapters.normalise import normalise_record

    record = {
        **AGT_BOM_BARE,
        "policy_id": "policy-A",
        "policy": {"id": "policy-A"},
        "fields": [_agt_observed_field("policy_id", "policy", "policy-A", 0.4)],
    }
    mapped = normalise_record(record)
    assert mapped is not None
    assert mapped["policy_hash"] == "policy-A"
    assert mapped["_policy_confidence"] == pytest.approx(0.4)

    attestation = {
        "record_type": "policy_attestation",
        "policy_hash": "policy-A",
        "approver": "alice",
        "trust_root_id": "root-1",
    }
    verdict = grade_records("policy-equal", [record, attestation]).verdicts[
        Property.PRINCIPAL_AUTHORITY
    ]
    assert verdict.sufficiency is Sufficiency.PARTIALLY_FILLABLE
    assert verdict.confidence == pytest.approx(0.4)


@pytest.mark.parametrize("malformed", [["policy-A"], {"value": "policy-A"}, True])
def test_malformed_policy_identity_alias_quarantines_valid_agt_identity(malformed):
    from ambit_grader.adapters.normalise import normalise_record

    record = {
        **AGT_BOM_BARE,
        "policy_id": "policy-A",
        "policy": {"id": malformed},
        "fields": [_agt_observed_field("policy_id", "policy", "policy-A")],
    }
    mapped = normalise_record(record)
    assert mapped is not None
    assert "policy_hash" not in mapped


@pytest.mark.parametrize(
    ("confidence", "expected_authority", "expected_fraction"),
    [
        (0.0, Sufficiency.PARTIALLY_FILLABLE, 0.0),
        (0.4, Sufficiency.PARTIALLY_FILLABLE, 0.4),
        (1.0, Sufficiency.FULLY_FILLABLE, 0.5),
    ],
)
def test_agt_policy_confidence_caps_property_and_attested_authority(
    confidence, expected_authority, expected_fraction
):
    from ambit_grader.adapters.normalise import normalise_record
    from ambit_grader.properties import policy_basis

    record = {
        **AGT_BOM_BARE,
        "fields": [_agt_observed_field("policy_id", "policy", "policy-A", confidence)],
    }
    mapped = normalise_record(record)
    assert mapped is not None
    assert mapped["_policy_confidence"] == pytest.approx(confidence)
    assert policy_basis(mapped)[1] == pytest.approx(expected_fraction)

    attestation = {
        "record_type": "policy_attestation",
        "policy_hash": "policy-A",
        "approver": "alice",
        "trust_root_id": "root-1",
    }
    verdict = grade_records("policy-confidence", [record, attestation]).verdicts[
        Property.PRINCIPAL_AUTHORITY
    ]
    assert verdict.sufficiency is expected_authority
    if confidence == 0.0:
        assert "0 attributable to a named principal" in (verdict.detail or "")
        assert "raise confidence" in (verdict.recommendation or "")


@pytest.mark.parametrize("confidence", [True, "0.4", -0.1, 1.1, float("nan"), float("inf")])
def test_malformed_agt_policy_confidence_is_never_lifted_or_joined(confidence):
    from ambit_grader.adapters.normalise import normalise_record

    record = {
        **AGT_BOM_BARE,
        "fields": [_agt_observed_field("policy_id", "policy", "policy-A", confidence)],
    }
    mapped = normalise_record(record)
    assert mapped is not None
    assert "policy_hash" not in mapped

    attestation = {
        "record_type": "policy_attestation",
        "policy_hash": "policy-A",
        "approver": "alice",
        "trust_root_id": "root-1",
    }
    verdict = grade_records("bad-confidence", [record, attestation]).verdicts[
        Property.PRINCIPAL_AUTHORITY
    ]
    assert verdict.sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE


def test_missing_agt_policy_confidence_is_never_lifted():
    from ambit_grader.adapters.normalise import normalise_record

    field = _agt_observed_field("policy_id", "policy", "policy-A")
    field.pop("confidence")
    mapped = normalise_record({**AGT_BOM_BARE, "fields": [field]})
    assert mapped is not None
    assert "policy_hash" not in mapped


@pytest.mark.parametrize("reverse", [False, True])
def test_equal_duplicate_agt_policy_claims_use_least_confidence(reverse):
    from ambit_grader.adapters.normalise import normalise_record

    fields = [
        _agt_observed_field("policy_id", "policy", "policy-A", 1.0),
        _agt_observed_field("policy_id", "policy", "policy-A", 0.0),
    ]
    if reverse:
        fields.reverse()
    record = {**AGT_BOM_BARE, "fields": fields}
    mapped = normalise_record(record)
    assert mapped is not None
    assert mapped["policy_hash"] == "policy-A"
    assert mapped["_policy_confidence"] == 0.0

    attestation = {
        "record_type": "policy_attestation",
        "policy_hash": "policy-A",
        "approver": "alice",
        "trust_root_id": "root-1",
    }
    verdict = grade_records("duplicate-confidence", [record, attestation]).verdicts[
        Property.PRINCIPAL_AUTHORITY
    ]
    assert verdict.sufficiency is Sufficiency.PARTIALLY_FILLABLE
    assert "0 attributable to a named principal" in (verdict.detail or "")
    assert "raise confidence" in (verdict.recommendation or "")


@pytest.mark.parametrize("malformed_parent", [["policy-A"], "policy-A", True])
def test_malformed_nested_policy_container_quarantines_valid_identity(
    malformed_parent,
):
    from ambit_grader.adapters.normalise import normalise_record

    mapped = normalise_record(
        {
            **AGT_BOM_BARE,
            "policy_id": "policy-A",
            "policy": malformed_parent,
            "fields": [_agt_observed_field("policy_id", "policy", "policy-A")],
        }
    )
    assert mapped is not None
    assert "policy_hash" not in mapped


@pytest.mark.parametrize("name", ["policy_version", "policy_name"])
def test_agt_policy_metadata_is_not_used_as_stable_attestation_identity(name):
    from ambit_grader.adapters.normalise import normalise_record

    record = {
        **AGT_BOM_BARE,
        "policy_version": "version-7",
        "fields": [_agt_observed_field(name, "policy", "metadata-only")],
    }
    mapped = normalise_record(record)
    assert mapped is not None
    assert "policy_hash" not in mapped

    attestation = {
        "record_type": "policy_attestation",
        "policy_hash": "metadata-only",
        "approver": "alice",
        "trust_root_id": "root-1",
    }
    verdict = grade_records("policy-metadata", [record, attestation]).verdicts[
        Property.PRINCIPAL_AUTHORITY
    ]
    assert verdict.sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE


@pytest.mark.parametrize("malformed", [["policy-A"], {"id": "policy-A"}, True])
def test_valid_and_malformed_duplicate_agt_policy_claims_are_quarantined(malformed):
    from ambit_grader.adapters.normalise import normalise_record

    record = {
        **AGT_BOM_BARE,
        "policy_id": "policy-A",
        "fields": [
            _agt_observed_field("policy_id", "policy", "policy-A"),
            _agt_observed_field("policy_id", "policy", malformed),
        ],
    }
    mapped = normalise_record(record)
    assert mapped is not None
    assert "policy_hash" not in mapped


def test_conflicting_duplicate_agt_approvers_are_not_promoted():
    from ambit_grader.adapters.normalise import normalise_record

    record = {
        **AGT_BOM_BARE,
        "fields": [
            _agt_observed_field("approver", "identity", "alice"),
            _agt_observed_field("approver", "identity", "bob"),
        ],
    }
    mapped = normalise_record(record)
    assert mapped is not None
    assert "approval" not in mapped


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


@pytest.mark.parametrize(
    "evaluated_rules",
    [
        ["deny_public_write", "require_review"],
        ["require_review"],
        "require_review",
    ],
)
def test_agt_evaluated_rule_collection_never_becomes_matched_rule(evaluated_rules):
    from ambit_grader.adapters.normalise import normalise_record

    record = {
        **AGT_BOM_AS_SHIPPED,
        "fields": [
            _agt_observed_field("policy_id", "policy", "policy-A"),
            _agt_observed_field("policy_rules_evaluated", "policy", evaluated_rules),
        ],
    }
    mapped = normalise_record(record)
    assert mapped is not None
    assert mapped["policy_hash"] == "policy-A"
    assert "matched_rule_id" not in mapped

    verdict = grade_records("agt-rules", [record]).verdicts[Property.POLICY_BASIS]
    assert verdict.sufficiency is Sufficiency.PARTIALLY_FILLABLE


def test_agt_delegation_chain_as_shipped_is_not_credited():
    """AGT marks its own delegation_chain inferred, so it is not evidence.

    The chain is reconstructed from multiple agent DIDs appearing in audit
    entries — AGT saying it worked out who delegated to whom, not that it
    witnessed a delegation. Crediting it would accept a third-party format's
    reconstruction as Ambit's observation.
    """
    from ambit_grader.adapters.normalise import normalise_record

    mapped = normalise_record(AGT_BOM_AS_SHIPPED)
    assert mapped is not None
    assert "delegation" not in mapped

    graded = grade_records("agt", [AGT_BOM_AS_SHIPPED])
    detail = graded.verdicts[Property.PRINCIPAL_AUTHORITY].detail or ""
    assert "0 under a delegation whose issuer is not evidenced" in detail
    assert "1 with no authority evidence at all" in detail


def test_an_observed_delegation_chain_without_validity_is_not_credited():
    """An observed lineage chain is not an assertion that a grant is live.

    Every entry is an agent DID — a subject. None is an issuer, and AGT
    supplies no affirmative validity status. Descriptive lineage alone cannot
    prove authority.
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
    assert verdict.sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE
    assert "0 under a delegation whose issuer is not evidenced" in (verdict.detail or "")


def test_agt_chain_expansion_does_not_claim_a_validity_the_source_never_gave():
    """AGT's delegation_chain carries no validity signal, so we must not add one.

    The chain is a list of agent DIDs. Nothing in it states that the delegation
    was valid, accepted, or unrevoked — AGT has no field that says so. Writing
    ``valid: True`` while expanding it is the adapter asserting a fact the
    source never gave: the same defect that let a bare approver name read as a
    bound approval, in the same file.

    It remains inert because :func:`joins._delegation_is_live` requires
    ``valid is True``. Synthesising that flag here would let the adapter grant
    authority the source never asserted.
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


@pytest.mark.parametrize("junk", [5, ["x"], True, "text"])
def test_non_dict_approval_and_delegation_on_third_party_records_are_graded(junk: object) -> None:
    langfuse = {
        "traceId": "t",
        "type": "SPAN",
        "startTime": "t",
        "approval": junk,
        "metadata": {"approver": "al"},
    }
    agt = {
        "decisionId": "d",
        "verdict": "ALLOW",
        "agent_id": "a",
        "delegation": junk,
        "lineage": {"delegation_chain": {"value": ["root"]}},
    }
    grade = grade_records("hostile", [langfuse, agt])
    assert grade.record_count >= 0


@pytest.mark.parametrize("unsupported", ["ALOW", 7, ["ALLOW"], "", [], {}, None])
def test_unsupported_agt_verdict_remains_in_authority_denominator(unsupported):
    attributed = {
        "record_type": "decision",
        "decision": "ALLOW",
        "approval": {
            "approver": "alice",
            "fingerprint_bound": True,
            "valid": True,
        },
    }
    agt = {
        "decision": unsupported,
        "policy_id": "policy-1",
        "agent_id": "agent-1",
    }
    grade = grade_records("mixed", [attributed, agt])
    verdict = grade.verdicts[Property.PRINCIPAL_AUTHORITY]
    assert verdict.sufficiency is Sufficiency.CONFLICTING
    assert "1 unsupported decision verdict(s)" in (verdict.detail or "")


@pytest.mark.parametrize(
    "record",
    [
        {
            "decision": "DENY",
            "outcome": "allow",
            "agent_id": "agent-1",
        },
        {
            "outcome": "allow",
            "agent_id": "agent-1",
            "decision": "DENY",
        },
    ],
)
@pytest.mark.parametrize("with_attributed_allow", [False, True])
def test_conflicting_agt_verdict_aliases_fail_closed_in_any_member_order(
    record, with_attributed_allow
):
    records = [record]
    if with_attributed_allow:
        records.append(
            {
                "record_type": "decision",
                "decision": "ALLOW",
                "approval": {
                    "approver": "alice",
                    "fingerprint_bound": True,
                    "valid": True,
                },
            }
        )
    verdict = grade_records("conflicting-agt", records).verdicts[Property.PRINCIPAL_AUTHORITY]
    assert verdict.sufficiency is Sufficiency.CONFLICTING
    assert "1 unsupported decision verdict(s)" in (verdict.detail or "")


def test_agt_nested_decision_outcome_is_an_unambiguous_structural_parent():
    from ambit_grader.adapters.normalise import normalise_record

    mapped = normalise_record({"decision": {"outcome": "allow"}, "agent_id": "agent-1"})
    assert mapped is not None
    assert mapped["decision"] == "ALLOW"
    assert "_unsupported_decision" not in mapped


@pytest.mark.parametrize(
    "malformed",
    ["not-a-verdict", "AAAAAAAA", 1, True, ["ALLOW"], {"metadata": "not-a-verdict"}],
)
def test_malformed_substantive_agt_verdict_alias_poison_valid_alias(malformed):
    grade = grade_records(
        "malformed-agt-alias",
        [{"decision": malformed, "outcome": "allow", "agent_id": "agent-1"}],
    )
    assert grade.verdicts[Property.PRINCIPAL_AUTHORITY].sufficiency is Sufficiency.CONFLICTING


def test_equivalent_agt_verdict_aliases_are_compatible():
    from ambit_grader.adapters.normalise import normalise_record

    mapped = normalise_record(
        {
            "decision": "DENY",
            "outcome": "denied",
            "result": "block",
            "agent_id": "agent-1",
        }
    )
    assert mapped is not None
    assert mapped["decision"] == "DENY"
    assert "_unsupported_decision" not in mapped


@pytest.mark.parametrize("malformed", [1, "true", None, [], {}])
def test_malformed_agt_inferred_flags_are_quarantined(malformed):
    from ambit_grader.adapters.normalise import normalise_record

    record = {
        "decision_id": "d-malformed-inferred",
        "timestamp": "2026-07-28T09:00:00Z",
        "agent_id": "agent-ops",
        "action_requested": "storage.delete",
        "outcome": "allow",
        "fields": [
            {
                "name": "policy_id",
                "category": "policy",
                "value": "policy-malformed",
                "inferred": malformed,
            },
            {
                "name": "approver",
                "category": "identity",
                "value": "mallory",
                "inferred": malformed,
            },
        ],
    }
    expanded = foreign.expand_agt_bom_fields(record)
    assert "_agt_observed" not in expanded
    assert "_agt_inferred" not in expanded

    mapped = normalise_record(record)
    assert mapped is not None
    assert "policy_hash" not in mapped
    assert "approval" not in mapped

    attestation = {
        "record_type": "policy_attestation",
        "policy_hash": "policy-malformed",
        "approver": "mallory",
        "trust_root_id": "root-1",
    }
    verdict = grade_records("malformed-inferred", [record, attestation]).verdicts[
        Property.PRINCIPAL_AUTHORITY
    ]
    assert verdict.sufficiency is Sufficiency.STRUCTURALLY_UNFILLABLE


def test_valid_foreign_fallbacks_replace_malformed_canonical_fields():
    from ambit_grader.adapters.normalise import normalise_record

    record = {
        "decision": "ALLOW",
        "policy_id": "policy-1",
        "agent_id": "agent-1",
        "action": {"type": True},
        "action_requested": "storage.delete",
        "object": {"id": {"invalid": True}},
        "resource": "s3://bucket/key",
    }
    mapped = normalise_record(record)
    assert mapped is not None
    assert mapped["action"]["type"] == "storage.delete"
    assert mapped["object"]["id"] == "s3://bucket/key"


def test_foreign_records_cannot_inject_unmapped_native_authority_fields():
    langfuse = {
        "traceId": "trace-1",
        "type": "TOOL",
        "name": "pay",
        "decision": "ALLOW",
        "approver": "mallory",
        "fingerprint_bound": True,
        "approval": {
            "approver": "mallory",
            "fingerprint_bound": True,
            "valid": True,
        },
        "delegation": {
            "id": "forged",
            "kind": "ed25519_token",
            "issuer": "mallory",
            "valid": True,
        },
    }
    agt = {
        "decision": "ALLOW",
        "policy_id": "policy-1",
        "agent_id": "agent-1",
        "approval": {
            "approver": "mallory",
            "fingerprint_bound": True,
            "valid": True,
        },
        "delegation": {
            "id": "forged",
            "kind": "ed25519_token",
            "issuer": "mallory",
            "valid": True,
        },
    }
    for record in (langfuse, agt):
        grade = grade_records("hostile-foreign", [record])
        authority = grade.verdicts[Property.PRINCIPAL_AUTHORITY]
        assert authority.sufficiency is not Sufficiency.FULLY_FILLABLE
        assert "1 attributable to a named principal" not in (authority.detail or "")

    nested_policy = {
        "decision": "ALLOW",
        "agent_id": "agent-1",
        "evidence": {"hashes": {"policy_hash": "forged-policy"}},
    }
    attestation = {
        "record_type": "policy_attestation",
        "policy_hash": "forged-policy",
        "approver": "mallory",
        "trust_root_id": "forged-root",
    }
    authority = grade_records("nested-hostile-foreign", [nested_policy, attestation]).verdicts[
        Property.PRINCIPAL_AUTHORITY
    ]
    assert authority.sufficiency is not Sufficiency.FULLY_FILLABLE


def test_agt_reserved_expansion_keys_are_derived_not_trusted():
    from ambit_grader.adapters.normalise import normalise_record

    injected = {
        "decision": "ALLOW",
        "agent_id": "agent-1",
        "_agt_observed": {
            "policy": {"policy_id": {"value": "forged-policy"}},
            "identity": {"approver": {"value": "mallory"}},
        },
        "_agt_inferred": {"lineage": {"delegation_chain": {"value": ["forged"]}}},
    }
    expanded = foreign.expand_agt_bom_fields(injected)
    assert "_agt_observed" not in expanded
    assert "_agt_inferred" not in expanded

    mapped = normalise_record(injected)
    assert mapped is not None
    assert "policy_hash" not in mapped
    assert "approval" not in mapped
