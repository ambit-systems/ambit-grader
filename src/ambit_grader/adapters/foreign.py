# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Adapters for third-party agent-trace formats.

Each profile maps one emitter's field paths onto the canonical shape the
property checks read. Profiles map; they never invent. A field absent from the
source stays absent, because the grade must measure the evidence rather than
the adapter's willingness to guess.

**The result these adapters produce is the same for every one of them, and that
is the finding.** No mainstream agent-trace format carries an authorisation
attribute. OpenTelemetry's GenAI semantic conventions define none — verified by
enumerating the `gen_ai.*` registry: nothing for authorisation, permission,
approval, consent, identity, principal, or delegation. OpenInference, Langfuse,
LangSmith and Weave all describe what the model and tools *did*, never on whose
authority. So an estate instrumented with any of them scores
`structurally_unfillable` on principal authority no matter how rich its traces
are. That is not a limitation of these adapters; it is the gap the grader
exists to name, and reading the formats faithfully is what makes it checkable.

Format selection is by observed adoption, not completeness: the OTel GenAI
conventions (the standard, Development status), OpenInference (Arize Phoenix's
convention, purpose-built for agent workloads), Langfuse (open-source,
self-hostable), LangSmith (LangChain/LangGraph), W&B Weave, and Microsoft's
Agent Governance Toolkit decision records — the only one of the six that even
attempts a governance verdict.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ambit_grader.adapters.agt_bom import _agt_paths_unusable
from ambit_grader.adapters.agt_bom import expand_agt_bom_fields as expand_agt_bom_fields
from ambit_grader.adapters.reconcile import (
    _first_matching,
    _first_matching_confident_claim,
    _reconciled_policy,
    _reconciled_timestamp,
    _reconciled_verdict,
)
from ambit_grader.sufficiency import (
    is_identifier,
    is_text,
)

# Foreign records may happen to use Ambit's canonical field names. Authority
# is credited only when the matched profile explicitly maps those claims.
_CANONICAL_AUTHORITY_FIELDS = frozenset(
    {
        "approval",
        "approval_approver",
        "approval_fingerprint",
        "approval_jti",
        "approver",
        "decision",
        "delegation",
        "fingerprint_bound",
        "matched_rule_id",
        "policy_hash",
        "request_fingerprint",
    }
)


def _without_canonical_claims(record: dict[str, Any]) -> dict[str, Any]:
    """Copy a record without the canonical claims that a profile must map itself."""
    out: dict[str, Any] = dict(record)
    out.pop("_conflicting_timestamp", None)
    out.pop("_policy_confidence", None)
    out.pop("ts", None)
    out.pop("timestamp_utc", None)
    for field in _CANONICAL_AUTHORITY_FIELDS:
        out.pop(field, None)
    out.pop("_unsupported_decision", None)
    evidence = out.get("evidence")
    if isinstance(evidence, dict):
        evidence = dict(evidence)
        for container_name, fields in (
            ("hashes", ("policy_hash", "request_fingerprint")),
            ("naming", ("matched_rule_id",)),
        ):
            container = evidence.get(container_name)
            if isinstance(container, dict):
                container = dict(container)
                for field in fields:
                    container.pop(field, None)
                evidence[container_name] = container
        out["evidence"] = evidence
    return out


@dataclass(frozen=True, slots=True)
class Profile:
    """One emitter's mapping onto the canonical shape.

    Attributes:
        name: Shape name reported in the grade.
        detect: Returns True if a record was emitted by this format.
        decision_event: Whether this profile's records are eligible for
            per-record DEMM property scoring.
        actor: Dotted paths that may hold the acting agent's identity.
        tool: Dotted paths that may hold the invoked tool's name.
        action_type: Dotted paths that may hold the operation kind.
        object_id: Dotted paths that may hold the target's identity.
        timestamp: Dotted paths that may hold the event time.
        unix_nanosecond_timestamp: Dotted paths explicitly defined by the
            emitter as Unix-nanosecond instants.
        verdict: Dotted paths that may hold a governance verdict.
        policy: Dotted paths that may hold a policy identity.
        rule: Dotted paths that may hold the rule identity within a policy.
        approver: Dotted paths that may name an approving principal.
        approval_binding: Dotted paths that would carry evidence tying a named
            approver to *this* request — a request fingerprint, action hash,
            or equivalent the approval itself references. Naming an approver
            is not binding one; this is what makes the difference checkable.
            None of the six shipped profiles declares one: no mainstream trace
            format records the join between an approver and the request it
            approves, so a name alone never sets ``fingerprint_bound``.
        expand: Optional pre-pass for formats that nest evidence in a list.
    """

    name: str
    detect: Callable[[dict[str, Any]], bool]
    decision_event: bool = True
    actor: tuple[str, ...] = ()
    tool: tuple[str, ...] = ()
    action_type: tuple[str, ...] = ()
    object_id: tuple[str, ...] = ()
    timestamp: tuple[str, ...] = ()
    unix_nanosecond_timestamp: tuple[str, ...] = ()
    verdict: tuple[str, ...] = ()
    policy: tuple[str, ...] = ()
    rule: tuple[str, ...] = ()
    approver: tuple[str, ...] = ()
    approval_binding: tuple[str, ...] = ()
    expand: Callable[[dict[str, Any]], dict[str, Any]] | None = None

    def apply(self, record: dict[str, Any]) -> dict[str, Any]:
        """Map a record onto canonical paths, omitting anything not present."""
        if self.expand is not None:
            record = self.expand(record)
        out = _without_canonical_claims(record)
        self._map_action_fields(record, out)
        self._map_decision_fields(record, out)
        self._map_approver(record, out)
        return out

    def _map_action_fields(self, record: dict[str, Any], out: dict[str, Any]) -> None:
        """Map who acted, with which tool, doing what, to which object."""
        actor = _first_matching(record, is_identifier, *self.actor)
        if actor is not None:
            out["actor_id"] = actor

        tool = _first_matching(record, is_text, *self.tool)
        if tool is not None:
            out["tool_name"] = tool

        # Some formats put a bare string where Ambit puts a block — AGT's
        # `action` is the verb itself. Rebuild rather than merge into it.
        action_type = _first_matching(record, is_text, *self.action_type)
        if action_type is not None:
            existing = out.get("action")
            action = dict(existing) if isinstance(existing, dict) else {}
            if not is_text(action.get("type")):
                action["type"] = action_type
            out["action"] = action

        object_id = _first_matching(record, is_identifier, *self.object_id)
        if object_id is not None:
            existing_obj = out.get("object")
            obj = dict(existing_obj) if isinstance(existing_obj, dict) else {}
            if not is_identifier(obj.get("id")):
                obj["id"] = object_id
            out["object"] = obj

    def _map_decision_fields(self, record: dict[str, Any], out: dict[str, Any]) -> None:
        """Map when the action ran, and its verdict, policy and rule."""
        timestamp, timestamp_conflict = _reconciled_timestamp(
            record, self.timestamp, self.unix_nanosecond_timestamp
        )
        if timestamp_conflict:
            out["_conflicting_timestamp"] = True
        elif timestamp is not None:
            out["ts"] = timestamp

        verdict = _reconciled_verdict(record, self.verdict)
        if verdict is not None:
            out["decision"] = verdict
        elif self.verdict:
            # A matched decision-bearing profile remains a decision event even
            # when its declared verdicts are absent, malformed, or conflicting.
            out["_unsupported_decision"] = True

        policy, policy_confidence = _reconciled_policy(record, self.policy)
        if policy is not None and policy_confidence is not None:
            out["policy_hash"] = policy
            out["_policy_confidence"] = policy_confidence

        rule = (
            None
            if _agt_paths_unusable(record, self.rule)
            else _first_matching(record, is_text, *self.rule)
        )
        if rule is not None:
            out["matched_rule_id"] = rule

    def _map_approver(self, record: dict[str, Any], out: dict[str, Any]) -> None:
        """Map a named approver, bound only through a declared binding path."""
        approver, approver_confidence = _first_matching_confident_claim(
            record, is_identifier, self.approver
        )
        if approver is not None:
            # A name is a real observation and is always recorded. Binding it
            # is a separate claim: fingerprint_bound is True only when the
            # source itself carries evidence tying THIS approval to THIS
            # request, via one of the profile's declared approval_binding
            # paths — never merely because a name was found. No profile below
            # declares one, so on all six shipped formats this is always
            # False. A name in a metadata blob is not proof anyone authorised
            # the specific action being graded.
            bound = _first_matching(record, is_identifier, *self.approval_binding) is not None
            existing_approval = out.get("approval")
            approval = {
                **(existing_approval if isinstance(existing_approval, dict) else {}),
                "approver": approver,
                "fingerprint_bound": bound,
            }
            if approver_confidence is not None:
                approval["confidence"] = approver_confidence
            out["approval"] = approval


def _has_prefix(record: dict[str, Any], prefix: str) -> bool:
    """True if any attribute key starts with the given namespace prefix."""
    for container in (record, record.get("attributes"), record.get("resource")):
        if isinstance(container, dict) and any(
            isinstance(key, str) and key.startswith(prefix) for key in container
        ):
            return True
    return False


#: OpenTelemetry GenAI semantic conventions. The standard; Development status.
#: Carries no authorisation attribute of any kind — enumerated, not assumed.
OTEL_GENAI = Profile(
    name="otel_genai",
    detect=lambda r: _has_prefix(r, "gen_ai."),
    decision_event=True,
    actor=("attributes.gen_ai.agent.id", "attributes.gen_ai.agent.name", "gen_ai.agent.id"),
    tool=("attributes.gen_ai.tool.name", "gen_ai.tool.name", "name"),
    action_type=("attributes.gen_ai.operation.name", "gen_ai.operation.name"),
    object_id=("attributes.gen_ai.tool.call.id", "gen_ai.tool.call.id"),
    timestamp=("start_time", "timestamp"),
    unix_nanosecond_timestamp=("startTimeUnixNano",),
)

#: OpenInference — Arize Phoenix's convention, purpose-built for agent traces.
OPENINFERENCE = Profile(
    name="openinference",
    detect=lambda r: _has_prefix(r, "openinference.") or _has_prefix(r, "llm."),
    decision_event=True,
    actor=("attributes.agent.name", "attributes.session.id", "agent.name"),
    tool=("attributes.tool.name", "tool.name", "name"),
    action_type=("attributes.openinference.span.kind", "openinference.span.kind"),
    object_id=("attributes.tool.call.id", "attributes.retrieval.document.id"),
    timestamp=("start_time", "startTime", "timestamp"),
)

#: Langfuse observation export.
LANGFUSE = Profile(
    name="langfuse",
    detect=lambda r: "traceId" in r or ("type" in r and "startTime" in r),
    decision_event=True,
    actor=("userId", "metadata.actor_id", "metadata.agent", "metadata.agent_id"),
    tool=("name",),
    action_type=("type",),
    object_id=("id", "observationId"),
    timestamp=("startTime", "timestamp"),
    policy=("metadata.policy_hash", "metadata.policy"),
    approver=("metadata.approver", "metadata.approved_by"),
    # No approval_binding: Langfuse's metadata is a free-form bag with no
    # convention for referencing the request an approval covers.
)

#: LangSmith run export.
LANGSMITH = Profile(
    name="langsmith",
    decision_event=True,
    detect=lambda r: "run_type" in r or ("trace_id" in r and "inputs" in r),
    actor=("extra.metadata.actor_id", "extra.metadata.agent"),
    tool=("name",),
    action_type=("run_type",),
    object_id=("id", "run_id"),
    timestamp=("start_time", "start_timestamp"),
    policy=("extra.metadata.policy_hash",),
    approver=("extra.metadata.approver", "extra.metadata.approved_by"),
    # No approval_binding: LangSmith's run metadata has no field referencing
    # the run an approval was meant to cover.
)

#: Weights & Biases Weave call export.
WEAVE = Profile(
    name="weave",
    decision_event=True,
    detect=lambda r: "op_name" in r,
    actor=("attributes.actor_id", "attributes.agent", "wb_user_id"),
    tool=("op_name",),
    action_type=("attributes.kind",),
    object_id=("id", "call_id"),
    timestamp=("started_at", "start_time"),
    policy=("attributes.policy_hash",),
    approver=("attributes.approver",),
    # No approval_binding: Weave's call attributes carry no reference from an
    # approver back to the call it approves.
)

#: Microsoft Agent Governance Toolkit — decision records and Decision BOMs.
#:
#: The only widely-used foreign format that carries a governance verdict. Its
#: schema names ``agent_id`` (the actor) and no approver, principal or reviewer
#: — the subject-not-issuer shape again — but its open ``fields`` list can
#: carry identity- and policy-category entries, which :func:`expand_agt_bom_fields`
#: makes visible. Only *observed* entries are read; AGT's own ``inferred``
#: reconstructions are expanded separately and never lifted as a principal.
MS_AGT = Profile(
    name="microsoft_agt",
    decision_event=True,
    detect=lambda r: (
        ("decision" in r and ("policy_id" in r or "agent_id" in r or "agt" in r))
        or ("decision_id" in r and "agent_id" in r and "outcome" in r)
    ),
    expand=expand_agt_bom_fields,
    actor=("agent_id", "agent.id", "principal_id"),
    tool=("tool", "tool_name", "action.tool", "action_requested"),
    action_type=("action", "action.type", "operation", "action_requested"),
    object_id=("resource", "resource_id", "target"),
    timestamp=("timestamp", "time", "occurred_at"),
    verdict=("decision", "decision.outcome", "outcome", "result"),
    policy=(
        "policy_id",
        "policy.id",
        # Policy version and display name are metadata, not stable identities.
        "_agt_observed.policy.policy_id.value",
    ),
    # `policy_rules_evaluated` is a collection of evaluated rules, not the
    # scalar identity of the rule that matched. It remains raw evidence only.
    approver=(
        # Observed identity-category BOM entries only. An inferred approver is
        # AGT's reconstruction, not a record that anyone approved.
        "_agt_observed.identity.approver.value",
        "_agt_observed.identity.approved_by.value",
        "_agt_observed.identity.reviewer.value",
        "_agt_observed.identity.principal.value",
    ),
    # No approval_binding: none of AGT's identity-category fields references
    # a request fingerprint or action hash back to the decision they name an
    # approver for — the BOM records who, never a link from who to which
    # specific request.
)

#: Ordered by detection specificity: the governance format first, then the
#: convention-tagged span formats, then the platform exports whose markers are
#: the loosest.
PROFILES: tuple[Profile, ...] = (
    MS_AGT,
    OTEL_GENAI,
    OPENINFERENCE,
    LANGSMITH,
    WEAVE,
    LANGFUSE,
)


def match(record: dict[str, Any]) -> Profile | None:
    """Return the first profile that recognises the record, or None."""
    for profile in PROFILES:
        try:
            if profile.detect(record):
                return profile
        except AttributeError, TypeError:  # pragma: no cover - defensive
            continue
    return None
