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

from ambit_grader.sufficiency import dig, interpretable

#: Verdict spellings seen across governance-bearing formats.
_ALLOW = frozenset({"allow", "allowed", "permit", "permitted", "pass", "success", "ok"})
_DENY = frozenset({"deny", "denied", "block", "blocked", "reject", "rejected", "fail"})
_ESCALATE = frozenset({"escalate", "escalated", "review", "pending", "input-required"})


def _verdict_from(value: Any) -> str | None:
    """Map a foreign verdict spelling onto ALLOW / DENY / ESCALATE."""
    if not isinstance(value, str):
        return None
    token = value.strip().lower()
    if token in _ALLOW:
        return "ALLOW"
    if token in _DENY:
        return "DENY"
    if token in _ESCALATE:
        return "ESCALATE"
    return None


def _lookup(record: dict[str, Any], path: str) -> Any:
    """Resolve a dotted path, tolerating flat dotted attribute keys.

    OpenTelemetry and OpenInference put their conventions in a flat attribute
    map whose *keys contain dots* — ``attributes["gen_ai.tool.name"]``, not
    ``attributes.gen_ai.tool.name`` as a nested structure. Walking the path
    naively finds nothing, so each split point is also tried as a literal key.
    """
    value = dig(record, path)
    if interpretable(value):
        return value
    segments = path.split(".")
    for cut in range(1, len(segments)):
        container = dig(record, ".".join(segments[:cut]))
        if isinstance(container, dict):
            candidate = container.get(".".join(segments[cut:]))
            if interpretable(candidate):
                return candidate
    return None


def _first(record: dict[str, Any], *paths: str) -> Any:
    """Return the first interpretable value among the given dotted paths."""
    for path in paths:
        value = _lookup(record, path)
        if interpretable(value):
            return value
    return None


@dataclass(frozen=True, slots=True)
class Profile:
    """One emitter's mapping onto the canonical shape.

    Attributes:
        name: Shape name reported in the grade.
        detect: Returns True if a record was emitted by this format.
        actor: Dotted paths that may hold the acting agent's identity.
        tool: Dotted paths that may hold the invoked tool's name.
        action_type: Dotted paths that may hold the operation kind.
        object_id: Dotted paths that may hold the target's identity.
        timestamp: Dotted paths that may hold the event time.
        verdict: Dotted paths that may hold a governance verdict.
        policy: Dotted paths that may hold a policy identity.
        approver: Dotted paths that may name an approving principal.
    """

    name: str
    detect: Callable[[dict[str, Any]], bool]
    actor: tuple[str, ...] = ()
    tool: tuple[str, ...] = ()
    action_type: tuple[str, ...] = ()
    object_id: tuple[str, ...] = ()
    timestamp: tuple[str, ...] = ()
    verdict: tuple[str, ...] = ()
    policy: tuple[str, ...] = ()
    approver: tuple[str, ...] = ()

    def apply(self, record: dict[str, Any]) -> dict[str, Any]:
        """Map a record onto canonical paths, omitting anything not present."""
        out: dict[str, Any] = dict(record)

        actor = _first(record, *self.actor)
        if actor is not None:
            out["actor_id"] = actor

        tool = _first(record, *self.tool)
        if tool is not None:
            out["tool_name"] = tool

        # Some formats put a bare string where Ambit puts a block — AGT's
        # `action` is the verb itself. Rebuild rather than merge into it.
        action_type = _first(record, *self.action_type)
        if action_type is not None:
            existing = out.get("action")
            action = dict(existing) if isinstance(existing, dict) else {}
            action.setdefault("type", action_type)
            out["action"] = action

        object_id = _first(record, *self.object_id)
        if object_id is not None:
            existing_obj = out.get("object")
            obj = dict(existing_obj) if isinstance(existing_obj, dict) else {}
            obj.setdefault("id", object_id)
            out["object"] = obj

        timestamp = _first(record, *self.timestamp)
        if timestamp is not None:
            out["ts"] = timestamp

        verdict = _verdict_from(_first(record, *self.verdict))
        if verdict is not None:
            out["decision"] = verdict

        policy = _first(record, *self.policy)
        if policy is not None:
            out["policy_hash"] = policy

        approver = _first(record, *self.approver)
        if approver is not None:
            out["approval"] = {
                **(out.get("approval") or {}),
                "approver": approver,
                "fingerprint_bound": True,
            }

        return out


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
    actor=("attributes.gen_ai.agent.id", "attributes.gen_ai.agent.name", "gen_ai.agent.id"),
    tool=("attributes.gen_ai.tool.name", "gen_ai.tool.name", "name"),
    action_type=("attributes.gen_ai.operation.name", "gen_ai.operation.name"),
    object_id=("attributes.gen_ai.tool.call.id", "gen_ai.tool.call.id"),
    timestamp=("startTimeUnixNano", "start_time", "timestamp"),
)

#: OpenInference — Arize Phoenix's convention, purpose-built for agent traces.
OPENINFERENCE = Profile(
    name="openinference",
    detect=lambda r: _has_prefix(r, "openinference.") or _has_prefix(r, "llm."),
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
    actor=("userId", "metadata.actor_id", "metadata.agent", "metadata.agent_id"),
    tool=("name",),
    action_type=("type",),
    object_id=("id", "observationId"),
    timestamp=("startTime", "timestamp"),
    policy=("metadata.policy_hash", "metadata.policy"),
    approver=("metadata.approver", "metadata.approved_by"),
)

#: LangSmith run export.
LANGSMITH = Profile(
    name="langsmith",
    detect=lambda r: "run_type" in r or ("trace_id" in r and "inputs" in r),
    actor=("extra.metadata.actor_id", "extra.metadata.agent", "session_name"),
    tool=("name",),
    action_type=("run_type",),
    object_id=("id", "run_id"),
    timestamp=("start_time", "start_timestamp"),
    policy=("extra.metadata.policy_hash",),
    approver=("extra.metadata.approver", "extra.metadata.approved_by"),
)

#: Weights & Biases Weave call export.
WEAVE = Profile(
    name="weave",
    detect=lambda r: "op_name" in r,
    actor=("attributes.actor_id", "attributes.agent", "wb_user_id"),
    tool=("op_name",),
    action_type=("attributes.kind",),
    object_id=("id", "call_id"),
    timestamp=("started_at", "start_time"),
    policy=("attributes.policy_hash",),
    approver=("attributes.approver",),
)

#: Microsoft Agent Governance Toolkit decision records. The only widely-used
#: format that carries a governance verdict — and it still names no principal:
#: the record says what was decided, not who authorised it.
MS_AGT = Profile(
    name="microsoft_agt",
    detect=lambda r: "decision" in r and ("policy_id" in r or "agent_id" in r or "agt" in r),
    actor=("agent_id", "agent.id", "principal_id"),
    tool=("tool", "tool_name", "action.tool"),
    action_type=("action", "action.type", "operation"),
    object_id=("resource", "resource_id", "target"),
    timestamp=("timestamp", "time", "occurred_at"),
    verdict=("decision", "decision.outcome", "outcome", "result"),
    policy=("policy_id", "policy_version", "policy.id"),
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
        except (AttributeError, TypeError):  # pragma: no cover - defensive
            continue
    return None
