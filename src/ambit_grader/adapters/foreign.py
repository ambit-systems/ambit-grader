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


def expand_agt_bom_fields(record: dict[str, Any]) -> dict[str, Any]:
    """Flatten a Microsoft AGT Decision BOM's ``fields`` list into lookupable paths.

    AGT does not put identity or policy content in named schema slots. It
    carries an open list of ``BOMField(name, category, value, source,
    confidence, inferred)``, categorised as identity / trust / policy / action
    / context / outcome / lineage. A flat-path lookup cannot see inside that
    list, so an AGT record could name a principal and the grader would report
    the property unfillable — the grader wrong in its own favour, pointed at a
    third-party format's evidence instead of Ambit's.

    Two of AGT's own per-field flags are load-bearing and are preserved:

    * ``inferred`` — "reconstructed rather than directly observed". AGT is
      telling us it worked the value out rather than witnessed it. A
      reconstruction is not evidence that someone approved, so inferred
      fields are expanded under a separate key and never lifted as a
      principal. Crediting them would be accepting a third-party format's
      inference as Ambit's observation.
    * ``confidence`` — carried through, because §3.5's partial weight is a
      confidence and AGT has already computed one.
    """
    fields = record.get("fields")
    if not isinstance(fields, list):
        return record

    observed: dict[str, dict[str, Any]] = {}
    inferred: dict[str, dict[str, Any]] = {}
    for entry in fields:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        category = entry.get("category")
        if not isinstance(name, str) or not isinstance(category, str):
            continue
        bucket = inferred if entry.get("inferred") is True else observed
        bucket.setdefault(category, {})[name] = entry

    out = dict(record)
    if observed:
        out["_agt_observed"] = observed
    if inferred:
        out["_agt_inferred"] = inferred

    # AGT's nearest authority artifact is a lineage-category `delegation_chain`
    # of agent DIDs. Every entry is a *subject* — which agent delegated to
    # which — and none is an issuer, the same shape Ambit's own delegation
    # envelope had before it recorded a trust root. Two teams arrived at
    # delegation-as-authority-artifact independently and both recorded the
    # delegate rather than the grantor.
    #
    # Mapped to a delegation envelope so the ordinary rule applies unchanged:
    # a live delegation whose issuer is not evidenced caps at partial. No
    # special-casing, and the same verdict Ambit's own HMAC delegations get.
    #
    # Only when AGT marks it observed. As shipped, AGT sets inferred=True on
    # this field, so on real AGT output this never fires — its own flag says
    # the chain was reconstructed from audit entries rather than witnessed,
    # and a reconstruction is not evidence that anyone delegated.
    #
    # No `valid` key: the chain says who delegated to whom and nothing about
    # whether that delegation holds. Asserting validity here would be the
    # adapter inventing a fact, so the envelope stays silent and
    # `_delegation_is_live`'s `is not False` reads the silence as it should.
    chain_field = observed.get("lineage", {}).get("delegation_chain")
    if isinstance(chain_field, dict):
        chain = chain_field.get("value")
        if isinstance(chain, list) and chain:
            existing_delegation = out.get("delegation")
            out["delegation"] = {
                **(existing_delegation if isinstance(existing_delegation, dict) else {}),
                "id": str(chain[0]),
                "jti": str(chain[0]),
                "kind": "agt_delegation_chain",
                "subject": str(chain[-1]),
            }
    return out


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
    actor: tuple[str, ...] = ()
    tool: tuple[str, ...] = ()
    action_type: tuple[str, ...] = ()
    object_id: tuple[str, ...] = ()
    timestamp: tuple[str, ...] = ()
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

        rule = _first(record, *self.rule)
        if rule is not None:
            out["matched_rule_id"] = rule

        approver = _first(record, *self.approver)
        if approver is not None:
            # A name is a real observation and is always recorded. Binding it
            # is a separate claim: fingerprint_bound is True only when the
            # source itself carries evidence tying THIS approval to THIS
            # request, via one of the profile's declared approval_binding
            # paths — never merely because a name was found. No profile below
            # declares one, so on all six shipped formats this is always
            # False. A name in a metadata blob is not proof anyone authorised
            # the specific action being graded.
            bound = _first(record, *self.approval_binding) is not None
            existing_approval = out.get("approval")
            out["approval"] = {
                **(existing_approval if isinstance(existing_approval, dict) else {}),
                "approver": approver,
                "fingerprint_bound": bound,
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
    # No approval_binding: Langfuse's metadata is a free-form bag with no
    # convention for referencing the request an approval covers.
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
    # No approval_binding: LangSmith's run metadata has no field referencing
    # the run an approval was meant to cover.
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
        "policy_version",
        "policy.id",
        # Observed policy-category BOM entries, by the names AGT uses.
        "_agt_observed.policy.policy_id.value",
        "_agt_observed.policy.policy_version.value",
        "_agt_observed.policy.policy_name.value",
    ),
    # `policy_rules_evaluated` is one of AGT's five REQUIRED fields, emitted
    # un-inferred. It is a *list of rule names* — the rule half of policy
    # basis, not a policy identity — and is the strongest property any of the
    # six foreign formats fills.
    rule=("_agt_observed.policy.policy_rules_evaluated.value",),
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
        except (AttributeError, TypeError):  # pragma: no cover - defensive
            continue
    return None
