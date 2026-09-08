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
from datetime import UTC, datetime, timedelta
from typing import Any

from ambit_grader.sufficiency import (
    bounded_confidence,
    dig,
    interpretable,
    is_identifier,
    is_substantive,
    is_text,
    is_unix_nanoseconds,
    timestamp_instant,
)

#: Verdict spellings seen across governance-bearing formats.
_ALLOW = frozenset({"allow", "allowed", "permit", "permitted", "pass", "success", "ok"})
_DENY = frozenset({"deny", "denied", "block", "blocked", "reject", "rejected", "fail"})
_ESCALATE = frozenset({"escalate", "escalated", "review", "pending", "input-required"})

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


def _first_matching(record: dict[str, Any], predicate: Callable[[Any], bool], *paths: str) -> Any:
    """Return the first value with the semantic type expected by its field."""
    for path in paths:
        value = _lookup(record, path)
        if predicate(value):
            return value
    return None


def _declared_values(record: dict[str, Any], path: str) -> list[Any]:
    """Return every supplied nested or flat-dotted representation of a path."""
    segments = path.split(".")
    values: list[Any] = []
    for cut in range(len(segments)):
        container: Any = record
        for segment in segments[:cut]:
            if not isinstance(container, dict) or segment not in container:
                break
            container = container[segment]
        else:
            key = ".".join(segments[cut:])
            if isinstance(container, dict) and key in container:
                values.append(container[key])
    return values


def _has_substantive_malformed_parent(record: dict[str, Any], path: str) -> bool:
    """Return whether a nested alias stops at a non-empty non-mapping parent."""
    current: Any = record
    for segment in path.split(".")[:-1]:
        if not isinstance(current, dict) or segment not in current:
            return False
        current = current[segment]
        if not isinstance(current, dict):
            return is_substantive(current)
    return False


def _reconciled_verdict(record: dict[str, Any], paths: tuple[str, ...]) -> str | None:
    """Return one unambiguous canonical verdict across every declared alias."""
    values_by_path = {path: _declared_values(record, path) for path in paths}
    canonical_paths = {
        path
        for path, values in values_by_path.items()
        if any(_verdict_from(value) is not None for value in values)
    }
    verdicts: set[str] = set()
    malformed = False
    for path, values in values_by_path.items():
        for value in values:
            if not is_substantive(value):
                continue
            verdict = _verdict_from(value)
            if verdict is not None:
                verdicts.add(verdict)
                continue
            structural_parent = isinstance(value, dict) and any(
                candidate in canonical_paths and candidate.startswith(f"{path}.")
                for candidate in paths
            )
            if not structural_parent:
                malformed = True
    if malformed or len(verdicts) != 1:
        return None
    return next(iter(verdicts))


def _rfc3339_from_unix_nanoseconds(value: str | int) -> str:
    """Canonicalise a validated Unix-nanosecond instant without losing precision."""
    seconds, nanoseconds = divmod(int(value), 1_000_000_000)
    instant = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
    return (
        f"{instant.year:04d}-{instant.month:02d}-{instant.day:02d}"
        f"T{instant.hour:02d}:{instant.minute:02d}:{instant.second:02d}"
        f".{nanoseconds:09d}Z"
    )


def _reconciled_timestamp(
    record: dict[str, Any],
    timestamp_paths: tuple[str, ...],
    unix_nanosecond_paths: tuple[str, ...],
) -> tuple[str | None, bool]:
    """Return one timestamp spelling and whether declared aliases conflict."""
    instants: list[tuple[tuple[int, int, int, int, int, int, int], str]] = []
    malformed = False
    for path in timestamp_paths:
        for value in _declared_values(record, path):
            if not is_substantive(value):
                continue
            instant = timestamp_instant(value)
            if instant is None:
                malformed = True
            else:
                instants.append((instant, value))
    for path in unix_nanosecond_paths:
        for value in _declared_values(record, path):
            if not is_substantive(value):
                continue
            if not is_unix_nanoseconds(value):
                malformed = True
                continue
            canonical = _rfc3339_from_unix_nanoseconds(value)
            instant = timestamp_instant(canonical)
            if instant is not None:
                instants.append((instant, canonical))

    distinct = {instant for instant, _value in instants}
    conflicting = len(distinct) > 1 or (malformed and bool(instants))
    if conflicting or not instants:
        return None, conflicting
    return instants[0][1], False


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
    * ``confidence`` — validated in ``[0, 1]`` and combined by taking the
      least confidence across equal duplicate claims before canonical lifting.
    """
    out = dict(record)
    out.pop("_agt_observed", None)
    out.pop("_agt_inferred", None)
    out.pop("_agt_conflicts", None)
    out.pop("_agt_invalid_confidence", None)
    fields = record.get("fields")
    if not isinstance(fields, list):
        return out

    observed_claims: dict[tuple[str, str], list[dict[str, Any]]] = {}
    inferred_claims: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for entry in fields:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        category = entry.get("category")
        if not isinstance(name, str) or not isinstance(category, str):
            continue
        inference = entry.get("inferred")
        if inference is True:
            claims = inferred_claims
        elif inference is False:
            claims = observed_claims
        else:
            continue
        claims.setdefault((category, name), []).append(entry)

    observed: dict[str, dict[str, Any]] = {}
    inferred: dict[str, dict[str, Any]] = {}
    conflicts: set[str] = set()
    invalid_confidence: set[str] = set()
    missing = object()
    for claims, bucket in (
        (observed_claims, observed),
        (inferred_claims, inferred),
    ):
        for (category, name), entries in claims.items():
            first = entries[0].get("value", missing)
            equivalent = all(
                type(value) is type(first) and value == first
                for entry in entries[1:]
                for value in (entry.get("value", missing),)
            )
            confidences = [bounded_confidence(entry.get("confidence")) for entry in entries]
            confidence_valid = all(value is not None for value in confidences)
            if equivalent and confidence_valid:
                claim = dict(entries[0])
                claim["confidence"] = min(value for value in confidences if value is not None)
                bucket.setdefault(category, {})[name] = claim
            else:
                # Preserve every unusable representation while making scalar
                # adapter paths fail closed.
                bucket.setdefault(category, {})[name] = entries if len(entries) > 1 else entries[0]
                if claims is observed_claims:
                    key = f"{category}.{name}"
                    if not equivalent:
                        conflicts.add(key)
                    if not confidence_valid:
                        invalid_confidence.add(key)

    if observed:
        out["_agt_observed"] = observed
    if inferred:
        out["_agt_inferred"] = inferred
    if conflicts:
        out["_agt_conflicts"] = sorted(conflicts)
    if invalid_confidence:
        out["_agt_invalid_confidence"] = sorted(invalid_confidence)

    # AGT's nearest authority artifact is a lineage-category `delegation_chain`
    # of agent DIDs. Every entry is a *subject* — which agent delegated to
    # which — and none is an issuer, the same shape Ambit's own delegation
    # envelope had before it recorded a trust root. Two teams arrived at
    # delegation-as-authority-artifact independently and both recorded the
    # delegate rather than the grantor.
    #
    # Mapped to a delegation envelope so the ordinary rule applies unchanged.
    # Without an affirmative validity assertion this remains descriptive
    # lineage, not evidence of a live grant.
    #
    # Only when AGT marks it observed. As shipped, AGT sets inferred=True on
    # this field, so on real AGT output this never fires — its own flag says
    # the chain was reconstructed from audit entries rather than witnessed,
    # and a reconstruction is not evidence that anyone delegated.
    #
    # No `valid` key: the chain says who delegated to whom and nothing about
    # whether that delegation holds. Asserting validity here would be the
    # adapter inventing a fact, so the envelope stays silent and inert.
    chain_field = observed.get("lineage", {}).get("delegation_chain")
    if isinstance(chain_field, dict) and "lineage.delegation_chain" not in invalid_confidence:
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


def _agt_paths_unusable(record: dict[str, Any], paths: tuple[str, ...]) -> bool:
    """Return whether an observed AGT path is contradictory or untrusted."""
    declared = {
        ".".join(path.split(".")[1:3]) for path in paths if path.startswith("_agt_observed.")
    }
    for marker in ("_agt_conflicts", "_agt_invalid_confidence"):
        claims = record.get(marker)
        if isinstance(claims, list) and any(claim in declared for claim in claims):
            return True
    return False


def _first_matching_confident_claim(
    record: dict[str, Any],
    predicate: Callable[[Any], bool],
    paths: tuple[str, ...],
) -> tuple[Any, float | None]:
    """Return the first claim whose AGT confidence is positive and valid."""
    if _agt_paths_unusable(record, paths):
        return None, None
    for path in paths:
        value = _lookup(record, path)
        if not predicate(value):
            continue
        if not path.startswith("_agt_observed."):
            return value, None
        entry = _lookup(record, path.rsplit(".", 1)[0])
        confidence = (
            bounded_confidence(entry.get("confidence")) if isinstance(entry, dict) else None
        )
        if confidence is not None and confidence > 0.0:
            return value, confidence
    return None, None


def _reconciled_policy(
    record: dict[str, Any], paths: tuple[str, ...]
) -> tuple[str | None, float | None]:
    """Return one stable policy identity and its least supporting confidence."""
    if _agt_paths_unusable(record, paths):
        return None, None
    claims: list[tuple[str, float]] = []
    malformed = False
    for path in paths:
        if _has_substantive_malformed_parent(record, path):
            malformed = True
        for value in _declared_values(record, path):
            if not is_substantive(value):
                continue
            if not is_text(value):
                malformed = True
                continue
            confidence = 1.0
            if path.startswith("_agt_observed."):
                entry = _lookup(record, path.rsplit(".", 1)[0])
                confidence_value = (
                    bounded_confidence(entry.get("confidence")) if isinstance(entry, dict) else None
                )
                if confidence_value is None:
                    malformed = True
                    continue
                confidence = confidence_value
            claims.append((value, confidence))
    identities = {value for value, _confidence in claims}
    if malformed or len(identities) != 1:
        return None, None
    return next(iter(identities)), min(confidence for _value, confidence in claims)


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
        except (AttributeError, TypeError):  # pragma: no cover - defensive
            continue
    return None
