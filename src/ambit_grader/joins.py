# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Corpus-level checks whose evidence spans more than one record.

This module exists because of a specific failure. The first implementation of
this grader scored authority per record, found no approver on any decision
record, and reported that authority was unreconstructible — over a corpus that
carried a complete approval chain in adjacent records. Presence-checking a
record cannot see evidence that lives in the joins between records, and DEMM
names exactly that conflation the container fallacy.

Every check here answers a question about the *set*, not about a record.
"""

from __future__ import annotations

from collections.abc import Callable
from itertools import pairwise
from typing import Any

from ambit_grader.adapters.normalise import is_decision_event
from ambit_grader.models import Property, PropertyVerdict, Sufficiency, UnfillableReason
from ambit_grader.sufficiency import (
    bounded_confidence,
    dig,
    is_genesis,
    is_identifier,
    is_text,
)

#: Verdicts that mean an action actually proceeded, so authority is owed.
_PERMITTED = frozenset({"ALLOW", "ESCALATE"})

# Optional status assertions are closed enums. Absence is allowed because the
# artifact routes already require their own positive identity/binding markers.
_ACCEPTABLE_STATUS = frozenset({"active", "approved", "valid"})
_ACCEPTABLE_SIGNATURE_STATUS = frozenset({"valid", "verified"})
_SUPPORTED_DELEGATION_KINDS = frozenset({"ed25519_token", "hmac_token"})
_ASYMMETRIC_DELEGATION_KINDS = frozenset({"ed25519_token"})

_FLAT_APPROVAL_FIELDS = frozenset(
    {
        "approval_approver",
        "approval_fingerprint",
        "approval_jti",
        "approver",
        "fingerprint_bound",
    }
)


def _is_approval(record: dict[str, Any]) -> bool:
    return record.get("record_type") == "approval"


def _scalar_key(value: Any) -> str | int | None:
    """Return a type-safe join key, excluding booleans and containers."""
    return value if is_identifier(value) else None


def chain_integrity(records: list[dict[str, Any]]) -> PropertyVerdict:
    """Verify the hash chain rather than checking that hash fields exist.

    Integrity of the container is confined to this property on purpose. A
    chain can be cryptographically perfect while describing events that never
    happened, so chain strength must never raise the score of any property
    that concerns what the records *say*.
    """
    linked = [
        r
        for r in records
        if (is_text(r.get("prev_hash")) or is_genesis(r.get("prev_hash")))
        and is_text(r.get("record_hash"))
    ]
    if len(linked) < 2:
        return PropertyVerdict(
            Property.VERIFICATION_STRENGTH,
            Sufficiency.STRUCTURALLY_UNFILLABLE,
            reason=UnfillableReason.EVIDENCE_NEVER_PERSISTED,
            recommendation="append records to a hash chain (prev_hash -> record_hash)",
            detail=f"{len(linked)} linked record(s); a chain needs at least 2",
        )

    breaks = sum(1 for prev, cur in pairwise(linked) if cur["prev_hash"] != prev["record_hash"])
    genesis_ok = is_genesis(linked[0].get("prev_hash"))
    unchained = len(records) - len(linked)

    if breaks:
        return PropertyVerdict(
            Property.VERIFICATION_STRENGTH,
            Sufficiency.PARTIALLY_FILLABLE,
            recommendation="repair the broken prev_hash -> record_hash links",
            detail=f"{breaks} of {len(linked) - 1} links broken",
        )
    if unchained:
        # Records outside the chain belong in the denominator. Dropping them
        # silently would let two linked records certify a corpus of ten.
        return PropertyVerdict(
            Property.VERIFICATION_STRENGTH,
            Sufficiency.PARTIALLY_FILLABLE,
            confidence=len(linked) / len(records),
            recommendation=f"append the {unchained} unchained record(s) to the hash chain",
            detail=f"{len(linked)} of {len(records)} records chained; {unchained} outside it",
        )
    if not genesis_ok:
        return PropertyVerdict(
            Property.VERIFICATION_STRENGTH,
            Sufficiency.PARTIALLY_FILLABLE,
            recommendation="anchor the chain with an all-zero genesis prev_hash",
            detail=(
                f"all {len(linked)} records link cleanly, but the head is unverifiable — "
                "a rotated segment cannot prove nothing precedes it"
            ),
        )
    return PropertyVerdict(
        Property.VERIFICATION_STRENGTH,
        Sufficiency.FULLY_FILLABLE,
        detail=f"all {len(linked)} records link cleanly from genesis",
    )


def _artifact_is_acceptable(record: dict[str, Any]) -> bool:
    """Accept only well-typed validity fields and known positive statuses."""
    if "valid" in record and not isinstance(record["valid"], bool):
        return False
    if record.get("valid") is False:
        return False
    if "revoked" in record and not isinstance(record["revoked"], bool):
        return False
    if record.get("revoked") is True:
        return False
    for field in ("signature_valid", "signature_verified"):
        if field in record and record[field] is not True:
            return False
    for field, accepted in (
        ("status", _ACCEPTABLE_STATUS),
        ("signature_status", _ACCEPTABLE_SIGNATURE_STATUS),
    ):
        if field not in record:
            continue
        status = record[field]
        if not isinstance(status, str) or status.strip().casefold() not in accepted:
            return False
    return True


def _approval_id(record: dict[str, Any]) -> str | int | None:
    """Return an existing approval identifier from a record or envelope."""
    for path in ("approval_jti", "approval.approval_jti", "approval.jti", "approval.id"):
        value = _scalar_key(dig(record, path))
        if value is not None:
            return value
    return None


def _approval_fingerprint(record: dict[str, Any]) -> str | int | None:
    """Return an approval's explicit request binding when present."""
    for path in (
        "approval_fingerprint",
        "approval.fingerprint",
        "approval.request_fingerprint",
    ):
        value = _scalar_key(dig(record, path))
        if value is not None:
            return value
    return None


def _approval_indexes(
    records: list[dict[str, Any]],
) -> tuple[
    dict[str | int, list[dict[str, Any]]],
    dict[str | int, list[dict[str, Any]]],
]:
    """Index every approval by fingerprint and ID without overwriting conflicts."""
    by_fingerprint: dict[str | int, list[dict[str, Any]]] = {}
    by_id: dict[str | int, list[dict[str, Any]]] = {}
    for record in records:
        if not _is_approval(record):
            continue
        fingerprint = _approval_fingerprint(record)
        if fingerprint is not None:
            by_fingerprint.setdefault(fingerprint, []).append(record)
        approval_id = _approval_id(record)
        if approval_id is not None:
            by_id.setdefault(approval_id, []).append(record)
    return by_fingerprint, by_id


def _approval_record_uses(
    records: list[dict[str, Any]],
    approvals_by_fingerprint: dict[str | int, list[dict[str, Any]]],
    approvals_by_id: dict[str | int, list[dict[str, Any]]],
) -> dict[int, int]:
    """Count actions reaching each artifact through their selected join handle."""
    uses: dict[int, int] = {}
    for record in records:
        candidates: set[int] = set()
        approval_id = _approval_id(record)
        if approval_id is not None:
            candidates.update(id(candidate) for candidate in approvals_by_id.get(approval_id, []))
        else:
            for fingerprint in {
                _scalar_key(record.get("request_fingerprint")),
                _approval_fingerprint(record),
            }:
                if fingerprint is not None:
                    candidates.update(
                        id(candidate) for candidate in approvals_by_fingerprint.get(fingerprint, [])
                    )
        for candidate in candidates:
            uses[candidate] = uses.get(candidate, 0) + 1
    return uses


def _approval_record_resolves(record: dict[str, Any]) -> bool:
    """Return True for an affirmatively identified, non-conflicting approval."""
    positively_identified = record.get("valid") is True or _approval_id(record) is not None
    return (
        positively_identified
        and not _local_approval_conflicts(record)
        and not _approval_claim_is_explicitly_invalid(record)
        and _artifact_is_acceptable(record)
        and is_identifier(record.get("approval_approver"))
    )


def _approval_envelope_approver(record: dict[str, Any]) -> str | int | None:
    """Return the named principal from a flat or nested approval envelope."""
    flat = _scalar_key(record.get("approver"))
    if flat is not None:
        return flat
    return _scalar_key(dig(record, "approval.approver"))


def _approval_envelope_resolves(record: dict[str, Any]) -> bool:
    """Return True if the record's own approval envelope is valid and bound."""
    if (
        record.get("fingerprint_bound") is True
        and is_identifier(record.get("approver"))
        and _artifact_is_acceptable(record)
    ):
        return True
    approval = record.get("approval")
    return (
        isinstance(approval, dict)
        and is_identifier(approval.get("approver"))
        and approval.get("fingerprint_bound") is True
        and approval.get("valid") is True
        and _artifact_is_acceptable(approval)
    )


def _approval_values(
    record: dict[str, Any],
    paths: tuple[str, ...],
    predicate: Callable[[Any], bool],
) -> tuple[list[Any], bool]:
    """Return supplied canonical claim values and whether one is malformed."""
    values: list[Any] = []
    malformed = False
    for path in paths:
        container: Any = record
        segments = path.split(".")
        for segment in segments[:-1]:
            if not isinstance(container, dict) or segment not in container:
                break
            container = container[segment]
        else:
            field = segments[-1]
            if isinstance(container, dict) and field in container:
                value = container[field]
                if predicate(value):
                    values.append(value)
                else:
                    malformed = True
    return values, malformed


def _local_approval_conflicts(record: dict[str, Any]) -> bool:
    """Reject disagreement between any supplied approval representations."""
    flat_claim = any(field in record for field in _FLAT_APPROVAL_FIELDS)
    nested_supplied = "approval" in record
    approval = record.get("approval")
    flat_positive = (
        record.get("fingerprint_bound") is True
        and (
            is_identifier(record.get("approver")) or is_identifier(record.get("approval_approver"))
        )
        and _artifact_is_acceptable(record)
    )
    nested_positive = (
        isinstance(approval, dict)
        and is_identifier(approval.get("approver"))
        and approval.get("fingerprint_bound") is True
        and approval.get("valid") is True
        and _artifact_is_acceptable(approval)
    )
    if nested_supplied and not isinstance(approval, dict):
        return flat_positive
    if flat_positive and isinstance(approval, dict) and not _artifact_is_acceptable(approval):
        return True
    if nested_positive and flat_claim and not _artifact_is_acceptable(record):
        return True

    claims = (
        (
            ("approval_approver", "approver", "approval.approver"),
            is_identifier,
        ),
        (
            (
                "approval_jti",
                "approval.approval_jti",
                "approval.jti",
                "approval.id",
            ),
            is_identifier,
        ),
        (
            (
                "approval_fingerprint",
                "approval.fingerprint",
                "approval.request_fingerprint",
            ),
            is_identifier,
        ),
        (
            ("fingerprint_bound", "approval.fingerprint_bound"),
            lambda value: isinstance(value, bool),
        ),
    )
    for paths, predicate in claims:
        values, malformed = _approval_values(record, paths, predicate)
        if len(set(values)) > 1 or (malformed and values):
            return True
    return False


def _approval_claim_is_explicitly_invalid(record: dict[str, Any]) -> bool:
    """Return True when a substantive local approval claim asserts invalidity."""
    approval = record.get("approval")
    flat_substance = (
        is_identifier(record.get("approver"))
        or is_identifier(record.get("approval_approver"))
        or _approval_id(record) is not None
        or _approval_fingerprint(record) is not None
        or record.get("fingerprint_bound") is True
        or _scalar_key(record.get("request_fingerprint")) is not None
    )
    nested_substance = isinstance(approval, dict) and (
        is_identifier(approval.get("approver"))
        or any(
            is_identifier(approval.get(field))
            for field in ("approval_jti", "jti", "id", "fingerprint", "request_fingerprint")
        )
        or approval.get("fingerprint_bound") is True
    )
    return (
        flat_substance
        and any(field in record for field in _FLAT_APPROVAL_FIELDS)
        and not _artifact_is_acceptable(record)
    ) or (
        isinstance(approval, dict)
        and (nested_substance or flat_substance)
        and not _artifact_is_acceptable(approval)
    )


def _approver_named(record: dict[str, Any]) -> bool:
    """Return True if the record's own evidence names an approver anywhere."""
    return is_identifier(record.get("approver")) or is_identifier(dig(record, "approval.approver"))


def _authority_gap_recommendation(bare_unaccounted: int, named_unbound: int, noun: str) -> str:
    """Recommend the fix for permitted actions with no resolved principal.

    Two different gaps need two different remedies, and conflating them sends
    an operator to do the wrong thing. Silence needs a first authority
    artifact — a policy identity, delegation or approval, any of which beats
    nothing. A named-but-unbound approver already has the hard part done;
    recommending "add an approver" there would ask for evidence that is
    already sitting in the record. What is missing is the join, so the fix is
    to bind the name that exists to the request it covers, never to collect
    another one.
    """
    if named_unbound and bare_unaccounted:
        return (
            f"bind the {named_unbound} named-but-unbound approval(s) to the request they "
            f"authorise, and give the {bare_unaccounted} {noun} naming no approver at all a "
            "first authority basis — a policy identity, delegation or approval"
        )
    if named_unbound:
        return (
            f"bind the {named_unbound} named approval(s) to the request they authorise — a "
            "request fingerprint or action hash the approval itself references; the "
            "approver is already named, so naming another one changes nothing"
        )
    return (
        f"give the {bare_unaccounted} {noun} an authority basis — a policy identity at "
        "minimum, a delegation or approval where consequential"
    )


def _delegation_is_live(record: dict[str, Any]) -> bool:
    """Return True for a valid delegation of a supported credential kind."""
    delegation = record.get("delegation")
    if not isinstance(delegation, dict):
        return False
    kind = delegation.get("kind")
    identified = is_identifier(delegation.get("id")) or is_identifier(delegation.get("jti"))
    return (
        identified
        and is_text(kind)
        and kind.strip().casefold() in _SUPPORTED_DELEGATION_KINDS
        and delegation.get("valid") is True
        and _artifact_is_acceptable(delegation)
    )


def _delegation_issuer_evidenced(record: dict[str, Any]) -> bool:
    """Return True if the evidence names *who granted* the delegation.

    This is the distinction that keeps the grader honest about Ambit's own
    primary artifact. A delegation envelope names its ``subject`` — the agent
    the authority was granted *to* — and its scope, duration and revocation
    state. None of that answers "who authorised this"; the issuer is the
    principal, and an envelope without one leaves the principal unnamed.

    An asymmetric signature binds a trust root that identifies the issuer. A
    symmetric one cannot: for HMAC the verify key is the forge key, so the
    holder of the verifying key could have minted the token itself.

    Treating envelope presence as principal identification would be the
    container fallacy one level up, committed in the vendor's own favour —
    which is the single bias an independence argument cannot survive.
    """
    if is_identifier(dig(record, "delegation.issuer")) or is_identifier(
        dig(record, "delegation.granted_by")
    ):
        return True
    kind = dig(record, "delegation.kind")
    root = dig(record, "delegation.trust_root_id")
    return (
        is_identifier(root)
        and is_text(kind)
        and kind.strip().casefold() in _ASYMMETRIC_DELEGATION_KINDS
    )


def _authority_resolution(
    record: dict[str, Any],
    approvals_by_fingerprint: dict[str | int, list[dict[str, Any]]],
    approvals_by_id: dict[str | int, list[dict[str, Any]]],
    fingerprint_uses: dict[str | int, int],
    approval_id_uses: dict[str | int, int],
    approval_record_uses: dict[int, int],
) -> tuple[bool, bool]:
    """Return ``(resolved, ambiguous)`` for one permitted action."""
    if _local_approval_conflicts(record) or _approval_claim_is_explicitly_invalid(record):
        return False, True
    approval_id = _approval_id(record)
    fingerprint = _scalar_key(record.get("request_fingerprint"))
    envelope_fingerprint = _approval_fingerprint(record)
    if (
        fingerprint is not None
        and envelope_fingerprint is not None
        and envelope_fingerprint != fingerprint
    ):
        return False, True
    if envelope_fingerprint is not None and fingerprint_uses.get(envelope_fingerprint, 0) != 1:
        return False, True
    if _approval_envelope_resolves(record):
        if approval_id is not None:
            if approval_id_uses.get(approval_id, 0) != 1:
                return False, True
            external_candidates = approvals_by_id.get(approval_id, [])
        else:
            binding_fingerprint = fingerprint if fingerprint is not None else envelope_fingerprint
            if (
                binding_fingerprint is not None
                and fingerprint_uses.get(binding_fingerprint, 0) != 1
            ):
                return False, True
            external_candidates = (
                approvals_by_fingerprint.get(binding_fingerprint, [])
                if binding_fingerprint is not None
                else []
            )
        if len(external_candidates) > 1:
            return False, True
        if external_candidates:
            candidate = external_candidates[0]
            if approval_record_uses.get(id(candidate), 0) != 1:
                return False, True
            candidate_fingerprint = _approval_fingerprint(candidate)
            expected_fingerprint = fingerprint if fingerprint is not None else envelope_fingerprint
            if (
                not _approval_record_resolves(candidate)
                or candidate.get("approval_approver") != _approval_envelope_approver(record)
                or (
                    expected_fingerprint is not None
                    and candidate_fingerprint is not None
                    and candidate_fingerprint != expected_fingerprint
                )
                or (
                    candidate_fingerprint is not None
                    and len(approvals_by_fingerprint.get(candidate_fingerprint, [])) != 1
                )
            ):
                return False, True
        return True, False
    if approval_id is not None:
        candidates = approvals_by_id.get(approval_id, [])
        if len(candidates) == 1:
            candidate_fingerprint = _approval_fingerprint(candidates[0])
            if (
                candidate_fingerprint is not None
                and len(approvals_by_fingerprint.get(candidate_fingerprint, [])) != 1
            ):
                return False, True
            if (
                fingerprint is not None
                and candidate_fingerprint is not None
                and candidate_fingerprint != fingerprint
            ):
                return False, True
        use_count = approval_id_uses.get(approval_id, 0)
    else:
        candidates = (
            approvals_by_fingerprint.get(fingerprint, []) if fingerprint is not None else []
        )
        use_count = fingerprint_uses.get(fingerprint, 0) if fingerprint is not None else 0
    if candidates and any(
        approval_record_uses.get(id(candidate), 0) != 1
        or _local_approval_conflicts(candidate)
        or _approval_claim_is_explicitly_invalid(candidate)
        or not _artifact_is_acceptable(candidate)
        for candidate in candidates
    ):
        return False, True
    if candidates and (len(candidates) != 1 or use_count != 1):
        return False, True
    if len(candidates) == 1 and _approval_record_resolves(candidates[0]):
        return True, False
    resolved_by_delegation = _delegation_is_live(record) and _delegation_issuer_evidenced(record)
    return resolved_by_delegation, False


def _attestation_index(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Index policy attestations by the policy_hash they attest.

    An attestation binds a policy version to the principal who approved it. It
    is what lets a policy-permitted action name a principal: the authority is
    inherited from the governed policy rather than asserted per call.
    """
    index: dict[str, dict[str, Any]] = {}
    for record in records:
        key = record.get("policy_hash")
        if (
            is_text(key)
            and record.get("record_type") == "policy_attestation"
            and is_identifier(record.get("approver"))
            # Asymmetric only. The trust root is the existing positive signed
            # marker; any explicit invalidity still overrides it.
            and is_identifier(record.get("trust_root_id"))
            and _artifact_is_acceptable(record)
        ):
            index[key] = record
    return index


def _policy_attestation_confidence(
    record: dict[str, Any], attestations: dict[str, dict[str, Any]]
) -> float | None:
    """Return confidence in an attested policy identity, if it can join."""
    confidence = bounded_confidence(record.get("_policy_confidence", 1.0))
    if confidence is None:
        return None
    for path in ("policy_hash", "evidence.hashes.policy_hash"):
        key = dig(record, path)
        if is_text(key) and key in attestations:
            return confidence
    return None


def _has_policy_identity(record: dict[str, Any]) -> bool:
    return (
        is_text(dig(record, "policy_hash"))
        or is_text(dig(record, "evidence.hashes.policy_hash"))
        or is_text(dig(record, "matched_rule_id"))
    )


def principal_authority(records: list[dict[str, Any]]) -> PropertyVerdict:
    """Grade whether every authority-requiring action names a principal.

    Denials are excluded from the denominator. A denied action executed
    nothing, so it owes no account of who authorised it, and counting denials
    would let a corpus flatter itself by refusing more often.

    An escalation resolved by a linked approval names a human principal. An
    allow under a named policy proves only *permission* — that the action was
    within a rule — not that any principal took responsibility for it. That
    gap between can and should is the property's whole point, so a corpus of
    policy-permitted allows is capped at partial no matter how clean it is.

    A permitted action that names an approver but cannot bind that name to
    this specific request is graded identically to one with no approver at
    all — DEMM's partial category means recoverable evidence plus a gap, and
    an unbound name is not recoverable evidence, so it earns no extra credit.
    The two are still reported separately in ``detail`` and
    ``recommendation``, because the remedy differs: bind the name that is
    already there, rather than go looking for a first one.
    """
    approvals_by_fingerprint, approvals_by_id = _approval_indexes(records)
    attestations = _attestation_index(records)
    authority_events = [record for record in records if is_decision_event(record)]
    permitted = [record for record in authority_events if record.get("decision") in _PERMITTED]
    denied = sum(record.get("decision") == "DENY" for record in authority_events)
    no_verdict = [
        record
        for record in authority_events
        if record.get("decision") is None and record.get("_unsupported_decision") is not True
    ]
    unsupported = len(authority_events) - len(permitted) - denied - len(no_verdict)
    accountable = [*permitted, *no_verdict]

    if not accountable:
        if unsupported:
            return PropertyVerdict(
                Property.PRINCIPAL_AUTHORITY,
                Sufficiency.CONFLICTING,
                recommendation="correct or explicitly classify every unsupported decision verdict",
                detail=(
                    f"no permitted actions; {unsupported} unsupported decision verdict(s) "
                    f"remain in the denominator ({denied} denial(s) excluded)"
                ),
            )
        return PropertyVerdict(
            Property.PRINCIPAL_AUTHORITY,
            Sufficiency.STRUCTURALLY_UNFILLABLE,
            reason=UnfillableReason.EVIDENCE_NEVER_PERSISTED,
            recommendation="record at least one permitted action to attribute",
            detail=f"no permitted actions ({denied} denial(s) excluded)",
        )

    fingerprint_uses: dict[str | int, int] = {}
    approval_id_uses: dict[str | int, int] = {}
    for record in permitted:
        fingerprints = {
            key
            for value in (
                record.get("request_fingerprint"),
                _approval_fingerprint(record),
            )
            if (key := _scalar_key(value)) is not None
        }
        for key in fingerprints:
            fingerprint_uses[key] = fingerprint_uses.get(key, 0) + 1
        approval_id = _approval_id(record)
        if approval_id is not None:
            approval_id_uses[approval_id] = approval_id_uses.get(approval_id, 0) + 1
    approval_record_uses = _approval_record_uses(
        permitted, approvals_by_fingerprint, approvals_by_id
    )

    attributed = delegated = unresolved = policy_only = unaccounted = named_unbound = 0
    ambiguous = confidence_limited = 0
    attribution_credit = 0.0
    for record in accountable:
        attestation_confidence = _policy_attestation_confidence(record, attestations)
        if record.get("decision") is None:
            unaccounted += 1
            if _approver_named(record):
                named_unbound += 1
            continue
        resolved, approval_ambiguous = _authority_resolution(
            record,
            approvals_by_fingerprint,
            approvals_by_id,
            fingerprint_uses,
            approval_id_uses,
            approval_record_uses,
        )
        if approval_ambiguous:
            ambiguous += 1
        elif resolved:
            attributed += 1
            attribution_credit += 1.0
        elif _delegation_is_live(record):
            # A live delegation proves a specific signed grant — strictly more
            # than policy permission — but names the delegate, not the grantor.
            delegated += 1
        elif record.get("decision") == "ESCALATE":
            unresolved += 1
        elif attestation_confidence is not None:
            # The attestation names the policy's principal, while the BOM
            # confidence limits how strongly this action can inherit it. Zero
            # confidence records the matched attestation without establishing
            # attribution or earning credit.
            if attestation_confidence < 1.0:
                confidence_limited += 1
            if attestation_confidence > 0.0:
                attributed += 1
                attribution_credit += attestation_confidence
        elif _has_policy_identity(record):
            policy_only += 1
        else:
            # An action with neither a principal nor a policy identity. Counting
            # it nowhere would let a corpus report full attribution while
            # carrying bare allows or eligible no-verdict action traces.
            unaccounted += 1
            if _approver_named(record):
                # A name is present but did not resolve. Track it separately so
                # the report distinguishes "nobody named" from "named, not bound".
                named_unbound += 1
    bare_unaccounted = unaccounted - named_unbound

    # Eligible no-verdict action traces remain in the same authority
    # denominator as permitted decisions. Unsupported verdicts also remain and
    # never earn attribution merely because normalization could not classify
    # them.
    authority_denominator = len(accountable) + unsupported
    attributed_share = (attribution_credit + 0.5 * delegated) / authority_denominator
    scope = f"{len(permitted)} permitted action(s)"
    if no_verdict:
        scope += f" plus {len(no_verdict)} eligible action(s) without a verdict"

    detail = (
        f"{scope}: {attributed} attributable to a named principal, "
        f"{confidence_limited} with a confidence-limited matching policy attestation, "
        f"{delegated} under a delegation whose issuer is not evidenced, "
        f"{policy_only} policy-permitted only, {unresolved} escalated without a resolving "
        f"approval, {ambiguous} with an ambiguous approval join, "
        f"{named_unbound} naming an approver not bound to this action, "
        f"{bare_unaccounted} with no authority evidence at all, "
        f"{unsupported} unsupported decision verdict(s) "
        f"({denied} denial(s) excluded)"
    )

    if ambiguous or unsupported:
        problems = []
        if ambiguous:
            problems.append(f"disambiguate {ambiguous} approval join(s)")
        if unsupported:
            problems.append(f"correct {unsupported} unsupported decision verdict(s)")
        return PropertyVerdict(
            Property.PRINCIPAL_AUTHORITY,
            Sufficiency.CONFLICTING,
            confidence=attributed_share,
            recommendation=" and ".join(problems),
            detail=detail,
        )
    if unresolved:
        return PropertyVerdict(
            Property.PRINCIPAL_AUTHORITY,
            Sufficiency.STRUCTURALLY_UNFILLABLE,
            # Not "never persisted": an escalation implies an approval step,
            # and the approval plausibly exists in a ticketing or IdP system
            # this evidence set does not span. The distinction changes the
            # remedy — go and join the other system, rather than start
            # emitting something nobody emits.
            reason=UnfillableReason.CROSS_STACK_BOUNDARY,
            recommendation=(
                f"link the {unresolved} unresolved escalation(s) to an approval record "
                "carrying a named approver"
            ),
            detail=detail,
        )
    if unaccounted == len(accountable):
        # Nothing recoverable at all. `partially_fillable` means recoverable
        # evidence plus a gap description; where every permitted action lacks
        # a principal, a policy and a delegation alike, there is no evidence
        # to partially recover and reporting one would be generous. An
        # unbound name is no more recoverable than no name — see
        # _authority_gap_recommendation for why the remedy still differs.
        return PropertyVerdict(
            Property.PRINCIPAL_AUTHORITY,
            Sufficiency.STRUCTURALLY_UNFILLABLE,
            reason=UnfillableReason.EVIDENCE_NEVER_PERSISTED,
            recommendation=_authority_gap_recommendation(
                bare_unaccounted, named_unbound, "permitted action(s)"
            ),
            detail=detail,
        )
    if unaccounted:
        return PropertyVerdict(
            Property.PRINCIPAL_AUTHORITY,
            Sufficiency.PARTIALLY_FILLABLE,
            confidence=attributed_share,
            recommendation=_authority_gap_recommendation(
                bare_unaccounted, named_unbound, "bare allow(s)"
            ),
            detail=detail,
        )
    if delegated:
        # Capped deliberately. A corpus of nothing but delegations would
        # otherwise report full attribution with no principal anywhere in the
        # evidence — the grader flattering its own vendor's artifact.
        return PropertyVerdict(
            Property.PRINCIPAL_AUTHORITY,
            Sufficiency.PARTIALLY_FILLABLE,
            confidence=attributed_share,
            recommendation=(
                f"evidence the issuer of the {delegated} delegation(s) — record who granted "
                "the delegation, or sign it asymmetrically so a trust root identifies them; "
                "an HMAC token cannot, because its verify key is its forge key"
            ),
            detail=detail,
        )
    if confidence_limited:
        recommendation = (
            f"raise confidence for the {confidence_limited} attested policy identity "
            "claim(s) to 1.0 before treating their actions as fully attributable"
        )
        if policy_only:
            recommendation += (
                f"; attest the policy that permitted the {policy_only} other automatic allow(s)"
            )
        return PropertyVerdict(
            Property.PRINCIPAL_AUTHORITY,
            Sufficiency.PARTIALLY_FILLABLE,
            confidence=attributed_share,
            recommendation=recommendation,
            detail=detail,
        )
    if attributed and not policy_only:
        return PropertyVerdict(
            Property.PRINCIPAL_AUTHORITY, Sufficiency.FULLY_FILLABLE, detail=detail
        )
    if attributed or policy_only:
        return PropertyVerdict(
            Property.PRINCIPAL_AUTHORITY,
            Sufficiency.PARTIALLY_FILLABLE,
            confidence=attributed_share,
            recommendation=(
                f"attest the policy that permitted the {policy_only} automatic allow(s) — "
                "bind policy_hash to a signed record naming who approved that policy"
            ),
            detail=detail,
        )
    return PropertyVerdict(
        Property.PRINCIPAL_AUTHORITY,
        Sufficiency.STRUCTURALLY_UNFILLABLE,
        reason=UnfillableReason.EVIDENCE_NEVER_PERSISTED,
        recommendation="emit a policy identity or an approval for every permitted action",
        detail=detail,
    )


#: Properties resolved across the corpus rather than per record.
CORPUS_CHECKS = {
    Property.PRINCIPAL_AUTHORITY: principal_authority,
    Property.VERIFICATION_STRENGTH: chain_integrity,
}
