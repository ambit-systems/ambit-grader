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

from itertools import pairwise
from typing import Any

from ambit_grader.models import Property, PropertyVerdict, Sufficiency, UnfillableReason
from ambit_grader.sufficiency import dig, interpretable, is_genesis

#: Verdicts that mean an action actually proceeded, so authority is owed.
_PERMITTED = frozenset({"ALLOW", "ESCALATE"})


def _is_approval(record: dict[str, Any]) -> bool:
    return record.get("record_type") == "approval"


def _is_decision(record: dict[str, Any]) -> bool:
    return record.get("record_type") in (None, "decision") and bool(record.get("decision"))


def chain_integrity(records: list[dict[str, Any]]) -> PropertyVerdict:
    """Verify the hash chain rather than checking that hash fields exist.

    Integrity of the container is confined to this property on purpose. A
    chain can be cryptographically perfect while describing events that never
    happened, so chain strength must never raise the score of any property
    that concerns what the records *say*.
    """
    linked = [r for r in records if r.get("prev_hash") is not None and r.get("record_hash")]
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


def _approval_index(records: list[dict[str, Any]]) -> dict[Any, dict[str, Any]]:
    """Index approval records by the request fingerprint they authorise."""
    return {
        r.get("approval_fingerprint"): r
        for r in records
        if _is_approval(r) and interpretable(r.get("approval_fingerprint"))
    }


def _approval_envelope_resolves(record: dict[str, Any]) -> bool:
    """Return True if the record's own approval envelope names a bound approver.

    Real valve receipts carry the join result inside a nested ``approval``
    envelope (``approver``, ``fingerprint_bound``, ``valid``), not at the top
    level. Reading only the flat fields misses the evidence the property asks
    for on Ambit's own native format.
    """
    if record.get("fingerprint_bound") is True and interpretable(record.get("approver")):
        return True
    return (
        interpretable(dig(record, "approval.approver"))
        and dig(record, "approval.fingerprint_bound") is True
        and dig(record, "approval.valid") is not False
    )


def _delegation_is_live(record: dict[str, Any]) -> bool:
    """Return True if the record carries a valid, unrevoked delegation envelope.

    An envelope counts only when it identifies a delegation of a known kind
    and asserts its own validity. ``kind: unknown`` with null ids is an empty
    envelope, and ``valid: false`` is a delegation the runtime itself
    rejected — neither is evidence of anything.
    """
    kind = dig(record, "delegation.kind")
    identified = interpretable(dig(record, "delegation.id")) or interpretable(
        dig(record, "delegation.jti")
    )
    return (
        identified
        and interpretable(kind)
        and kind != "unknown"
        and dig(record, "delegation.valid") is not False
        and dig(record, "delegation.revoked") is not True
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
    if interpretable(dig(record, "delegation.issuer")) or interpretable(
        dig(record, "delegation.granted_by")
    ):
        return True
    kind = dig(record, "delegation.kind")
    root = dig(record, "delegation.trust_root_id")
    return interpretable(root) and isinstance(kind, str) and "hmac" not in kind.lower()


def _authority_resolved(record: dict[str, Any], approvals: dict[Any, dict[str, Any]]) -> bool:
    """Return True if a permitted action is bound to a *named principal*.

    Three routes: the record's own approval envelope, a separate approval
    record joined on the request fingerprint, or a delegation whose issuer is
    evidenced. A live delegation without an evidenced issuer is a weaker,
    separate class — see :func:`_delegation_is_live`.
    """
    if _approval_envelope_resolves(record):
        return True
    approval = approvals.get(record.get("request_fingerprint"))
    if approval is not None and interpretable(approval.get("approval_approver")):
        return True
    return _delegation_is_live(record) and _delegation_issuer_evidenced(record)


def _attestation_index(records: list[dict[str, Any]]) -> dict[Any, dict[str, Any]]:
    """Index policy attestations by the policy_hash they attest.

    An attestation binds a policy version to the principal who approved it. It
    is what lets a policy-permitted action name a principal: the authority is
    inherited from the governed policy rather than asserted per call.
    """
    return {
        r.get("policy_hash"): r
        for r in records
        if r.get("record_type") == "policy_attestation"
        and interpretable(r.get("policy_hash"))
        and interpretable(r.get("approver"))
        # Asymmetric only. A symmetric attestation cannot evidence an issuer,
        # so accepting one would reintroduce the gap it exists to close.
        and interpretable(r.get("trust_root_id"))
    }


def _policy_attested(record: dict[str, Any], attestations: dict[Any, dict[str, Any]]) -> bool:
    """True if the policy that permitted this action names an approver."""
    for path in ("policy_hash", "evidence.hashes.policy_hash"):
        value = dig(record, path)
        if not interpretable(value):
            continue
        try:
            if value in attestations:
                return True
        except TypeError:
            # Unhashable: a foreign format put a list or dict where a scalar
            # identity was expected. Not a match, and never a crash.
            continue
    return False


def _has_policy_identity(record: dict[str, Any]) -> bool:
    return (
        interpretable(dig(record, "policy_hash"))
        or interpretable(dig(record, "evidence.hashes.policy_hash"))
        or interpretable(dig(record, "matched_rule_id"))
    )


def principal_authority(records: list[dict[str, Any]]) -> PropertyVerdict:
    """Grade whether every permitted action can be traced to a named principal.

    Denials are excluded from the denominator. A denied action executed
    nothing, so it owes no account of who authorised it, and counting denials
    would let a corpus flatter itself by refusing more often.

    An escalation resolved by a linked approval names a human principal. An
    allow under a named policy proves only *permission* — that the action was
    within a rule — not that any principal took responsibility for it. That
    gap between can and should is the property's whole point, so a corpus of
    policy-permitted allows is capped at partial no matter how clean it is.
    """
    approvals = _approval_index(records)
    attestations = _attestation_index(records)
    decisions = [r for r in records if _is_decision(r)]
    permitted = [r for r in decisions if r.get("decision") in _PERMITTED]
    denied = len(decisions) - len(permitted)

    if not permitted:
        return PropertyVerdict(
            Property.PRINCIPAL_AUTHORITY,
            Sufficiency.STRUCTURALLY_UNFILLABLE,
            reason=UnfillableReason.EVIDENCE_NEVER_PERSISTED,
            recommendation="record at least one permitted action to attribute",
            detail=f"no permitted actions ({denied} denial(s) excluded)",
        )

    attributed = delegated = unresolved = policy_only = unaccounted = 0
    for record in permitted:
        if _authority_resolved(record, approvals):
            attributed += 1
        elif _delegation_is_live(record):
            # A live delegation proves a specific signed grant — strictly more
            # than policy permission — but names the delegate, not the grantor.
            delegated += 1
        elif record.get("decision") == "ESCALATE":
            unresolved += 1
        elif _policy_attested(record, attestations):
            # Permitted by a policy whose approver is named and signed: the
            # action inherits a principal through the policy it ran under.
            attributed += 1
        elif _has_policy_identity(record):
            policy_only += 1
        else:
            # A permitted action with neither a principal nor a policy identity.
            # Counting it nowhere would let it vanish from the denominator and
            # let a corpus report full attribution while carrying bare allows.
            unaccounted += 1

    # §3.5 confidence: the share of permitted actions whose principal is
    # actually named. A delegation without an evidenced issuer counts half —
    # a specific signed grant is more than bare policy permission, and less
    # than a named principal.
    attributed_share = (attributed + 0.5 * delegated) / len(permitted)

    detail = (
        f"{len(permitted)} permitted action(s): {attributed} attributable to a named "
        f"principal, {delegated} under a delegation whose issuer is not evidenced, "
        f"{policy_only} policy-permitted only, {unresolved} escalated without a resolving "
        f"approval, {unaccounted} with no authority evidence at all "
        f"({denied} denial(s) excluded)"
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
    if unaccounted == len(permitted):
        # Nothing recoverable at all. `partially_fillable` means recoverable
        # evidence plus a gap description; where every permitted action lacks
        # a principal, a policy and a delegation alike, there is no evidence
        # to partially recover and reporting one would be generous.
        return PropertyVerdict(
            Property.PRINCIPAL_AUTHORITY,
            Sufficiency.STRUCTURALLY_UNFILLABLE,
            reason=UnfillableReason.EVIDENCE_NEVER_PERSISTED,
            recommendation=(
                f"give the {unaccounted} permitted action(s) an authority basis — a policy "
                "identity at minimum, a delegation or approval where consequential"
            ),
            detail=detail,
        )
    if unaccounted:
        return PropertyVerdict(
            Property.PRINCIPAL_AUTHORITY,
            Sufficiency.PARTIALLY_FILLABLE,
            confidence=attributed_share,
            recommendation=(
                f"give the {unaccounted} bare allow(s) an authority basis — a policy "
                "identity at minimum, a delegation or approval where consequential"
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
