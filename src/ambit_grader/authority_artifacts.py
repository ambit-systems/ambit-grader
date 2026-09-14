# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Record-level readers for authority artifacts: approvals, delegations, and policy identity.

Each function here reads one record, or one approval or delegation envelope
inside it. None of them reads the corpus. :mod:`ambit_grader.joins` combines
these readings across records.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ambit_grader.sufficiency import dig, is_identifier, is_text

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


def _has_policy_identity(record: dict[str, Any]) -> bool:
    return (
        is_text(dig(record, "policy_hash"))
        or is_text(dig(record, "evidence.hashes.policy_hash"))
        or is_text(dig(record, "matched_rule_id"))
    )
