# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Expansion of Microsoft Agent Governance Toolkit Decision BOM fields.

AGT carries identity, policy and lineage content in an open ``fields`` list,
not in named schema slots. :func:`expand_agt_bom_fields` makes that list
readable by dotted path and marks the claims it cannot use. The profile
readers check those marks before they lift an observed claim.
"""

from __future__ import annotations

from typing import Any

from ambit_grader.sufficiency import bounded_confidence


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
