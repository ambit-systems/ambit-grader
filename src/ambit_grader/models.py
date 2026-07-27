# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Core types for evidence grading.

Vocabulary follows the Decision Evidence Maturity Model (DEMM, arXiv
2605.04093). Two things are computed and they are never blended:

* **DEMM reconstruction completeness** (§3.5) — a weighted average over the
  seven implementation rows, faithful to the published formula and comparable
  to any other DEMM implementation. Nothing Ambit authored is inside it.
* **The Ambit authority verdict** — Ambit's own narrower reading of whether a
  permitted action can be traced to a principal. Clearly labelled as ours.

What is deliberately *not* computed is a DEMM maturity level. §3.7 defines the
five levels as descriptions of the evidence **regime** — whether reconstruction
is manual on challenge, automated by design, exercised against a question
battery, or monitored as an SLO. None of that is visible in a static evidence
file, so deriving a level from a snapshot would be an invention wearing DEMM's
name. The levels are recorded here as documentation only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Sufficiency(StrEnum):
    """DEMM §3.5 fillability categories.

    Four are executable; ``CONFLICTING`` is protocol-level in v0.1.0, with
    conflict-scoring and precedence rules named as future work in the paper.
    """

    FULLY_FILLABLE = "fully_fillable"
    """The property value is reconstructable from the evidence."""

    PARTIALLY_FILLABLE = "partially_fillable"
    """Recoverable evidence plus a gap description."""

    STRUCTURALLY_UNFILLABLE = "structurally_unfillable"
    """No value, annotated with an architectural reason."""

    OPAQUE = "opaque"
    """The ML-opacity boundary (§3.4).

    Not a failure. Post-hoc reconstruction of internal model reasoning
    conflates governance with explainability, so the reasoning trace is
    classified opaque uniformly and an authorisation envelope is substituted.
    §3.5 weights it 1.0 because the envelope is the actionable governance
    fragment.
    """

    CONFLICTING = "conflicting"
    """Cross-regime fragments disagree."""


class UnfillableReason(StrEnum):
    """The architectural reasons DEMM §3.5 requires on an unfillable verdict.

    The full vocabulary is exported because a reader of this tool's JSON needs
    the value space, but only two are reachable from a static evidence file and
    that limit is stated rather than hidden:

    * ``EVIDENCE_NEVER_PERSISTED`` — the runtime could have written the field
      and did not. Determinable: the field is simply absent.
    * ``CROSS_STACK_BOUNDARY`` — the evidence plausibly exists on the other
      side of a system boundary this set does not span, which an unresolved
      escalation implies.
    * ``STATE_LOST`` — requires knowing something *was* recorded and is now
      gone. A snapshot cannot show a deletion it never witnessed.
    * ``NON_COOPERATIVE_STRIPPING`` — requires knowing a party removed the
      evidence deliberately. That is an inference about intent, and a grader
      that infers intent from absence is guessing.

    The last two are emitted only by a caller who knows the history; this
    grader never claims them from a file alone.
    """

    CROSS_STACK_BOUNDARY = "cross_stack_boundary"
    STATE_LOST = "state_lost"
    EVIDENCE_NEVER_PERSISTED = "evidence_never_persisted"
    NON_COOPERATIVE_STRIPPING = "non_cooperative_stripping"


#: DEMM §3.5 completeness weights. Opaque is 1.0 by construction, not by
#: leniency.
WEIGHT: dict[Sufficiency, float] = {
    Sufficiency.FULLY_FILLABLE: 1.0,
    Sufficiency.OPAQUE: 1.0,
    Sufficiency.PARTIALLY_FILLABLE: 0.5,
    Sufficiency.STRUCTURALLY_UNFILLABLE: 0.0,
    Sufficiency.CONFLICTING: 0.0,
}

#: The v0.1.0 default confidence for a partially-fillable property.
#:
#: §3.5 defines the partial weight as "confidence in [0, 1]", of which 0.5 is
#: only the reference implementation's *default* — and one the paper states is
#: not independently calibrated. Treating 0.5 as a constant makes completeness
#: blind: a property fillable for one action in eight scores identically to one
#: fillable for six in eight. Where a check can compute the fraction it is
#: actually confident about, it supplies it; this default applies only where no
#: principled fraction exists.
DEFAULT_PARTIAL_CONFIDENCE = 0.5


class Property(StrEnum):
    """The eight DEMM conceptual property classes (§3.1)."""

    ACTOR_IDENTITY = "actor_identity"
    PRINCIPAL_AUTHORITY = "principal_authority"
    ACTION_BOUNDARY = "action_boundary"
    POLICY_BASIS = "policy_basis"
    DECISION_BASIS = "decision_basis"
    DATA_TOUCH = "data_and_resource_touch"
    LIFECYCLE_CONTEXT = "lifecycle_context"
    VERIFICATION_STRENGTH = "verification_strength"


#: The v0.1.0 implementation rows (§3.1, Table 7). The reference implementation
#: collapses actor identity and principal authority into a single row, giving
#: the seven-property metric that completeness is averaged over. Grading over
#: eight rows instead of seven would silently diverge from every published
#: DEMM number.
IMPLEMENTATION_ROWS: tuple[tuple[str, tuple[Property, ...]], ...] = (
    (
        "actor_identity_and_principal_authority",
        (Property.ACTOR_IDENTITY, Property.PRINCIPAL_AUTHORITY),
    ),
    ("action_boundary_and_configuration_envelope", (Property.ACTION_BOUNDARY,)),
    ("policy_basis", (Property.POLICY_BASIS,)),
    ("reasoning_trace_with_opaque_substitution", (Property.DECISION_BASIS,)),
    ("inputs", (Property.DATA_TOUCH,)),
    ("post_condition_state", (Property.LIFECYCLE_CONTEXT,)),
    ("output_action", (Property.VERIFICATION_STRENGTH,)),
)

#: |P| in the completeness formula.
ROW_COUNT = len(IMPLEMENTATION_ROWS)

#: The properties Ambit's own authority verdict reads. This is Ambit's
#: scoping, not a DEMM level, and it is reported separately from completeness.
AUTHORITY_SPINE: tuple[Property, ...] = (
    Property.PRINCIPAL_AUTHORITY,
    Property.ACTION_BOUNDARY,
    Property.VERIFICATION_STRENGTH,
)

#: DEMM §3.7 maturity levels, recorded for reference only.
#:
#: These describe the evidence *regime* a deployment carries into audit, not
#: the contents of an evidence file. Assigning one from a snapshot is not
#: possible, so this grader does not do it.
LEVEL_DESCRIPTIONS: dict[int, str] = {
    1: "ad-hoc — reactive manual assembly on challenge; turnaround days-weeks",
    2: "process-attested — governance processes; manual reconstruction; hours-days",
    3: "property-instrumented — runtime captures schema-named properties; minutes-hours",
    4: "sufficiency-tested — instrumented regime exercised against a question battery",
    5: "continuously-attested — sufficiency monitored as an SLO; degradation alarms",
}


@dataclass(frozen=True, slots=True)
class PropertyVerdict:
    """The verdict for one property class.

    Attributes:
        prop: Which property class this verdict covers. Named ``prop`` so it
            does not shadow the builtin inside the class body.
        sufficiency: The DEMM §3.5 fillability category.
        reason: The architectural reason, required when the verdict is
            ``STRUCTURALLY_UNFILLABLE``.
        recommendation: The upstream regime change that would close the gap
            (§3.6). Emitted for partial and unfillable verdicts.
        detail: Human-readable expansion, used by corpus-level checks.
    """

    prop: Property
    sufficiency: Sufficiency
    reason: UnfillableReason | None = None
    recommendation: str | None = None
    detail: str | None = None
    confidence: float | None = None
    """The §3.5 confidence for a partially-fillable verdict, in [0, 1].

    ``None`` falls back to :data:`DEFAULT_PARTIAL_CONFIDENCE`. Ignored for
    every other category, whose weights are fixed by the method.
    """

    @property
    def weight(self) -> float:
        """Return the DEMM §3.5 completeness weight for this verdict."""
        if self.sufficiency is Sufficiency.PARTIALLY_FILLABLE:
            if self.confidence is None:
                return DEFAULT_PARTIAL_CONFIDENCE
            return max(0.0, min(1.0, self.confidence))
        return WEIGHT[self.sufficiency]


@dataclass(frozen=True, slots=True)
class Grade:
    """The result of grading one evidence set.

    Attributes:
        source: Name of the evidence set.
        record_count: Number of evidence records read.
        verdicts: Per-property verdicts over the eight conceptual classes.
        completeness: DEMM §3.5 reconstruction completeness over the seven
            implementation rows, in [0, 1].
        authority: Ambit's own verdict on whether permitted actions can be
            traced to a principal. Not a DEMM output.
    """

    source: str
    record_count: int
    verdicts: dict[Property, PropertyVerdict] = field(default_factory=dict)
    completeness: float = 0.0
    authority: Sufficiency = Sufficiency.STRUCTURALLY_UNFILLABLE
    shapes: str = ""
    """What was read, by shape, including anything skipped as unrecognised."""

    unrecognised: int = 0
    """Records that parsed as JSON but matched no known evidence shape."""

    def row_verdicts(self) -> list[tuple[str, Sufficiency]]:
        """Return the seven implementation rows with their collapsed verdicts.

        A collapsed row takes the weakest of its constituent properties, so
        the merge cannot manufacture strength that neither property had.
        """
        rows: list[tuple[str, Sufficiency]] = []
        for row_name, props in IMPLEMENTATION_ROWS:
            worst = min(
                (self.verdicts[p] for p in props if p in self.verdicts),
                key=lambda v: v.weight,
                default=None,
            )
            rows.append(
                (row_name, worst.sufficiency if worst else Sufficiency.STRUCTURALLY_UNFILLABLE)
            )
        return rows

    def next_move(self) -> str:
        """Return the single highest-value gap-closing recommendation.

        Ordered weakest-first, not by spine declaration order. The verdict is
        the weakest spine property, so the move that raises it is the one
        addressing that property; returning an earlier-declared but stronger
        property's recommendation would name a step that changes nothing.

        DEMM's own recommendation tensor ranks nothing — it emits one
        recommendation per unfilled property and leaves prioritisation to the
        reader — so the ordering here is Ambit's.
        """
        candidates = sorted(
            (self.verdicts[p] for p in AUTHORITY_SPINE if p in self.verdicts),
            key=lambda v: v.weight,
        )
        for verdict in candidates:
            if verdict.sufficiency is Sufficiency.FULLY_FILLABLE:
                continue
            if verdict.recommendation:
                return verdict.recommendation
        return "authority spine fully fillable; extend to the remaining properties"
