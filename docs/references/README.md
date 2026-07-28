# References

Third-party source material this implementation is verified against. These are **not** Ambit works, and the repository's proprietary licence does not extend to them — each remains under its own terms. They are retained here so the implementation can be checked against normative text offline, without a network round trip.

## `arXiv-2605.04093-decision-evidence-maturity-model.pdf`

*Decision Evidence Maturity Model for Agentic AI: A Property-Level Method Specification.* Retrieved from `arxiv.org/abs/2605.04093` on 2026-07-27.

SHA-256: `843c6026116c6f7026b7b46f1a9f09f9806cfce0254206b5ca0eaf1d7df823aa`

This is the normative source for everything in `ambit_grader` that claims to be DEMM. The sections the implementation depends on, and where each lands in the code:

| Paper | Implements |
|---|---|
| §3.1 — eight conceptual property classes; v0.1.0 collapse to seven implementation rows | `models.Property`, `models.IMPLEMENTATION_ROWS` |
| §3.2 — adapter tier declares the fragment-to-property mapping | `adapters.ambit_receipts.is_decision_event` |
| §3.4 — ML-opacity boundary; reasoning trace uniformly opaque, authorisation envelope substituted | `aggregate._reasoning_trace_verdict` |
| §3.5 — five fillability categories, completeness formula, weights (opaque = 1.0), architectural reasons | `models.Sufficiency`, `models.WEIGHT`, `models.UnfillableReason`, `aggregate.completeness` |
| §3.6 — gap-closing recommendations routed by regime | `properties.RECOMMENDATIONS`, per-verdict `recommendation` |
| §3.7 — five maturity levels | **deliberately not derived**; see `models.LEVEL_DESCRIPTIONS` |

### Two places the implementation departs, and why

**No maturity level is computed.** §3.7's levels describe the evidence *regime* — manual assembly on challenge, runtime-instrumented by design, exercised against a question battery, monitored as an SLO. None of that is visible in a static evidence file, so assigning a level from a snapshot would be an invention wearing DEMM's name.

**Per-property fill criteria are Ambit's.** The paper defers field-level requirements to the Decision Event Schema (Solozobov 2026b), which is a separate work **not read**. The specific fields each property check looks for are therefore heuristics, and §3.2 makes the adapter tier their proper home. This is the one open fidelity gap: whether `verification_strength` mapping to Table 7's "Output action" row means what is implemented here as chain integrity remains unverified against the schema.
