# ambit-grader

Grades what execution evidence can and cannot prove about **who authorised an action**.

Free, local, offline. It reads evidence you already have and tells you, property by property, which governance questions that evidence can answer — and which it cannot.

## What it does

Point it at an evidence file. It returns three things, in this order:

1. **A sentence you can act on** — "10 permitted actions: 4 attributable to a named approver, 6 policy-permitted only. Next: attest the policy that permitted the 6 automatic allows."
2. **A property table** — the eight DEMM property classes, each carrying a fillability category, an architectural reason where unfillable, and the upstream change that would close the gap.
3. **Two aggregates, never blended** — DEMM reconstruction completeness, and Ambit's own authority verdict.

```bash
ambit-grade receipts.jsonl
ambit-grade receipts.jsonl --format json
ambit-grade receipts.jsonl --min-completeness 0.8   # exit 1 below 80% completeness
```

## What it does not do

- **No network.** Not configurable — there is no network code.
- **No execution.** Nothing in the evidence is ever run. Contrast with scanners that spawn servers to enumerate their tools.
- **No telemetry.** Nothing leaves the machine.
- **No runtime dependencies.** The supply-chain surface is the Python standard library. Adding a runtime dependency is a doctrine-level change, not a convenience.

## The measure is not ours

The property architecture is the **Decision Evidence Maturity Model** (DEMM, arXiv 2605.04093) with its Decision Event Schema (MIT) and reference implementation (Apache-2.0). The eight property classes (§3.1), the five fillability categories (§3.5), the completeness formula and its weights (§3.5), the seven-row v0.1.0 collapse (§3.1), the reasoning-trace opacity boundary (§3.4), and the gap-closing recommendations (§3.6) are implemented as published.

This is deliberate. A yardstick Ambit authored is a yardstick Ambit can be accused of shaping to flatter its own product — the same objection Ambit makes to substrate vendors grading their own evidence. Grading against a measure written by someone else is what lets the result be cited by someone who does not trust Ambit.

Two outputs, never blended:

- **DEMM reconstruction completeness** — the §3.5 weighted average over the seven v0.1.0 implementation rows, comparable to any other implementation of the published formula;
- **the Ambit authority verdict** — the weakest of principal authority, action boundary, and verification strength. Ambit's scoping, labelled as ours.

They are reported separately because they disagree, and the disagreement is the information. On the conformance corpora, `receipts.sample` scores **higher** DEMM completeness than `receipts.rich` (78.6% against 55.7%) while its authority verdict is **worse** — it carries an escalation nobody approved, which floors the spine no matter how well the rest of the record is populated. A single blended number would hide exactly the finding worth having.

**No DEMM maturity level is derived.** §3.7's five levels describe the evidence *regime* — whether reconstruction is manual on challenge, automated by design, exercised against a question battery, or monitored as an SLO. None of that is visible in a static evidence file, so assigning a level from a snapshot would be an invention wearing DEMM's name. `LEVEL_DESCRIPTIONS` records them for reference only.

**Opaque is not a failure.** §3.4 draws the ML-opacity boundary: post-hoc reconstruction of internal model reasoning conflates governance with explainability, so the reasoning trace is classified opaque uniformly and an authorisation envelope is substituted. §3.5 weights it **1.0**, equal to fully fillable. A placeholder digest is not opaque — it is `structurally_unfillable` with reason `evidence_never_persisted`.

**Completeness is protocol-relative, and its partial weight is a real confidence.** §3.5 defines the partially-fillable weight as "confidence in [0, 1]", of which 0.5 is only the reference implementation's *uncalibrated default*. Treating it as a constant makes the score blind: a property fillable for one action in eight would weigh exactly the same as one fillable for six in eight. Where a check can compute the share it is actually confident about it supplies it, and the 0.5 default applies only where no principled fraction exists.

That sensitivity is not cosmetic. Regenerating Ambit's own demo ledger with asymmetrically-signed delegations moved attribution from 1 of 8 permitted actions to 6 of 8; under a flat 0.5 the completeness figure did not move at all, and under the real confidence it goes 84.8% → 89.3%. Completeness compares runs of this tool; it is not an absolute score.

## Two properties are corpus-level, and that is the point

`principal_authority` and `verification_strength` are **not** scored per record. Their evidence lives in the joins *between* records — an escalation and the approval that resolved it, a hash and the record it chains to.

Scoring them per record is the container fallacy: mistaking the presence of an evidence container for the sufficiency of the evidence. The first implementation of this grader made exactly that mistake, reporting authority as unreconstructible over a corpus that carried a complete approval chain in adjacent records. `tests/test_container_fallacy.py` makes that failure permanent, including the case that matters most — a corpus with **more** fully-fillable properties and **higher** DEMM completeness still scoring worse on authority, because its joins are broken.

## Permission is not authority

An `ALLOW` under a named policy proves the action was *within a rule*. It does not prove any principal took responsibility for it. So a corpus of automatic allows is capped at `partial` on principal authority however clean it is, and the next move it reports is to attest the policy itself — bind `policy_hash` to a signed record naming who approved that policy version.

Denials are excluded from the authority denominator. A refused action executed nothing and owes no account of who authorised it; counting denials would let an estate flatter itself by refusing more often.

## Delegation is not issuer

This is the subtlest rule in the grader, and the one that decides whether it can be trusted about its own vendor.

A delegation envelope proves a specific signed grant — strictly more than policy permission. But it names its **`subject`**: the agent the authority was granted *to*. The **issuer** is the principal, and it is the issuer that "who authorised this" asks for.

Ambit's own captured receipts used to fail this. Their delegation envelopes carried `id`, `jti`, `kind`, `scope`, `subject`, `valid`, `revoked`, duration and a full revocation chain — and no issuer at all, because the slips were HMAC-signed. The grader reported 1 of 8 permitted actions naming a principal. The fix was upstream, not in the grader: sign delegations asymmetrically and let the receipt record the verified trust root.

An HMAC token cannot close the gap. Its verify key is its forge key, so anyone able to verify the token could have minted it; a symmetric credential structurally cannot identify its issuer to a third party. Only an explicit `issuer`/`granted_by` field, or an asymmetric signature whose trust root names the grantor, evidences a principal.

So a live delegation without an evidenced issuer is a **distinct third class**, capped at `partially_fillable` and counted separately from human-approved escalations:

| Class | Verdict |
|---|---|
| Named principal — approval envelope, approval-record join, or issuer-evidenced delegation | can reach `fully_fillable` |
| Delegation, issuer not evidenced | capped at `partially_fillable` |
| Policy-permitted only | capped at `partially_fillable` |
| Escalated, no resolving approval | `structurally_unfillable` |
| Permitted with no authority evidence at all — including a named approver that cannot be bound to this action | capped at `partially_fillable`; the two are still named separately in the detail, because the remedy differs |

Naming an approver is not binding one. An adapter only sets `fingerprint_bound` when the source record itself carries evidence tying that approver to *this* request — a request fingerprint or action hash the approval references — never merely because a name was found. None of the six foreign formats this tool reads carries that evidence, so a foreign approver is always recorded but never counted as bound; a `metadata.approver` on a Langfuse span, for instance, is real evidence someone was *named*, not evidence they authorised the specific action being graded.

Treating envelope presence as principal identification would be the container fallacy one level up, committed in the vendor's own favour — the single bias an independence argument cannot survive.

The cost is paid in public. Run against Ambit's own richest captured demo ledger, this grader reports **1 of 8 permitted actions naming a principal**, 5 under delegations whose issuers are not evidenced. A grader that cannot embarrass its own vendor is not evidence.

## Adapters

One ships: Ambit decision-ledger and receipt JSONL. Harness doctrine §3.1 makes connector breadth an explicit anti-goal, so a second adapter waits for a real estate that needs one.

## Library use

```python
from pathlib import Path

from ambit_grader import grade_records, render_text
from ambit_grader.adapters import ambit_receipts

records = ambit_receipts.load(Path("receipts.jsonl"))
grade = grade_records("receipts.jsonl", records)

print(grade.completeness, grade.authority, grade.next_move())
print(render_text([grade]))
```

## Development

```bash
uv sync --extra dev
uv run ruff check .
uv run ruff format --check src tests
uv run python scripts/check_file_size.py
uv run mypy
uv run pytest -q
```

## Status

Pre-release. The rubric has been exercised against hand-built fixtures only; it has never run against a captured production estate. That is the next test, and nothing here should be read as evidence that it converts, installs, or that anyone acts on the finding.
