# ambit-grader

`ambit-grader` grades what existing execution evidence can and cannot prove about **who authorised an action**.

It reads an evidence file you already have. It reports, property by property, which governance questions that evidence can answer and which it cannot. It is read-only and offline. It executes nothing.

## What it does

Give it a JSONL evidence file. It returns three things, in this order:

1. **One sentence you can act on.** Example from a shipped fixture: `2 permitted action(s): 0 attributable to a named principal, 0 under a delegation whose issuer is not evidenced, 1 policy-permitted only, 1 escalated without a resolving approval, 0 naming an approver not bound to this action, 0 with no authority evidence at all (1 denial(s) excluded). Next: link the 1 unresolved escalation(s) to an approval record carrying a named approver.`
2. **A property table.** One row for each of the eight DEMM property classes. Each row carries a fillability category. An unfillable row carries an architectural reason and the upstream change that would close the gap.
3. **Two aggregates, never blended.** DEMM reconstruction completeness, and Ambit's own authority verdict.

## What it does not do

- **No network.** There is no network code. This is not a setting.
- **No execution.** Nothing in the evidence is run. The grader parses records and scores them.
- **No subprocess.** The grader spawns nothing.
- **No telemetry.** Nothing leaves the machine.
- **No runtime dependencies.** The supply-chain surface is the Python standard library. See `SECURITY.md`.

## Install

Python 3.12 or later.

```bash
pip install ambit-grader
```

## Run

```bash
ambit-grade evidence.jsonl
ambit-grade evidence.jsonl --format json
ambit-grade a.jsonl b.jsonl                   # one report, one column per file
ambit-grade evidence.jsonl --min-completeness 0.8   # exit 5 below 80 % completeness
```

`ambit-grade --help` lists the options.

## Supported formats

The input is newline-delimited JSON, encoded as UTF-8. A leading byte order mark is skipped. A file that is not valid UTF-8 is a read error. Every non-blank line must be a JSON object. The grader recognises the shape of each record. It maps known fields onto canonical paths. It never invents a value: a field absent from the source stays absent.

| Shape name | Recognised by |
|---|---|
| `ambit_ledger` | `record_type: "decision"`, or a string `decision` verdict with no `record_type` |
| `ambit_approval` | `record_type: "approval"` |
| `ambit_<type>` | any other string `record_type` (consequence intent, outcome, observatory score); kept for the joins, not scored as a decision event. A `record_type` that is not a string is dropped and the record is matched on its other fields |
| `ambit_receipt_payload` | `decision` is an object with an `outcome` |
| `microsoft_agt` | Microsoft Agent Governance Toolkit decision records and Decision BOMs (`decision` with `policy_id`, `agent_id` or `agt`; or `decision_id` + `agent_id` + `outcome`) |
| `otel_genai` | OpenTelemetry GenAI semantic conventions (any `gen_ai.*` attribute) |
| `openinference` | OpenInference spans (any `openinference.*` or `llm.*` attribute) |
| `langsmith` | LangSmith run export (`run_type`, or `trace_id` + `inputs`) |
| `weave` | Weights & Biases Weave call export (`op_name`) |
| `langfuse` | Langfuse observation export (`traceId`, or `type` + `startTime`) |
| `generic_jsonl` | no verdict and no type, but at least one of `actor_id`, `actor.id`, `tool_name`, `action.type`, `object.id` |

A record that matches no shape is counted as `unrecognised` and reported. It is not raised as an error. A line that is not a JSON object is an error: the file is malformed, and a grade computed around it would be a false assurance.

None of the six third-party trace formats carries an authorisation attribute. An estate instrumented with any of them scores `structurally_unfillable` on principal authority whatever the trace richness. That is the gap the grader exists to name.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Every path graded. No completeness gate breached. |
| `1` | At least one path could not be read or parsed. The other paths are still graded and rendered. |
| `2` | Usage error (argparse). |
| `5` | A grade fell below `--min-completeness`. |

Errors go to stderr. The report goes to stdout, so `--format json` output stays parseable. Code `1` takes precedence over code `5`: when one path is unreadable and another grade is below the gate, the exit code is `1`. `--min-completeness` accepts a number in the range 0-1; any other value is a usage error.

## Output

Text output (default): one header and one headline sentence per file, then a table with one column per file. The table has eight property rows, a `DEMM completeness (7 rows)` row and an `Ambit authority verdict` row. Two fixed notes follow that explain the two aggregates.

JSON output (`--format json`): a list with one object per file.

```json
[
  {
    "source": "evidence.jsonl",
    "record_count": 4,
    "shapes": "1 ambit_approval, 3 ambit_ledger",
    "unrecognised": 0,
    "demm": {
      "completeness": 0.7857,
      "row_verdicts": { "<row>": "<sufficiency>" },
      "properties": {
        "<property>": {
          "sufficiency": "fully_fillable | partially_fillable | structurally_unfillable | opaque | conflicting",
          "weight": 1.0,
          "reason": "<architectural reason or null>",
          "recommendation": "<upstream change that closes the gap or null>",
          "detail": "<what was counted>"
        }
      }
    },
    "ambit": {
      "authority_verdict": "<sufficiency>",
      "spine": ["principal_authority", "action_boundary", "verification_strength"],
      "headline": "<the sentence>",
      "next_move": "<the one defaulted next action>"
    }
  }
]
```

`record_count` is the number of records that matched a known shape. It excludes `unrecognised`. `source` is the path as given on the command line.

The eight properties are `actor_identity`, `principal_authority`, `action_boundary`, `policy_basis`, `decision_basis`, `data_and_resource_touch`, `lifecycle_context` and `verification_strength`.

## The measure

The property architecture is the **Decision Evidence Maturity Model** (DEMM, arXiv 2605.04093). The grader implements the eight property classes (§3.1), the five fillability categories (§3.5), the completeness formula and its weights (§3.5), the seven-row v0.1.0 collapse (§3.1), the reasoning-trace opacity boundary (§3.4), and the gap-closing recommendations (§3.6) as published. `docs/references/README.md` maps each section to the code.

Ambit did not write the measure. A yardstick Ambit authored could be shaped to flatter Ambit's own product. Grading against a published measure lets a reader who does not trust Ambit check the result.

Two outputs are reported, and they are never blended:

- **DEMM reconstruction completeness.** The §3.5 weighted average over the seven v0.1.0 implementation rows. Comparable to any other implementation of the published formula.
- **The Ambit authority verdict.** The weakest of `principal_authority`, `action_boundary` and `verification_strength`. This is Ambit's scoping and is labelled as such.

The two can disagree, and the disagreement is the finding. On the two shipped fixtures, `complete_records_broken_joins.jsonl` scores higher DEMM completeness than `sparse_records_complete_joins.jsonl` (78.6 % against 57.1 %) and a worse authority verdict (`structurally_unfillable` against `partially_fillable`). It carries an escalation that nobody approved. One blended number would hide that.

**Partial weight is a real confidence.** §3.5 defines the partially-fillable weight as a confidence in [0, 1]. The reference implementation's 0.5 is an uncalibrated default. Where a check can compute the share of cases it is confident about, it supplies that share. The 0.5 default applies only where no principled fraction exists. Completeness therefore compares runs of this tool. It is not an absolute score.

## How authority is graded

**Permission is not authority.** An `ALLOW` under a named policy proves the action was within a rule. It does not prove that a principal took responsibility for it. A corpus of automatic allows is capped at `partially_fillable` on principal authority. The reported next move is to attest the policy: bind `policy_hash` to a signed record that names who approved that policy version.

**Denials are excluded from the authority denominator.** A refused action executed nothing and owes no account of who authorised it.

**Delegation is not issuer.** A delegation envelope names its `subject`, the agent the authority was granted to. The question "who authorised this" asks for the issuer. A symmetric (HMAC) credential cannot evidence its issuer to a third party, because its verify key is its forge key. Only an explicit `issuer` or `granted_by` field, or an asymmetric signature whose trust root names the grantor, evidences a principal. A live delegation without an evidenced issuer is a distinct class, capped at `partially_fillable`.

**Naming an approver is not binding one.** An adapter sets `fingerprint_bound` only when the source record carries evidence tying that approver to this request: a request fingerprint or action hash the approval references. None of the six third-party formats carries that evidence, so a foreign approver is always recorded and never counted as bound.

**Two properties are corpus-level.** `principal_authority` and `verification_strength` are not scored per record. Their evidence lives in the joins between records: an escalation and the approval that resolved it, a hash and the record it chains to. Scoring them per record is the container fallacy: mistaking the presence of an evidence container for the sufficiency of the evidence. `tests/test_container_fallacy.py` locks this in, including the case where a corpus with higher DEMM completeness scores worse on authority because its joins are broken.

| Class | Verdict |
|---|---|
| Named principal: approval envelope, approval-record join, or issuer-evidenced delegation | can reach `fully_fillable` |
| Delegation, issuer not evidenced | capped at `partially_fillable` |
| Policy-permitted only | capped at `partially_fillable` |
| Escalated, no resolving approval | `structurally_unfillable` |
| Permitted with no authority evidence, or a named approver not bound to this action | capped at `partially_fillable`; the two are named separately in the detail because the remedy differs |

## What the grade does not claim

- **It does not assign a DEMM maturity level.** §3.7 levels describe the evidence regime: whether reconstruction is manual on challenge, automated by design, exercised against a question battery, or monitored as an SLO. A static file does not show that. `ambit_grader.models.LEVEL_DESCRIPTIONS` records the levels for reference only.
- **It does not verify signatures or recompute hashes.** `verification_strength` checks that each record's `prev_hash` equals the previous record's `record_hash`, and counts records outside the chain. It does not recompute a record hash from its content and it does not verify a signature. Use a ledger verifier for that.
- **It does not read the Decision Event Schema.** Per-property fill criteria are Ambit's heuristics. §3.2 makes the adapter tier their proper home. `docs/references/README.md` names the one open fidelity gap.
- **`opaque` is not a failure.** §3.4 classifies the reasoning trace as opaque and substitutes an authorisation envelope. §3.5 weights it 1.0. A placeholder digest is not opaque; it is `structurally_unfillable` with reason `evidence_never_persisted`.
- **Completeness is not an absolute score.** It is protocol-relative. Compare runs of this tool against each other.
- **A grade is not a security assessment.** The grader reports what the evidence proves. It does not test the system that produced the evidence.

## Library use

```python
from ambit_grader import EvidenceReadError, grade_records, load_jsonl, render_text

try:
    records = load_jsonl("evidence.jsonl")
except EvidenceReadError as exc:
    raise SystemExit(f"error: {exc}") from exc
grade = grade_records("evidence.jsonl", records)

print(grade.completeness, grade.authority, grade.next_move())
print(render_text([grade]))
```

`load_jsonl` accepts a `str` or any `os.PathLike`. It raises `EvidenceReadError` when the file cannot be read, is not UTF-8, or has a line that is not a JSON object.

The supported library surface is the names in `ambit_grader.__all__`: `grade_records`, `load_jsonl`, `EvidenceReadError`, `Grade`, `PropertyVerdict`, `Property`, `Sufficiency`, `UnfillableReason`, `AUTHORITY_SPINE`, `IMPLEMENTATION_ROWS`, `render_text`, `render_json` and `to_dict`. `ambit_grader.cli.run_grade(paths, output_format=..., min_completeness=...)` is the same loop the CLI runs and returns the same exit codes. Other module-level names can change between minor versions.

## Development

```bash
uv sync --extra dev
uv run ruff check .
uv run ruff format --check .
uv run python scripts/check_file_size.py
uv run mypy
uv run pytest -q
uv build
```

## Status

The rubric has been exercised against hand-built fixtures and against captured Ambit sample ledgers. It has not run against a production estate from another vendor. Treat every number it prints as a statement about the evidence file, not about the system that produced it.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`. The DEMM paper is a third-party work under its own terms; `docs/references/README.md` records its source and digest.
