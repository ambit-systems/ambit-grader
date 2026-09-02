# ambit-grader — agent entry point

Read before substantive work in this repository:

- `README.md` — what the grader claims and what it does not claim.
- `SECURITY.md` — the zero-dependency posture and the untrusted-input rule.
- `docs/references/README.md` — the DEMM sections the code implements and where each lands.

Invariants:

- No runtime dependency. The supply-chain surface is the Python standard library.
- No network I/O, no subprocess, nothing executed from evidence.
- Adapters map fields. They never invent a value.
- DEMM completeness and the Ambit authority verdict are reported separately. Never blend them.

Verify with `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy`, `uv run pytest -q`.
