# Changelog

All notable changes to ambit-grader are recorded in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — public release under Apache-2.0

### Changed

- Licence changed from proprietary to Apache-2.0. `LICENSE` carries the full
  text; `NOTICE` carries the copyright line; every source file carries an
  SPDX header.
- Package metadata: `license = "Apache-2.0"`, the OSI classifier, Python 3.12
  and 3.13 classifiers, project URLs, and an sdist that ships `tests/`,
  `CHANGELOG.md`, `SECURITY.md`, `LICENSE` and `NOTICE`.
- README rewritten for a reader outside Ambit: what the grader does, install,
  run, the recognised record shapes, exit codes, output shape, how authority
  is graded, and what the grade does not claim.
- Public surfaces no longer name private Ambit repositories, hostnames or
  private design documents. The loader docstring no longer claims to be
  the only adapter; the third-party trace profiles have shipped since 0.1.0.
- The public API is the thirteen names in `ambit_grader.__all__`. `combine`,
  `completeness`, `headline`, `WEIGHT`, `ROW_COUNT` and `LEVEL_DESCRIPTIONS`
  are no longer re-exported from the package root; they remain importable
  from their modules.
- The JSONL loader moved from `ambit_grader.adapters.ambit_receipts` to
  `ambit_grader.jsonl`, and is exported as `ambit_grader.load_jsonl` with
  `ambit_grader.EvidenceReadError`. `is_decision_event` moved to
  `ambit_grader.adapters.normalise`. `load` accepts a `str` or
  `os.PathLike`. A leading UTF-8 byte order mark is skipped.
- The CLI reports `source` as the path given on the command line, so two
  files with the same basename stay distinguishable.
- `--min-completeness` rejects values outside the range 0-1, including `nan`,
  with exit code 2.
- The DEMM paper is no longer committed to the repository.
  `docs/references/README.md` records its URL and SHA-256.
- `SECURITY.md`: the latest PyPI release and `main` are the supported lines.

### Added

- `.github/workflows/ci.yml`: ruff, ruff format, file-size budget, mypy,
  pytest and `uv build` on Python 3.12 and 3.13, on push to `main` and on
  pull requests. Actions pinned by commit SHA.
- `.github/workflows/release.yml`: on a `v*` tag, check the tag against the
  package version, test, build sdist and wheel, and publish to PyPI through
  trusted publishing. No secrets. Actions pinned by commit SHA.
- `run_grade()`, the shared implementation of the grading loop, exit codes and
  partial-failure behaviour, for the standalone entry point and the Ambit CLI.
- Direct unit tests for `partial_confidence`, the function that implements the
  confidence-weighting claim in the README.
- Tests for multi-path grading, the `--min-completeness` passing branch, and
  the exact-boundary case where completeness equals the threshold (the gate is
  `<`, so equality passes).
- `SECURITY.md`, recording the zero-dependency supply-chain posture and the
  requirement that evidence input is untrusted.

### Breaking

- **A completeness breach exits `5`, not `1`.** The same gate exits `5`
  through `ambit grade` in the Ambit CLI, so a CI pipeline behaved differently
  depending on which entry point it called. A read error keeps exit `1`.
  "Your evidence is thin" and "I could not read your file" are different
  problems, and a gate needs to tell them apart.
- **Errors go to stderr.** They were printed to stdout, so `--format json`
  emitted a non-JSON line into the document the caller was parsing.

### Fixed

- A failure on any path discarded every grade already computed. Every path is
  now attempted, whatever succeeded is rendered, the failures are reported on
  stderr, and the exit code is still non-zero.
- A file that is not valid UTF-8 raised an uncaught `UnicodeDecodeError`. It
  is now an `EvidenceReadError` naming the path.
- A `record_type`, `decision`, `request_fingerprint`, `approval_fingerprint`
  or `policy_hash` value that was a list or dict raised `TypeError`. Such
  values are now dropped or ignored, and the record is still graded.
- Lines were split on every Unicode line terminator, so a valid JSON string
  containing U+2028 or U+0085 was rejected as malformed. Lines are now split
  on `\n` only.

## [0.1.0]

- The grader: eight DEMM property classes, DEMM completeness over the seven
  implementation rows, and the Ambit authority verdict.
- Six third-party trace profiles: OpenTelemetry GenAI, OpenInference,
  Langfuse, LangSmith, Weave and Microsoft Agent Governance Toolkit.
- Two fixtures: `complete_records_broken_joins.jsonl` and
  `sparse_records_complete_joins.jsonl`.
- Not published.
