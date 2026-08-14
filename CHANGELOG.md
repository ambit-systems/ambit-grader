# Changelog

All notable changes to ambit-grader will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking

- **A completeness breach now exits `5`, not `1`.** The same gate exits `5`
  through `ambit grade` in ambit-cli, so a CI pipeline behaved differently
  depending on which entry point it called, and ambit-cli's README documented
  `5`. A read error keeps exit `1`. The two are different problems — "your
  evidence is thin" and "I could not read your file" — and a gate needs to tell
  them apart.
- **Errors go to stderr.** They were printed to stdout, so `--format json`
  emitted a non-JSON line into the document the caller was parsing.

### Fixed

- A failure on any path discarded every grade already computed. The loop
  returned before the renderer ran, so grading five files where the third was
  malformed produced no output at all — not even for the two that succeeded.
  Every path is now attempted, whatever succeeded is rendered, the failures are
  reported on stderr, and the exit code is still non-zero.

### Added

- `run_grade()`, the shared implementation of the grading loop, exit codes and
  partial-failure behaviour. `ambit grade` in ambit-cli carries a duplicate of
  this logic that had already drifted; it will delegate here once the pinned
  ambit-grader dependency advances past this commit.
- Direct unit tests for `partial_confidence`, the function implementing the
  confidence-weighting claim the README foregrounds. It was previously
  exercised only indirectly through `grade_records`, so the headline claim was
  validated one layer removed from the code that makes it.
- Tests for multi-path grading, the `--min-completeness` passing branch, and the
  exact-boundary case where completeness equals the threshold (the gate is `<`,
  so equality must pass).
- `SECURITY.md`, recording the zero-dependency supply-chain posture as a
  deliberate constraint and the requirement that evidence input is untrusted.
- `authors`, `license` and the proprietary classifier in package metadata. The
  wheel previously shipped with no licence declared.

### Changed

- `pydantic` is not a dependency and never was; no change there. The runtime
  dependency set remains empty by design.
