# Security

## Reporting a vulnerability

Report suspected vulnerabilities to **security@ambit-systems.com**. Do not open a
public issue and do not disclose the finding to third parties before we have
responded.

Include the affected version or commit and an evidence file that reproduces the
defect, with any customer content removed. We acknowledge reports within two
business days and give an assessment with a remediation plan within ten.

## Supported versions

The latest release on PyPI and the `main` branch are the supported lines.
Fixes land on `main` and ship in the next release. We do not backport.

## Supply-chain posture

`ambit-grader` declares **zero runtime dependencies**. Its entire supply-chain
surface is the Python standard library. This is a deliberate constraint, not an
accident of scope: the grader is a trust object, and a tool that tells you what
your evidence proves should not itself depend on code you have not audited.

Adding a runtime dependency to this package is a design decision, not a
convenience. Open an issue before you propose one.

## Handling untrusted input

The grader reads JSONL evidence files, including six foreign adapter formats
produced by systems outside Ambit's control. It must therefore treat every input
file as untrusted.

- **It never executes anything described in the evidence it reads.** The grader
  parses and scores records; it does not act on them.
- It performs no network I/O and spawns no subprocesses.
- Malformed records are reported, not silently dropped. A grade computed over
  records the tool could not parse would be a false assurance.

If you can make the grader crash, hang, or consume unbounded memory on a crafted
evidence file, that is a vulnerability and we want to hear about it.

## Interpreting output

The grader reports a DEMM completeness score and Ambit's authority verdict
separately, and deliberately does not blend them or derive a maturity level from
a static file. Do not present a completeness percentage as an authority
assurance — they answer different questions, and the separation is the point.
