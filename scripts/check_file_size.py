# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Check Python file-size budgets for maintainability."""

from __future__ import annotations

from pathlib import Path

WARN_LIMIT = 600
FAIL_LIMIT = 1000
SOURCE_ROOTS = ("src", "tests", "scripts")
EXCLUDED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".uv-cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
}
ALLOWLIST: dict[str, str] = {}


def _python_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for source_root in SOURCE_ROOTS:
        base = root / source_root
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            if any(part in EXCLUDED_DIRS for part in path.relative_to(root).parts):
                continue
            files.append(path)
    return sorted(files)


def _line_count(path: Path) -> int:
    return sum(1 for _ in path.open("r", encoding="utf-8"))


def main() -> int:
    """Run the file-size budget check."""
    root = Path(__file__).resolve().parents[1]
    warnings: list[tuple[str, int]] = []
    failures: list[tuple[str, int]] = []

    for path in _python_files(root):
        rel = path.relative_to(root).as_posix()
        count = _line_count(path)
        if rel in ALLOWLIST:
            reason = ALLOWLIST[rel]
            print(f"ALLOW file-size {rel}: {count} lines - {reason}")
            continue
        if count >= FAIL_LIMIT:
            failures.append((rel, count))
        elif count >= WARN_LIMIT:
            warnings.append((rel, count))

    for rel, count in warnings:
        print(f"WARN file-size {rel}: {count} lines >= {WARN_LIMIT}; consider splitting")
    for rel, count in failures:
        print(
            f"FAIL file-size {rel}: {count} lines >= {FAIL_LIMIT}; "
            "split it or add an allowlist justification"
        )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
