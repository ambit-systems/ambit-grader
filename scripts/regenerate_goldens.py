# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Regenerate the golden files that lock the grader's observable behaviour.

``tests/test_pipeline_golden_master.py``, ``tests/test_cli_golden_master.py``,
and ``tests/test_public_surface_snapshot.py`` compare the code with the files
in ``tests/golden/``. Run this script only after a behaviour change that is
intended and reviewed. Then read the whole ``git diff tests/golden`` before you
commit it. A difference that the change does not explain is a defect, not a
golden to update.

Run from the repository root::

    uv run python scripts/regenerate_goldens.py

Each pipeline case keeps its recorded stage and arguments. The script computes
only the expected output again.
"""

from __future__ import annotations

import argparse
import ast
import importlib
import json
import os
import sys
import tempfile
from pathlib import Path
from types import ModuleType

REPO = Path(__file__).resolve().parent.parent
GOLDEN = REPO / "tests" / "golden"
PIPELINE_CASES = GOLDEN / "pipeline_cases.jsonl"


def _lock(name: str) -> ModuleType:
    """Import one lock test module from the repository's ``tests`` package."""
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    return importlib.import_module(f"tests.{name}")


def _module_path(module_name: str) -> Path:
    """Return the source file of one ``ambit_grader`` module."""
    base = REPO / "src" / Path(*module_name.split("."))
    return base / "__init__.py" if base.is_dir() else base.with_suffix(".py")


def regenerate_pipeline(cases_path: Path) -> dict[str, int]:
    """Compute the expected output of every pipeline case again.

    Args:
        cases_path: JSON Lines file whose lines carry ``kind`` and ``args``.

    Returns:
        The number of cases written for each pipeline stage.
    """
    pipeline_lock = _lock("test_pipeline_golden_master")
    lines: list[str] = []
    counts: dict[str, int] = {}
    for raw in cases_path.read_text(encoding="ascii").splitlines():
        case = json.loads(raw)
        expected = json.loads(pipeline_lock.replay(case["kind"], case["args"]))
        lines.append(
            json.dumps(
                {"kind": case["kind"], "args": case["args"], "expected": expected},
                ensure_ascii=True,
            )
        )
        counts[case["kind"]] = counts.get(case["kind"], 0) + 1
    PIPELINE_CASES.write_text("\n".join(lines) + "\n", encoding="ascii")
    return dict(sorted(counts.items()))


def _recorded_members() -> dict[str, set[str]]:
    """Return the public names that the current surface golden records, per module."""
    path = GOLDEN / "public_surface.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {module: set(entry["members"]) for module, entry in data["modules"].items()}


def regenerate_surface() -> int:
    """Record the public surface of every module that the surface lock names.

    A name that the golden already records stays recorded. A definition that
    moves to another module and is imported back therefore stays locked.

    Returns:
        The number of modules recorded.

    Raises:
        SystemExit: If a module no longer exposes a name that the golden records.
    """
    surface_lock = _lock("test_public_surface_snapshot")
    recorded = _recorded_members()
    modules: dict[str, dict[str, object]] = {}
    for module_name in surface_lock.MODULES:
        module = importlib.import_module(module_name)
        tree = ast.parse(_module_path(module_name).read_text(encoding="utf-8"))
        names: list[str] = []
        for node in tree.body:
            if isinstance(node, ast.FunctionDef | ast.ClassDef):
                names.append(node.name)
            elif isinstance(node, ast.Assign):
                names.extend(target.id for target in node.targets if isinstance(target, ast.Name))
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names.append(node.target.id)
        exported = list(getattr(module, "__all__", []))
        defined = {name for name in names if not name.startswith("_")}
        public = sorted(defined | set(exported) | recorded.get(module_name, set()))
        unreachable = [name for name in public if not hasattr(module, name)]
        if unreachable:
            raise SystemExit(
                f"{module_name} no longer exposes {', '.join(unreachable)}. Remove a name "
                "from tests/golden/public_surface.json by hand only if the removal is intended."
            )
        modules[module_name] = {
            "__all__": getattr(module, "__all__", None),
            "members": {name: surface_lock.describe(getattr(module, name)) for name in public},
        }
    (GOLDEN / "public_surface.json").write_text(
        json.dumps({"modules": modules}, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    return len(modules)


def regenerate_cli() -> int:
    """Record the exit code, stdout, and stderr of every CLI lock case.

    Returns:
        The number of cases recorded.
    """
    cli_lock = _lock("test_cli_golden_master")
    os.chdir(REPO)
    os.environ.update(cli_lock.CLI_ENVIRONMENT)
    outputs: dict[str, object] = {}
    for case, argv in sorted(cli_lock.CASES.items()):
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            outputs[case] = cli_lock.run_cli(argv(workdir), workdir)
    outputs[cli_lock.SUBPROCESS_CASE] = cli_lock.run_cli_subprocess()
    (GOLDEN / "cli_outputs.json").write_text(
        json.dumps(outputs, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    return len(outputs)


def main(argv: list[str] | None = None) -> int:
    """Regenerate the three golden files and print what the script wrote."""
    parser = argparse.ArgumentParser(description="Regenerate the grader's golden files.")
    parser.add_argument(
        "--cases",
        type=Path,
        default=PIPELINE_CASES,
        help="JSON Lines file of pipeline cases to record (default: the current golden file)",
    )
    args = parser.parse_args(argv)
    print("pipeline cases:", regenerate_pipeline(args.cases))
    print("surface modules:", regenerate_surface())
    print("cli cases:", regenerate_cli())
    return 0


if __name__ == "__main__":
    sys.exit(main())
