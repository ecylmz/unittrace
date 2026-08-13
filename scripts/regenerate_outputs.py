from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def output_hashes() -> dict[str, str]:
    excluded = {
        "analysis_determinism.json",
        "analysis_output_hashes.json",
        "numeric_consistency_audit.json",
        "manuscript_compile_status.json",
        "publication_output_hashes.json",
        "quality_gates.json",
    }
    return {
        str(path.relative_to(ROOT)): sha256(path)
        for directory in (ROOT / "artifacts/full/analysis", ROOT / "artifacts/full/tables")
        for path in sorted(directory.glob("*"))
        if path.is_file() and path.name not in excluded
    }


def run_module(name: str) -> None:
    subprocess.run([sys.executable, "-m", name], cwd=ROOT, check=True)


def restore() -> None:
    subprocess.run([sys.executable, "scripts/restore_derived_data.py"], cwd=ROOT, check=True)


def analysis() -> None:
    restore()
    run_module("unittrace.analysis")
    first = output_hashes()
    run_module("unittrace.analysis")
    second = output_hashes()
    if first != second:
        changed = sorted(set(first) | set(second) - {path for path in first if first.get(path) == second.get(path)})
        raise RuntimeError(f"analysis output drift: {changed}")
    print(f"PASS: {len(first)} analysis/table files are byte-equivalent across repeated runs")


def figures() -> None:
    analysis()
    run_module("unittrace.revision")
    print("PASS: revision tables and seven figures regenerated")


def main() -> None:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--analysis", action="store_true")
    group.add_argument("--figures", action="store_true")
    args = parser.parse_args()
    if args.analysis:
        analysis()
    elif args.figures:
        figures()


if __name__ == "__main__":
    main()
