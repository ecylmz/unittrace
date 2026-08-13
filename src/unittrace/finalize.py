from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from .analysis import run as run_analysis
from .io import atomic_json, sha256_file


ROOT = Path(__file__).resolve().parents[2]
FULL = ROOT / "artifacts/full"
ANALYSIS = FULL / "analysis"
MANIFESTS = FULL / "manifests"


def _source_tree_manifest() -> tuple[list[dict[str, Any]], str]:
    roots = [ROOT / "src", ROOT / "tests", ROOT / "config"]
    files = [ROOT / "pyproject.toml", ROOT / "uv.lock", ROOT / "unittrace_article_spec_v4_2.md"]
    for directory in roots:
        files.extend(path for path in directory.rglob("*") if path.is_file() and "__pycache__" not in path.parts)
    rows = [
        {"path": str(path.relative_to(ROOT)), "bytes": path.stat().st_size, "sha256": sha256_file(path)}
        for path in sorted(set(files))
    ]
    material = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return rows, hashlib.sha256(material).hexdigest()


def _analysis_hashes() -> dict[str, str]:
    excluded = {"analysis_output_hashes.json", "analysis_determinism.json", "numeric_consistency_audit.json"}
    return {
        str(path.relative_to(FULL)): sha256_file(path)
        for directory in (ANALYSIS, FULL / "tables")
        for path in sorted(directory.glob("*"))
        if path.is_file() and path.name not in excluded
    }


def policy_equivalence() -> dict[str, Any]:
    evaluator = Path("/usr/bin/systemd-analyze")
    policy = ROOT / "config/security-policy.json"
    cases = [
        ("fixture-reset", FULL / "roots/fixtures/reset", "fixture.service"),
        ("fixture-effective", FULL / "roots/fixtures/effective", "fixture.service"),
        ("fixture-dropin", FULL / "roots/fixtures/dropin", "fixture.service"),
        ("fixture-service-wide", FULL / "roots/fixtures/service-wide", "fixture.service"),
        ("fixture-alias", FULL / "roots/fixtures/alias", "canonical.service"),
        ("frozen-vsftpd", FULL / "roots/effective/arch/vsftpd-3.0.5-2", "vsftpd.service"),
    ]
    rows: list[dict[str, Any]] = []
    base = [str(evaluator), "security", "--offline=yes", "--json=short", "--no-pager"]
    for name, root, unit in cases:
        fixed = subprocess.run(base + [f"--root={root}", f"--security-policy={policy}", unit], capture_output=True, check=False)
        builtin = subprocess.run(base + [f"--root={root}", unit], capture_output=True, check=False)
        rows.append({
            "case": name, "unit": unit, "fixed_returncode": fixed.returncode, "builtin_returncode": builtin.returncode,
            "fixed_stdout_sha256": hashlib.sha256(fixed.stdout).hexdigest(),
            "builtin_stdout_sha256": hashlib.sha256(builtin.stdout).hexdigest(),
            "byte_equivalent": fixed.returncode == builtin.returncode and fixed.stdout == builtin.stdout,
        })
    result = {
        "archived_policy_sha256": sha256_file(policy), "archived_policy_json": json.loads(policy.read_text()),
        "evaluator_sha256": sha256_file(evaluator), "cases": rows,
        "all_byte_equivalent": all(row["byte_equivalent"] for row in rows),
        "interpretation": "The archived policy is the empty JSON override; under the pinned evaluator it is byte-equivalent to the built-in policy on all semantic fixtures and a frozen census unit.",
    }
    atomic_json(ANALYSIS / "policy_weighting_sensitivity.json", result)
    return result


def finalize() -> dict[str, Any]:
    policy = policy_equivalence()
    run_analysis()
    first = _analysis_hashes()
    run_analysis()
    second = _analysis_hashes()
    analysis_determinism = {
        "bootstrap_seed": 420260809, "bootstrap_replicates": 5000,
        "first_run_hashes": first, "second_run_hashes": second,
        "byte_equivalent": first == second,
    }
    atomic_json(MANIFESTS / "analysis_determinism.json", analysis_determinism)
    if not analysis_determinism["byte_equivalent"]:
        raise RuntimeError("analysis outputs are not byte-equivalent with the frozen seed")
    source_files, source_tree_hash = _source_tree_manifest()
    atomic_json(MANIFESTS / "source_tree_manifest.json", {"files": source_files, "source_tree_sha256": source_tree_hash})
    environment = json.loads((ROOT / "artifacts/execution_environment.json").read_text())
    census = json.loads((FULL / "normalized/census_manifest.json").read_text())
    normalized = json.loads((MANIFESTS / "determinism_manifest.json").read_text())
    traceable_artifacts = {
        "frozen_input_verification": FULL / "frozen_input_verification.json",
        "protocol_freeze": ROOT / "artifacts/protocol_freeze.json",
        "execution_environment": ROOT / "artifacts/execution_environment.json",
        "package_artifact_manifest": FULL / "raw/package_artifact_manifest.json",
        "source_artifact_manifest": FULL / "raw/source_artifact_manifest.json",
        "canonical_upstream_mapping": FULL / "normalized/eligible_population.csv",
        "matching_table": FULL / "normalized/service_lineages.csv",
        "cohort_memberships": FULL / "normalized/cohorts.csv",
        "normalized_policy_states": FULL / "normalized/policy_states.csv",
        "provenance_states": FULL / "normalized/upstream_artifacts.csv",
        "transformation_table": FULL / "normalized/transformations.csv",
        "exclusion_table": FULL / "normalized/exclusions.csv",
    }
    manifest = {
        "study": "UnitTrace v4.2 full frozen census", "protocol_sha256": census["authoritative_protocol_sha256"],
        "source_code_commit": "UNAVAILABLE_NO_GIT_METADATA_IN_WORKSPACE", "source_tree_sha256": source_tree_hash,
        "eligible_population_sha256": census["eligible_population_sha256"], "eligible_projects": census["eligible_projects"],
        "repository_freeze_manifest": "artifacts/full/frozen_input_verification.json",
        "package_artifact_manifest": "artifacts/full/raw/package_artifact_manifest.json",
        "source_artifact_manifest": "artifacts/full/raw/source_artifact_manifest.json",
        "evaluator_sha256": environment["evaluator_digest"], "evaluator_version": environment["evaluator_version"],
        "security_policy_sha256": environment["security_policy_hash"],
        "execution_environment_manifest": "artifacts/execution_environment.json",
        "normalized_output_sha256": normalized["normalized_output_hash"],
        "analysis_output_hashes": "artifacts/full/manifests/analysis_output_hashes.json",
        "bootstrap_seed": 420260809, "bootstrap_namespace": census["bootstrap_namespace"], "bootstrap_replicates": 5000,
        "rq3d_status": "RQ3d_DISABLED", "repositories_refrozen": False,
        "policy_sensitivity_pass": policy["all_byte_equivalent"],
        "normalized_determinism_pass": normalized["byte_equivalent_normalized_outputs"],
        "analysis_determinism_pass": analysis_determinism["byte_equivalent"],
        "traceable_artifact_hashes": {
            name: {"path": str(path.relative_to(ROOT)), "sha256": sha256_file(path)}
            for name, path in traceable_artifacts.items()
        },
        "reproduction_commands": [
            "uv sync --frozen", "uv run pytest -q", "uv run python -m unittrace.fullstudy verify",
            "uv run python -m unittrace.fullstudy run", "uv run python -m unittrace.finalize",
            "uv run python -m unittrace.revision", "uv run python -m unittrace.publication",
        ],
        "third_party_artifact_policy": "Raw third-party packages/sources are not intended for redistribution; manifests contain repository URLs and hashes for reacquisition.",
        "hostname": os.uname().nodename,
    }
    atomic_json(MANIFESTS / "reproducibility_manifest.json", manifest)
    return manifest


if __name__ == "__main__":
    finalize()
