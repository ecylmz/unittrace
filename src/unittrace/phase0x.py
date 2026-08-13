from __future__ import annotations

import argparse
import csv
import hashlib
import inspect
import json
import os
import platform
import shutil
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .fixtures import run_semantic_fixtures
from .io import atomic_json, download, read_json, sha256_file, write_csv
from .model import DimensionStatus, UArtifactClass
from .phase0_audit import MATCH_MODES, audit_matching_invariants, compute_pair_profiles, effective_state_index, matched_lineage_index
from .pipeline import (
    analyze_states,
    cross_distribution_transformations,
    extract_pilot_packages,
    match_lineages,
    prepare_distribution_bases,
    root_manifest_hash,
)
from .protocol import deterministic_order
from .repositories import _release_hash, fetch_pilot_packages
from .sources import (
    evaluate_upstream,
    extract_pristine_sources,
    fetch_arch_sources,
    fetch_deb_sources,
    fetch_fedora_sources,
    resolve_upstream_artifacts,
)


ROOT = Path(__file__).resolve().parents[2]
HISTORICAL = ROOT / "artifacts"
ARTIFACTS = HISTORICAL / "phase0x"
REPORT = ROOT / "PHASE0X_REPORT.md"
CONFIG_PATH = ROOT / "config/phase0x.json"
HISTORICAL_REPORTS = (ROOT / "PHASE0_REPORT.md", ROOT / "PHASE0_AUDIT_REPORT.md")
DISTRIBUTIONS = ("debian", "ubuntu", "fedora", "arch")
PAIR_SPECS = (
    ("debian", "ubuntu", "Debian ↔ Ubuntu", "DERIVATIVE_FAMILY"),
    ("debian", "fedora", "Debian ↔ Fedora", "CROSS_FAMILY"),
    ("debian", "arch", "Debian ↔ Arch", "CROSS_FAMILY"),
    ("ubuntu", "fedora", "Ubuntu ↔ Fedora", "CROSS_FAMILY"),
    ("ubuntu", "arch", "Ubuntu ↔ Arch", "CROSS_FAMILY"),
    ("fedora", "arch", "Fedora ↔ Arch", "CROSS_FAMILY"),
)
CROSS_FAMILY_PAIRS = tuple((left, right) for left, right, _, family in PAIR_SPECS if family == "CROSS_FAMILY")
PROVENANCE_CLASSES = tuple(item.value for item in UArtifactClass)
RESOLVED_STATUSES = {DimensionStatus.PRESENT_RESOLVED.value, DimensionStatus.ABSENT_RESOLVED.value}
NORMALIZED_TARGETS = (
    "normalized/cohorts.csv",
    "normalized/eligible_population.csv",
    "normalized/exclusions.csv",
    "normalized/gate_results.csv",
    "normalized/matching_mode_availability.json",
    "normalized/matching_modes.csv",
    "normalized/metrics.json",
    "normalized/pairwise_support.csv",
    "normalized/per_dimension_retention.csv",
    "normalized/pilot_packages.csv",
    "normalized/policy_states.csv",
    "normalized/repository_packages.csv",
    "normalized/repository_services.csv",
    "normalized/sampling_manifest.json",
    "normalized/selected_projects.csv",
    "normalized/semantic_fixture_results.json",
    "normalized/service_lineages.csv",
    "normalized/service_units.csv",
    "normalized/source_inventories.json",
    "normalized/transformations.csv",
    "normalized/upstream_artifacts.csv",
    "security_assessment_schema.json",
    "tier_a_invariant_audit.json",
    "attrition_by_distribution.csv",
    "attrition_by_pair.csv",
)


def load_config() -> dict[str, Any]:
    return read_json(CONFIG_PATH)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def pair_family_type(left: str, right: str) -> str:
    pair = frozenset((left, right))
    if pair == frozenset(("debian", "ubuntu")):
        return "DERIVATIVE_FAMILY"
    if any(pair == frozenset(item) for item in CROSS_FAMILY_PAIRS):
        return "CROSS_FAMILY"
    raise ValueError(f"not a preregistered distribution pair: {left}, {right}")


def _pair_labels(distributions: set[str]) -> list[str]:
    return [label for left, right, label, family in PAIR_SPECS if family == "CROSS_FAMILY" and {left, right} <= distributions]


def construct_eligible_population(
    packages: list[dict[str, Any]], namespace: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
    no_url: list[dict[str, Any]] = []
    for package in packages:
        canonical = package.get("canonical_upstream_id", "")
        if not canonical:
            no_url.append(
                {
                    "entity_type": "package",
                    "entity_id": f"{package['distribution']}:{package['name']}",
                    "stage": "cross_family_eligibility",
                    "reason_code": "NO_AUTHORITATIVE_UPSTREAM_URL",
                    "technical_detail": package.get("homepage", ""),
                }
            )
            continue
        by_project[canonical].append(package)
    eligible: list[dict[str, Any]] = []
    for canonical, observations in by_project.items():
        distributions = {row["distribution"] for row in observations}
        pairs = _pair_labels(distributions)
        if not pairs:
            continue
        eligible.append(
            {
                "canonical_upstream_id": canonical,
                "selection_hash": deterministic_order(canonical, namespace),
                "distribution_count": len(distributions),
                "distributions": ";".join(sorted(distributions)),
                "eligible_cross_family_pairs": ";".join(pairs),
                "package_count": len(observations),
            }
        )
    eligible.sort(key=lambda row: (row["selection_hash"], row["canonical_upstream_id"]))
    return eligible, no_url


def select_cross_family_pilot(
    eligible: list[dict[str, Any]], pilot_size: int
) -> list[dict[str, Any]]:
    ordered = sorted(eligible, key=lambda row: (row["selection_hash"], row["canonical_upstream_id"]))
    return ordered[: min(pilot_size, len(ordered))]


def deduplicated_cross_family_sets(
    pair_sets: dict[tuple[str, str], dict[str, set[str]]]
) -> dict[str, set[str]]:
    return {
        key: set().union(*(pair_sets[pair][key] for pair in CROSS_FAMILY_PAIRS))
        for key in ("tier_a", "comparable", "differing")
    }


def c3x_membership(c1x: set[str], usable_provenance_lineages: set[str]) -> set[str]:
    return c1x & usable_provenance_lineages


def _bundle_hash(paths: Iterable[Path]) -> tuple[str, list[dict[str, Any]]]:
    records = [
        {"path": str(path.relative_to(ROOT)), "sha256": sha256_file(path), "bytes": path.stat().st_size}
        for path in sorted(set(paths))
    ]
    material = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(material).hexdigest(), records


def _verify_recorded_files(records: Iterable[dict[str, Any]], detail: list[dict[str, Any]]) -> None:
    for record in records:
        path_value = record.get("path") or record.get("local_path")
        digest = record.get("sha256") or record.get("observed_sha256")
        if not path_value or not digest:
            continue
        path = Path(path_value)
        observed = sha256_file(path) if path.is_file() else "MISSING"
        detail.append(
            {
                "path": str(path),
                "expected_sha256": digest,
                "observed_sha256": observed,
                "status": "PASS" if observed == digest else "FAIL",
            }
        )


def verify_frozen_inputs() -> dict[str, Any]:
    config = load_config()
    historical_config = read_json(ROOT / config["historical_config"])
    checks: list[dict[str, Any]] = []
    file_checks = (
        (ROOT / config["authoritative_protocol"], config["authoritative_protocol_sha256"], "authoritative_protocol_v4_2"),
        (HISTORICAL_REPORTS[0], config["historical_phase0_report_sha256"], "historical_phase0_report"),
        (HISTORICAL_REPORTS[1], config["historical_phase0_audit_report_sha256"], "historical_phase0_audit_report"),
        (Path(historical_config["evaluator"]["path"]), historical_config["evaluator"]["sha256"], "pinned_evaluator"),
        (ROOT / historical_config["evaluator"]["policy"], read_json(HISTORICAL / "execution_environment.json")["security_policy_hash"], "archived_security_policy"),
    )
    for path, expected, label in file_checks:
        observed = sha256_file(path) if path.is_file() else "MISSING"
        checks.append({"label": label, "path": str(path), "expected_sha256": expected, "observed_sha256": observed, "status": "PASS" if observed == expected else "FAIL"})

    runtime = read_json(HISTORICAL / "evaluator_runtime_manifest.json")
    _verify_recorded_files(runtime["files"], checks)
    repository_files: list[Path] = []
    for distribution in DISTRIBUTIONS:
        freeze_path = HISTORICAL / f"raw/repositories/{distribution}/freeze_records.json"
        repository_files.append(freeze_path)
        records = read_json(freeze_path)
        _verify_recorded_files(records, checks)
        repository_files.extend(Path(row["path"]) for row in records)

    for distribution in ("debian", "ubuntu"):
        release = (HISTORICAL / f"raw/repositories/{distribution}/Release").read_text(encoding="utf-8")
        for component in historical_config["repositories"][distribution]["components"]:
            relative = f"{component}/source/Sources.xz"
            expected = _release_hash(release, relative)
            if expected is None:
                continue
            path = HISTORICAL / "raw/repositories" / distribution / relative
            observed = sha256_file(path) if path.is_file() else "MISSING"
            checks.append({"label": f"{distribution}_frozen_source_index", "path": str(path), "expected_sha256": expected[0], "observed_sha256": observed, "status": "PASS" if observed == expected[0] else "FAIL"})
            repository_files.append(path)

    for manifest_name in ("raw/package_artifact_manifest.json", "raw/source_artifact_manifest.json", "raw/base_package_manifest.json"):
        manifest_path = HISTORICAL / manifest_name
        manifest = read_json(manifest_path)
        repository_files.append(manifest_path)
        if manifest_name.endswith("source_artifact_manifest.json"):
            _verify_recorded_files((item for row in manifest for item in row.get("files", [])), checks)
        else:
            _verify_recorded_files((row for row in manifest if row.get("fetch_status", "SUCCESS") == "SUCCESS"), checks)

    historical_determinism = read_json(HISTORICAL / "determinism_manifest.json")
    for relative, expected in historical_determinism["current_hashes"].items():
        path = HISTORICAL / relative
        observed = sha256_file(path) if path.is_file() else "MISSING"
        checks.append({"label": "historical_normalized_output", "path": str(path), "expected_sha256": expected, "observed_sha256": observed, "status": "PASS" if observed == expected else "FAIL"})

    input_paths = [
        ROOT / config["authoritative_protocol"],
        ROOT / config["historical_config"],
        CONFIG_PATH,
        ROOT / "config/security-policy.json",
        HISTORICAL_REPORTS[0],
        HISTORICAL_REPORTS[1],
        HISTORICAL / "normalized/repository_packages.csv",
        HISTORICAL / "normalized/repository_services.csv",
        HISTORICAL / "evaluator_runtime_manifest.json",
        HISTORICAL / "execution_environment.json",
        HISTORICAL / "determinism_manifest.json",
        ROOT / "src/unittrace/phase0x.py",
        ROOT / "src/unittrace/phase0_audit.py",
        ROOT / "src/unittrace/pipeline.py",
        ROOT / "src/unittrace/protocol.py",
        ROOT / "src/unittrace/sources.py",
        *repository_files,
    ]
    bundle, inputs = _bundle_hash(path for path in input_paths if path.exists())
    result = {
        "all_checks_pass": all(row["status"] == "PASS" for row in checks),
        "checks_total": len(checks),
        "checks_passed": sum(row["status"] == "PASS" for row in checks),
        "checks_failed": sum(row["status"] != "PASS" for row in checks),
        "repository_adapters_usable": {distribution: all(row["status"] == "PASS" for row in checks if f"/repositories/{distribution}/" in row["path"]) for distribution in DISTRIBUTIONS},
        "input_manifest_hash": bundle,
        "inputs": inputs,
        "verification_detail": checks,
        "repositories_refrozen": False,
    }
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    atomic_json(ARTIFACTS / "frozen_input_verification.json", result)
    atomic_json(ARTIFACTS / "input_manifest.json", {"input_manifest_hash": bundle, "inputs": inputs})
    if not result["all_checks_pass"]:
        failed = [row["path"] for row in checks if row["status"] != "PASS"]
        raise RuntimeError(f"frozen input verification failed: {failed[:10]}")
    return result


def prepare_selection() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    config = load_config()
    packages = read_csv(HISTORICAL / "normalized/repository_packages.csv")
    services = read_csv(HISTORICAL / "normalized/repository_services.csv")
    eligible, no_url = construct_eligible_population(packages, config["selection_namespace"])
    selected = select_cross_family_pilot(eligible, int(config["pilot_size"]))
    selected_ids = {row["canonical_upstream_id"] for row in selected}
    pilot_packages = [row for row in packages if row["canonical_upstream_id"] in selected_ids]
    write_csv(ARTIFACTS / "normalized/repository_packages.csv", packages, list(packages[0]))
    write_csv(ARTIFACTS / "normalized/repository_services.csv", services, list(services[0]))
    fields = ["canonical_upstream_id", "selection_hash", "distribution_count", "distributions", "eligible_cross_family_pairs", "package_count"]
    write_csv(ARTIFACTS / "normalized/eligible_population.csv", eligible, fields)
    write_csv(ARTIFACTS / "normalized/selected_projects.csv", selected, fields)
    write_csv(ARTIFACTS / "normalized/pilot_packages.csv", pilot_packages, list(packages[0]))
    write_csv(ARTIFACTS / "normalized/exclusions.csv", no_url, ["entity_type", "entity_id", "stage", "reason_code", "technical_detail"])
    manifest_path = ARTIFACTS / "normalized/sampling_manifest.json"
    prior = read_json(manifest_path) if manifest_path.exists() else {}
    selection_timestamp = prior.get("selection_timestamp_utc") or datetime.now(timezone.utc).isoformat()
    population_hash = sha256_file(ARTIFACTS / "normalized/eligible_population.csv")
    selected_hash = sha256_file(ARTIFACTS / "normalized/selected_projects.csv")
    pair_counts = {
        label: sum(label in row["eligible_cross_family_pairs"].split(";") for row in eligible)
        for _, _, label, family in PAIR_SPECS if family == "CROSS_FAMILY"
    }
    sampling = {
        "phase0_run_id": config["phase0_run_id"],
        "candidate_population": len(eligible),
        "selected_projects": len(selected),
        "intended_pilot_size": config["pilot_size"],
        "population_below_intended_size": len(eligible) < int(config["pilot_size"]),
        "namespace": config["selection_namespace"],
        "rule": "ascending sha256(namespace + NUL + canonical_upstream_id), then canonical_upstream_id",
        "selection_timestamp_utc": selection_timestamp,
        "eligible_population_sha256": population_hash,
        "selected_pilot_sha256": selected_hash,
        "eligibility_rule": "canonical upstream project has service-shipping package candidates in at least one preregistered cross-family distribution pair",
        "eligibility_metadata_fields": config["eligibility_metadata_fields"],
        "forbidden_eligibility_fields": config["forbidden_eligibility_fields"],
        "outcome_fields_used": [],
        "outcome_inspected_before_selection": False,
        "pair_coverage": pair_counts,
        "rq3d_status": "RQ3d_DISABLED",
    }
    atomic_json(manifest_path, sampling)
    return selected, pilot_packages


def _hardlink_or_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        return
    try:
        os.link(source, destination)
    except OSError:
        shutil.copy2(source, destination)


def _reuse_historical_cache(pilot_packages: list[dict[str, Any]]) -> None:
    old_manifest = read_json(HISTORICAL / "raw/package_artifact_manifest.json")
    by_hash = {
        row.get("observed_sha256"): Path(row["local_path"])
        for row in old_manifest
        if row.get("fetch_status") == "SUCCESS" and row.get("observed_sha256") and Path(row.get("local_path", "")).is_file()
    }
    for package in pilot_packages:
        expected = package.get("artifact_sha256", "")
        source = by_hash.get(expected)
        if source is None or sha256_file(source) != expected:
            continue
        extension = ".deb" if package["distribution"] in {"debian", "ubuntu"} else (".rpm" if package["distribution"] == "fedora" else ".pkg.tar.zst")
        destination = ARTIFACTS / "raw/packages" / package["distribution"] / f"{package['name']}-{package['version'].replace('/', '_')}{extension}"
        _hardlink_or_copy(source, destination)

    for relative in ("raw/packages/base", "raw/sources"):
        source_root = HISTORICAL / relative
        if not source_root.exists():
            continue
        for source in source_root.rglob("*"):
            if source.is_file():
                _hardlink_or_copy(source, ARTIFACTS / source.relative_to(HISTORICAL))


def acquire_packages(pilot_packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    _reuse_historical_cache(pilot_packages)
    return fetch_pilot_packages(pilot_packages, ARTIFACTS)


def _source_records(pilot_packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    historical_config = read_json(ROOT / load_config()["historical_config"])
    records = fetch_deb_sources(historical_config, pilot_packages, ARTIFACTS, frozen_repository_artifacts=HISTORICAL)
    records.extend(fetch_fedora_sources(historical_config, pilot_packages, ARTIFACTS, frozen_repository_artifacts=HISTORICAL))
    records.extend(fetch_arch_sources(historical_config, pilot_packages, ARTIFACTS))
    atomic_json(ARTIFACTS / "raw/source_artifact_manifest.json", records)
    return records


def _cohort_sets(
    lineage_index: dict[str, list[dict[str, str]]],
    states: list[dict[str, Any]],
    upstream: list[dict[str, Any]],
    pilot_packages: list[dict[str, Any]],
) -> dict[str, set[str]]:
    distributions = {lineage_id: {row["distribution"] for row in members} for lineage_id, members in lineage_index.items()}
    c1x = {lineage_id for lineage_id, observed in distributions.items() if any({left, right} <= observed for left, right in CROSS_FAMILY_PAIRS)}
    c1d = {lineage_id for lineage_id, observed in distributions.items() if {"debian", "ubuntu"} <= observed}
    c2 = {lineage_id for lineage_id, observed in distributions.items() if observed == set(DISTRIBUTIONS)}
    usable = {row["lineage_id"] for row in states if row["layer"] == "U" and row["dimension_provenance_status"] in RESOLVED_STATUSES}
    c3 = set(lineage_index) & usable
    c3x = c3x_membership(c1x, c3)
    schema_count = read_json(ARTIFACTS / "security_assessment_schema.json")["assessment_count"]
    resolved_counts = Counter(row["lineage_id"] for row in states if row["layer"] == "U" and row["dimension_provenance_status"] in RESOLVED_STATUSES)
    observation_counts = Counter(row["lineage_id"] for row in upstream)
    fully_rendered = {
        lineage_id for lineage_id in c3x
        if observation_counts[lineage_id] and resolved_counts[lineage_id] == observation_counts[lineage_id] * schema_count
    }
    package_index = {(row["distribution"], row["name"]): row for row in pilot_packages}
    c4: set[str] = set()
    for lineage_id in c1x:
        members = lineage_index[lineage_id]
        versions = {row["distribution"]: package_index[(row["distribution"], row["binary_package_id"])]["source_version"].split(":", 1)[-1] for row in members}
        if any({left, right} <= versions.keys() and versions[left] == versions[right] for left, right in CROSS_FAMILY_PAIRS):
            c4.add(lineage_id)
    return {"C1": set(lineage_index), "C1X": c1x, "C1D": c1d, "C2": c2, "C3": c3, "C3X": c3x, "C3F": fully_rendered, "C4": c4, "C5": set()}


def write_cohorts_x(lineage_index: dict[str, list[dict[str, str]]], cohorts: dict[str, set[str]]) -> None:
    rows: list[dict[str, Any]] = []
    for cohort, lineage_ids in cohorts.items():
        for lineage_id in sorted(lineage_ids):
            members = lineage_index[lineage_id]
            distributions = sorted({row["distribution"] for row in members})
            rows.append({"cohort": cohort, "lineage_id": lineage_id, "canonical_upstream_id": members[0]["canonical_upstream_id"], "distributions": ";".join(distributions), "distribution_count": len(distributions), "family_type": "CROSS_FAMILY" if cohort in {"C1X", "C3X", "C3F", "C4"} else ("DERIVATIVE_FAMILY" if cohort == "C1D" else "MIXED_OR_GENERAL")})
    write_csv(ARTIFACTS / "normalized/cohorts.csv", rows, ["cohort", "lineage_id", "canonical_upstream_id", "distributions", "distribution_count", "family_type"])


def matching_mode_distribution(
    lineage_index: dict[str, list[dict[str, str]]], cohort: set[str], cohort_name: str
) -> list[dict[str, Any]]:
    projects = {lineage_id: members[0]["canonical_upstream_id"] for lineage_id, members in lineage_index.items()}
    rows: list[dict[str, Any]] = []
    for mode in MATCH_MODES:
        ids = {lineage_id for lineage_id in cohort if {row["lineage_match_mode"] for row in lineage_index[lineage_id]} == {mode}}
        rows.append({"cohort": cohort_name, "match_mode": mode, "projects": len({projects[lineage_id] for lineage_id in ids}), "lineages": len(ids), "percentage": ratio(len(ids), len(cohort)) or 0.0})
    return rows


def u1_sensitivity(
    c3x: set[str], lineage_index: dict[str, list[dict[str, str]]], upstream: list[dict[str, Any]], states: list[dict[str, Any]]
) -> dict[str, int]:
    usable_observations = {(row["lineage_id"], row["distribution"]) for row in states if row["layer"] == "U" and row["dimension_provenance_status"] in RESOLVED_STATUSES and row["lineage_id"] in c3x}
    classes: dict[str, set[str]] = defaultdict(set)
    for row in upstream:
        if (row["lineage_id"], row["distribution"]) in usable_observations:
            classes[row["canonical_upstream_id"]].add(row["u_artifact_class"])
    all_projects = {lineage_index[lineage_id][0]["canonical_upstream_id"] for lineage_id in c3x}
    u1_only = {project for project, values in classes.items() if values == {UArtifactClass.U1_TEMPLATE_VALUE_ONLY.value}}
    without_u1_only = all_projects - u1_only
    return {"c3x_projects_exclusively_dependent_on_U1": len(u1_only), "c3x_projects_if_U1_only_projects_excluded": len(without_u1_only)}


def _per_dimension_retention(c1x: set[str], upstream: list[dict[str, Any]], states: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int, int]:
    assessment_ids = [row.get("json_field") or row.get("name") for row in read_json(ARTIFACTS / "security_assessment_schema.json")["assessments"]]
    candidate_observations = [row for row in upstream if row["lineage_id"] in c1x]
    resolved = Counter(row["assessment_id"] for row in states if row["layer"] == "U" and row["lineage_id"] in c1x and row["dimension_provenance_status"] in RESOLVED_STATUSES)
    rows = [{"assessment_id": assessment, "candidate_observations": len(candidate_observations), "resolved_observations": resolved[assessment], "retention": ratio(resolved[assessment], len(candidate_observations)) or 0.0} for assessment in sorted(assessment_ids)]
    return rows, len(candidate_observations) * len(assessment_ids), sum(resolved.values())


def _matching_invariant_audit(lineage_index: dict[str, list[dict[str, str]]], lineages: list[dict[str, str]], units: list[dict[str, str]]) -> dict[str, Any]:
    audit = audit_matching_invariants(lineage_index, lineages, units)
    source = inspect.getsource(run_scientific_pass)
    extra_checks = {
        "phase0x_matching_precedes_policy_analysis": source.index("match_lineages(") < source.index("analyze_states("),
        "phase0x_selection_precedes_policy_analysis": source.index("prepare_selection(") < source.index("analyze_states("),
        "phase0x_matching_consumes_no_policy_outcomes": (
            len(inspect.signature(match_lineages).parameters) == 4
            and "policy_states" not in inspect.getsource(match_lineages)
            and "transformations" not in inspect.getsource(match_lineages)
        ),
    }
    audit["code_checks"].update(extra_checks)
    audit["code_violation_types"] = sorted(name for name, passed in audit["code_checks"].items() if not passed)
    audit["blocking_violation"] = bool(audit["lineages_violating_invariants"] or audit["code_violation_types"])
    atomic_json(ARTIFACTS / "tier_a_invariant_audit.json", audit)
    return audit


def _write_exclusions(manifest: list[dict[str, Any]], lineages: list[dict[str, Any]], units: list[dict[str, Any]], states: list[dict[str, Any]], upstream: list[dict[str, Any]]) -> list[dict[str, Any]]:
    existing = read_csv(ARTIFACTS / "normalized/exclusions.csv")
    rows: list[dict[str, Any]] = list(existing)
    for record in manifest:
        if record.get("fetch_status") != "SUCCESS":
            rows.append({"entity_type": "package", "entity_id": f"{record['distribution']}:{record['name']}", "stage": "artifact_fetch", "reason_code": "ARTIFACT_FETCH_FAILURE", "technical_detail": record.get("failure", "")})
        elif record.get("extract_status") != "SUCCESS":
            rows.append({"entity_type": "package", "entity_id": f"{record['distribution']}:{record['name']}", "stage": "artifact_extraction", "reason_code": "ARTIFACT_EXTRACTION_FAILURE", "technical_detail": record.get("failure", "")})
    for row in lineages:
        if row["match_status"] == "SERVICE_LINEAGE_AMBIGUOUS":
            rows.append({"entity_type": "service_lineage", "entity_id": f"{row['distribution']}:{row['lineage_id']}", "stage": "tier_a_matching", "reason_code": "SERVICE_LINEAGE_AMBIGUOUS", "technical_detail": f"candidate_count={row['candidate_count']}"})
    matched_members = {(row["distribution"], row["binary_package_id"], row["unit_path"]) for row in lineages if row["match_status"] == "MATCHED"}
    for unit in units:
        key = (unit["distribution"], unit["binary_package_id"], unit["unit_path"])
        if key in matched_members:
            continue
        reason = "MASKED_EFFECTIVE_UNIT" if unit["mask_state"] == "MASKED_EFFECTIVE_UNIT" else ("DUPLICATE_ALIAS" if unit["canonical_target"] != unit["unit_path"] else "NO_TIER_A_PARTNER")
        rows.append({"entity_type": "service_unit", "entity_id": ":".join(key), "stage": "tier_a_matching", "reason_code": reason, "technical_detail": unit["canonical_target"]})
    failures: set[tuple[str, str, str]] = set()
    for state in states:
        if state["analysis_status"] == "ANALYZER_FAILURE":
            key = (state["lineage_id"], state["distribution"], state["layer"])
            if key not in failures:
                rows.append({"entity_type": "policy_state", "entity_id": ":".join(key), "stage": "semantic_evaluation", "reason_code": "ANALYZER_FAILURE", "technical_detail": state["description_normalized"]})
                failures.add(key)
    for item in upstream:
        reason = None
        if item["u_artifact_class"] == UArtifactClass.U4_NO_UPSTREAM_STATIC_OR_TEMPLATE_UNIT.value:
            reason = "U4_NO_UPSTREAM_UNIT"
        elif item["u_artifact_class"] == UArtifactClass.U5_AMBIGUOUS_OR_UNRESOLVED.value:
            reason = "U5_AMBIGUOUS_OR_UNRESOLVED"
        if reason:
            rows.append({"entity_type": "upstream_artifact", "entity_id": f"{item['distribution']}:{item['lineage_id']}", "stage": "upstream_recovery", "reason_code": reason, "technical_detail": item["resolution_detail"]})
    unique = {(row["entity_type"], row["entity_id"], row["stage"], row["reason_code"], row["technical_detail"]): row for row in rows}
    result = [unique[key] for key in sorted(unique)]
    write_csv(ARTIFACTS / "normalized/exclusions.csv", result, ["entity_type", "entity_id", "stage", "reason_code", "technical_detail"])
    return result


def _attrition_tables(exclusions: list[dict[str, Any]], packages: list[dict[str, Any]], units: list[dict[str, Any]], upstream: list[dict[str, Any]], states: list[dict[str, Any]], pair_profiles: list[dict[str, Any]], lineages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    reasons = ("NO_AUTHORITATIVE_UPSTREAM_URL", "NO_TIER_A_PARTNER", "SERVICE_LINEAGE_AMBIGUOUS", "U4_NO_UPSTREAM_UNIT", "U5_AMBIGUOUS_OR_UNRESOLVED", "ANALYZER_FAILURE")
    counts: Counter[tuple[str, str]] = Counter()
    for row in exclusions:
        distribution = row["entity_id"].split(":", 1)[0]
        if distribution in DISTRIBUTIONS and row["reason_code"] in reasons:
            counts[(distribution, row["reason_code"])] += 1
    state_denominator = Counter((row["distribution"], row["lineage_id"], row["layer"]) for row in states if row["layer"] in {"P", "E"})
    distribution_rows: list[dict[str, Any]] = []
    for distribution in DISTRIBUTIONS:
        denominators = {
            "NO_AUTHORITATIVE_UPSTREAM_URL": sum(row["distribution"] == distribution for row in packages),
            "NO_TIER_A_PARTNER": sum(row["distribution"] == distribution for row in units),
            "SERVICE_LINEAGE_AMBIGUOUS": sum(row["distribution"] == distribution for row in units),
            "U4_NO_UPSTREAM_UNIT": sum(row["distribution"] == distribution for row in upstream),
            "U5_AMBIGUOUS_OR_UNRESOLVED": sum(row["distribution"] == distribution for row in upstream),
            "ANALYZER_FAILURE": sum(key[0] == distribution for key in state_denominator),
        }
        for reason in reasons:
            count = counts[(distribution, reason)]
            distribution_rows.append({"distribution": distribution, "stage": {"NO_AUTHORITATIVE_UPSTREAM_URL": "cross_family_eligibility", "NO_TIER_A_PARTNER": "tier_a_matching", "SERVICE_LINEAGE_AMBIGUOUS": "tier_a_matching", "U4_NO_UPSTREAM_UNIT": "upstream_recovery", "U5_AMBIGUOUS_OR_UNRESOLVED": "upstream_recovery", "ANALYZER_FAILURE": "semantic_evaluation"}[reason], "reason_code": reason, "stage_denominator": denominators[reason], "count": count, "rate": ratio(count, denominators[reason]) or 0.0})
    lineage_groups: dict[str, set[str]] = defaultdict(set)
    for row in lineages:
        lineage_groups[row["lineage_id"]].add(row["distribution"])
    class_index = {(row["lineage_id"], row["distribution"]): row["u_artifact_class"] for row in upstream}
    analyzer_failures = {(row["lineage_id"], row["distribution"]) for row in states if row["layer"] == "E" and row["analysis_status"] == "ANALYZER_FAILURE"}
    pair_rows: list[dict[str, Any]] = []
    profile_index = {row["pair"]: row for row in pair_profiles}
    for left, right, label, family in PAIR_SPECS:
        profile = profile_index[label]
        pair_lineages = {lineage_id for lineage_id, observed in lineage_groups.items() if {left, right} <= observed and any(row["lineage_id"] == lineage_id and row["match_status"] == "MATCHED" for row in lineages)}
        ambiguous = {lineage_id for lineage_id, observed in lineage_groups.items() if {left, right} <= observed and any(row["lineage_id"] == lineage_id and row["match_status"] == "SERVICE_LINEAGE_AMBIGUOUS" for row in lineages)}
        values = {
            "SERVICE_LINEAGE_AMBIGUOUS": (len(ambiguous), len(ambiguous) + profile["tier_a_lineages"]),
            "U4_NO_UPSTREAM_UNIT": (sum(any(class_index.get((lineage_id, distribution)) == UArtifactClass.U4_NO_UPSTREAM_STATIC_OR_TEMPLATE_UNIT.value for distribution in (left, right)) for lineage_id in pair_lineages), len(pair_lineages)),
            "U5_AMBIGUOUS_OR_UNRESOLVED": (sum(any(class_index.get((lineage_id, distribution)) == UArtifactClass.U5_AMBIGUOUS_OR_UNRESOLVED.value for distribution in (left, right)) for lineage_id in pair_lineages), len(pair_lineages)),
            "ANALYZER_FAILURE": (sum(any((lineage_id, distribution) in analyzer_failures for distribution in (left, right)) for lineage_id in pair_lineages), len(pair_lineages)),
        }
        for reason, (count, denominator) in values.items():
            pair_rows.append({"pair": label, "family_type": family, "reason_code": reason, "stage_denominator": denominator, "count": count, "rate": ratio(count, denominator) or 0.0})
    write_csv(ARTIFACTS / "attrition_by_distribution.csv", distribution_rows, ["distribution", "stage", "reason_code", "stage_denominator", "count", "rate"])
    write_csv(ARTIFACTS / "attrition_by_pair.csv", pair_rows, ["pair", "family_type", "reason_code", "stage_denominator", "count", "rate"])
    return distribution_rows, pair_rows


def calculate_phase0x_gates(metrics: dict[str, Any], thresholds: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    statuses = {
        "P0R-A-X": metrics["repository_integrity"] and metrics["artifact_rate"] >= thresholds["artifact_rate"],
        "P0R-B-X": metrics["analyzable_rate"] >= thresholds["analyzable_rate"] and metrics["fixtures_pass"],
        "P0R-CX": metrics["cross_family_projects"] >= thresholds["cross_family_projects"] and metrics["cross_family_tier_a_lineages"] >= thresholds["cross_family_tier_a_lineages"],
        "P0R-EX": metrics["c3x_projects"] >= thresholds["c3x_projects"] and metrics["provenance_retention"] >= thresholds["provenance_retention"],
        "P0R-FX": metrics["cross_family_differing_lineages"] >= thresholds["differing_lineages"] or metrics["cross_family_divergence_rate"] >= thresholds["divergence_rate"] or metrics["cross_family_transformed_u_p_lineages"] >= thresholds["transformed_lineages"],
    }
    rows = [
        {"gate": "P0R-A-X", "metric": "pilot_artifact_reproducibility", "numerator": metrics["artifacts_ok"], "denominator": metrics["artifacts_total"], "value": metrics["artifact_rate"], "threshold": ">=0.95 and 4/4 frozen adapters", "status": "PASS" if statuses["P0R-A-X"] else "FAIL"},
        {"gate": "P0R-B-X", "metric": "analyzable_or_classified_states", "numerator": metrics["states_analyzable"], "denominator": metrics["states_total"], "value": metrics["analyzable_rate"], "threshold": ">=0.90 and 6/6 fixtures", "status": "PASS" if statuses["P0R-B-X"] else "FAIL"},
        {"gate": "P0R-CX", "metric": "cross_family_projects", "numerator": metrics["cross_family_projects"], "denominator": metrics["selected_pilot_size"], "value": metrics["cross_family_projects"], "threshold": ">=30", "status": "PASS" if statuses["P0R-CX"] else "FAIL"},
        {"gate": "P0R-CX", "metric": "cross_family_tier_a_lineages", "numerator": metrics["cross_family_tier_a_lineages"], "denominator": metrics["tier_a_lineages"], "value": metrics["cross_family_tier_a_lineages"], "threshold": ">=40", "status": "PASS" if statuses["P0R-CX"] else "FAIL"},
        {"gate": "P0R-D-X", "metric": "complete_four_way_support_descriptive", "numerator": metrics["four_way_projects"], "denominator": metrics["four_way_lineages"], "value": metrics["four_way_projects"], "threshold": "none (non-blocking)", "status": "DESCRIPTIVE"},
        {"gate": "P0R-EX", "metric": "c3x_projects", "numerator": metrics["c3x_projects"], "denominator": metrics["cross_family_projects"], "value": metrics["c3x_projects"], "threshold": ">=30", "status": "PASS" if statuses["P0R-EX"] else "FAIL"},
        {"gate": "P0R-EX", "metric": "usable_cross_family_provenance_lineages", "numerator": metrics["usable_cross_family_provenance_lineages"], "denominator": metrics["cross_family_c3_candidate_lineages"], "value": metrics["provenance_retention"], "threshold": ">=0.50", "status": "PASS" if statuses["P0R-EX"] else "FAIL"},
        {"gate": "P0R-FX", "metric": "differing_cross_family_lineages", "numerator": metrics["cross_family_differing_lineages"], "denominator": metrics["cross_family_comparable_lineages"], "value": metrics["cross_family_differing_lineages"], "threshold": ">=25", "status": "PASS" if metrics["cross_family_differing_lineages"] >= thresholds["differing_lineages"] else "FAIL"},
        {"gate": "P0R-FX", "metric": "cross_family_divergence_rate", "numerator": metrics["cross_family_differing_lineages"], "denominator": metrics["cross_family_comparable_lineages"], "value": metrics["cross_family_divergence_rate"], "threshold": ">=0.10", "status": "PASS" if metrics["cross_family_divergence_rate"] >= thresholds["divergence_rate"] else "FAIL"},
        {"gate": "P0R-FX", "metric": "cross_family_u_p_transformed_lineages", "numerator": metrics["cross_family_transformed_u_p_lineages"], "denominator": metrics["usable_cross_family_provenance_lineages"], "value": metrics["cross_family_transformed_u_p_lineages"], "threshold": ">=25", "status": "PASS" if metrics["cross_family_transformed_u_p_lineages"] >= thresholds["transformed_lineages"] else "FAIL"},
    ]
    if not statuses["P0R-CX"] or not statuses["P0R-EX"] or not statuses["P0R-FX"]:
        decision = "STOP"
    elif not statuses["P0R-A-X"] or not statuses["P0R-B-X"]:
        decision = "REDESIGN_REQUIRED"
    elif metrics["tier_a_blocking_violation"] or not metrics.get("determinism_pass", True):
        decision = "STOP"
    else:
        decision = "CONFIRMED_GO"
    return rows, decision


def _summarize(manifest: list[dict[str, Any]], lineages: list[dict[str, Any]], units: list[dict[str, Any]], states: list[dict[str, Any]], upstream: list[dict[str, Any]], transformations: list[dict[str, Any]], fixtures_pass: bool, pilot_packages: list[dict[str, Any]]) -> dict[str, Any]:
    config = load_config()
    verification = read_json(ARTIFACTS / "frozen_input_verification.json")
    lineage_index = matched_lineage_index(lineages)
    cohorts = _cohort_sets(lineage_index, states, upstream, pilot_packages)
    write_cohorts_x(lineage_index, cohorts)
    effective = effective_state_index(states)
    profiles, pair_sets = compute_pair_profiles(lineage_index, effective, cohorts["C3"])
    for profile in profiles:
        profile["family_type"] = pair_family_type(profile["left_distribution"], profile["right_distribution"])
        profile["comparable"] = profile.pop("comparable_lineages")
        profile["differing"] = profile.pop("differing_lineages")
        profile["divergence"] = profile.pop("divergence_rate")
    write_csv(ARTIFACTS / "normalized/pairwise_support.csv", profiles, ["pair", "left_distribution", "right_distribution", "family_type", "projects", "tier_a_lineages", "comparable", "differing", "divergence", "c3_lineages", "comparable_dimensions"])
    cross_sets = deduplicated_cross_family_sets(pair_sets)
    comparable = cross_sets["comparable"]
    differing = cross_sets["differing"]
    transformed = {row["lineage_id"] for row in transformations if row["transition"] == "U_P" and row["semantic_category"] != "UNCHANGED" and row["source_resolved"] is True and row["destination_resolved"] is True} & cohorts["C3X"]
    project_by_lineage = {lineage_id: members[0]["canonical_upstream_id"] for lineage_id, members in lineage_index.items()}
    state_status = {(row["lineage_id"], row["distribution"], row["layer"]): row["analysis_status"] for row in states if row["layer"] in {"P", "E"}}
    per_dimension, candidate_dimensions, resolved_dimensions = _per_dimension_retention(cohorts["C1X"], upstream, states)
    write_csv(ARTIFACTS / "normalized/per_dimension_retention.csv", per_dimension, ["assessment_id", "candidate_observations", "resolved_observations", "retention"])
    sensitivity = u1_sensitivity(cohorts["C3X"], lineage_index, upstream, states)
    u_rows = [row for row in upstream if row["lineage_id"] in cohorts["C3X"]]
    u_counts = Counter(row["u_artifact_class"] for row in u_rows)
    mode_rows = []
    mode_rows.extend(matching_mode_distribution(lineage_index, cohorts["C1"], "WHOLE_PILOT"))
    mode_rows.extend(matching_mode_distribution(lineage_index, cohorts["C1X"], "C1X"))
    mode_rows.extend(matching_mode_distribution(lineage_index, cohorts["C3X"], "C3X"))
    write_csv(ARTIFACTS / "normalized/matching_modes.csv", mode_rows, ["cohort", "match_mode", "projects", "lineages", "percentage"])
    invariant = _matching_invariant_audit(lineage_index, lineages, units)
    exclusions = _write_exclusions(manifest, lineages, units, states, upstream)
    all_packages = read_csv(HISTORICAL / "normalized/repository_packages.csv")
    distribution_attrition, pair_attrition = _attrition_tables(exclusions, all_packages, units, upstream, states, profiles, lineages)
    sampling = read_json(ARTIFACTS / "normalized/sampling_manifest.json")
    metrics: dict[str, Any] = {
        "cross_family_eligible_population": sampling["candidate_population"],
        "selected_pilot_size": sampling["selected_projects"],
        "repository_integrity": verification["all_checks_pass"] and all(verification["repository_adapters_usable"].values()),
        "artifacts_ok": sum(row.get("fetch_status") == "SUCCESS" and row.get("extract_status") == "SUCCESS" for row in manifest),
        "artifacts_total": len(manifest),
        "states_analyzable": sum(status in {"ANALYZABLE", "MASKED_EFFECTIVE_UNIT", "NOT_APPLICABLE"} for status in state_status.values()),
        "states_total": len(state_status),
        "fixtures_pass": fixtures_pass,
        "fixtures_passed": 6 if fixtures_pass else 0,
        "fixtures_total": 6,
        "tier_a_projects": len({row["canonical_upstream_id"] for row in lineages if row["match_status"] == "MATCHED"}),
        "tier_a_lineages": len(cohorts["C1"]),
        "cross_family_projects": len({project_by_lineage[lineage_id] for lineage_id in cohorts["C1X"]}),
        "cross_family_tier_a_lineages": len(cohorts["C1X"]),
        "cross_family_comparable_lineages": len(comparable),
        "cross_family_differing_lineages": len(differing),
        "four_way_projects": len({project_by_lineage[lineage_id] for lineage_id in cohorts["C2"]}),
        "four_way_lineages": len(cohorts["C2"]),
        "c3_projects": len({project_by_lineage[lineage_id] for lineage_id in cohorts["C3"]}),
        "c3_lineages": len(cohorts["C3"]),
        "c3x_projects": len({project_by_lineage[lineage_id] for lineage_id in cohorts["C3X"]}),
        "c3x_lineages": len(cohorts["C3X"]),
        "cross_family_c3_candidate_lineages": len(cohorts["C1X"]),
        "usable_cross_family_provenance_lineages": len(cohorts["C3X"]),
        "candidate_dimensions": candidate_dimensions,
        "resolved_candidate_dimensions": resolved_dimensions,
        "per_dimension_retention": per_dimension,
        "cross_family_transformed_u_p_lineages": len(transformed),
        "tier_a_lineages_audited": invariant["lineages_audited"],
        "tier_a_lineages_passing": invariant["lineages_passing_invariants"],
        "tier_a_violation_types": invariant["violation_type_counts"],
        "tier_a_blocking_violation": invariant["blocking_violation"],
        "matching_modes": mode_rows,
        "u_counts": {artifact_class: u_counts[artifact_class] for artifact_class in PROVENANCE_CLASSES},
        "u_rates": {artifact_class: ratio(u_counts[artifact_class], len(u_rows)) or 0.0 for artifact_class in PROVENANCE_CLASSES},
        "u_observations_in_c3x": len(u_rows),
        "input_manifest_hash": verification["input_manifest_hash"],
        "selected_pilot_hash": sampling["selected_pilot_sha256"],
        "rq3d_status": "RQ3d_DISABLED",
        **sensitivity,
    }
    metrics["artifact_rate"] = ratio(metrics["artifacts_ok"], metrics["artifacts_total"]) or 0.0
    metrics["analyzable_rate"] = ratio(metrics["states_analyzable"], metrics["states_total"]) or 0.0
    metrics["provenance_retention"] = ratio(metrics["usable_cross_family_provenance_lineages"], metrics["cross_family_c3_candidate_lineages"]) or 0.0
    metrics["cross_family_divergence_rate"] = ratio(metrics["cross_family_differing_lineages"], metrics["cross_family_comparable_lineages"]) or 0.0
    gate_rows, decision = calculate_phase0x_gates(metrics, config["thresholds"])
    metrics["gate_statuses"] = {gate: ("PASS" if all(row["status"] == "PASS" for row in gate_rows if row["gate"] == gate) else "FAIL") for gate in ("P0R-A-X", "P0R-B-X", "P0R-CX", "P0R-EX")}
    metrics["gate_statuses"]["P0R-D-X"] = "DESCRIPTIVE"
    metrics["gate_statuses"]["P0R-FX"] = "PASS" if any(row["status"] == "PASS" for row in gate_rows if row["gate"] == "P0R-FX") else "FAIL"
    metrics["decision_before_determinism"] = decision
    atomic_json(ARTIFACTS / "normalized/metrics.json", metrics)
    write_csv(ARTIFACTS / "normalized/gate_results.csv", gate_rows, ["gate", "metric", "numerator", "denominator", "value", "threshold", "status"])
    return {"metrics": metrics, "gates": gate_rows, "pair_profiles": profiles, "distribution_attrition": distribution_attrition, "pair_attrition": pair_attrition, "invariant": invariant}


def run_scientific_pass() -> dict[str, Any]:
    _, pilot_packages = prepare_selection()
    config = read_json(ROOT / load_config()["historical_config"])
    evaluator = Path(config["evaluator"]["path"])
    policy = ROOT / config["evaluator"]["policy"]
    fixture_results = run_semantic_fixtures(evaluator, policy, ARTIFACTS)
    fetch_manifest = read_json(ARTIFACTS / "raw/package_artifact_manifest.json")
    manifest, units = extract_pilot_packages(fetch_manifest, ARTIFACTS)
    source_records = _source_records(pilot_packages)
    inventories = extract_pristine_sources(source_records, ARTIFACTS)
    lineages = match_lineages(units, ARTIFACTS, inventories, pilot_packages)
    prepare_distribution_bases(read_csv(ARTIFACTS / "normalized/repository_packages.csv"), ARTIFACTS)
    states = analyze_states(lineages, units, evaluator, policy, ARTIFACTS)
    upstream = resolve_upstream_artifacts(lineages, inventories, ARTIFACTS)
    states, upstream_transformations = evaluate_upstream(upstream, states, evaluator, policy, ARTIFACTS)
    transformations = cross_distribution_transformations(states, ARTIFACTS) + upstream_transformations
    write_csv(ARTIFACTS / "normalized/transformations.csv", transformations, ["lineage_id", "distribution", "transition", "assessment_id", "semantic_category", "provenance_category", "exposure_delta", "source_resolved", "destination_resolved"])
    return _summarize(manifest, lineages, units, states, upstream, transformations, bool(fixture_results["all_pass"]), pilot_packages)


def _normalized_hashes() -> dict[str, str]:
    return {path: sha256_file(ARTIFACTS / path) for path in NORMALIZED_TARGETS}


def _percent(value: float | None) -> str:
    return "NA" if value is None else f"{100 * value:.1f}%"


def _render_table(headers: list[str], aligns: list[str], rows: Iterable[Iterable[Any]]) -> str:
    return "\n".join(["| " + " | ".join(headers) + " |", "| " + " | ".join(aligns) + " |", *("| " + " | ".join(str(value) for value in row) + " |" for row in rows)])


def write_report(result: dict[str, Any], determinism: dict[str, Any]) -> str:
    metrics = result["metrics"]
    profiles = result["pair_profiles"]
    verification = read_json(ARTIFACTS / "frozen_input_verification.json")
    sampling = read_json(ARTIFACTS / "normalized/sampling_manifest.json")
    environment = read_json(HISTORICAL / "execution_environment.json")
    historical_config = read_json(ROOT / load_config()["historical_config"])
    gates = result["gates"]
    metrics["determinism_pass"] = determinism["byte_equivalent_normalized_outputs"]
    _, final_decision = calculate_phase0x_gates(metrics, load_config()["thresholds"])
    metrics["final_decision"] = final_decision
    metrics["normalized_output_hash"] = determinism["normalized_output_hash"]
    atomic_json(ARTIFACTS / "phase0x_result.json", metrics)
    pair_table = _render_table(
        ["Pair", "Family type", "Projects", "Tier-A lineages", "Comparable", "Differing", "Divergence"],
        ["----", "-----------", "-------:", "--------------:", "---------:", "--------:", "---------:"],
        ([row["pair"], row["family_type"], row["projects"], row["tier_a_lineages"], row["comparable"], row["differing"], _percent(row["divergence"])] for row in profiles),
    )
    gate_table = _render_table(
        ["Gate", "Metric", "Numerator", "Denominator", "Value", "Threshold", "Status"],
        ["---", "---", "---:", "---:", "---:", "---", "---"],
        ([row["gate"], row["metric"], row["numerator"], row["denominator"], f"{row['value']:.4f}" if isinstance(row["value"], float) else row["value"], row["threshold"], row["status"]] for row in gates),
    )
    mode_table = _render_table(
        ["Cohort", "Match mode", "Projects", "Lineages", "Percentage"],
        ["---", "---", "---:", "---:", "---:"],
        ([row["cohort"], row["match_mode"], row["projects"], row["lineages"], _percent(row["percentage"])] for row in metrics["matching_modes"]),
    )
    u_table = _render_table(
        ["U class", "Count", "Rate"], ["---", "---:", "---:"],
        ([artifact_class, metrics["u_counts"][artifact_class], _percent(metrics["u_rates"][artifact_class])] for artifact_class in PROVENANCE_CLASSES),
    )
    dimension_table = _render_table(
        ["Assessment", "Candidate observations", "Resolved", "Retention"], ["---", "---:", "---:", "---:"],
        ([row["assessment_id"], row["candidate_observations"], row["resolved_observations"], _percent(row["retention"])] for row in metrics["per_dimension_retention"]),
    )
    attrition_distribution = _render_table(
        ["Distribution", "Stage", "Reason", "Denominator", "Count", "Rate"], ["---", "---", "---", "---:", "---:", "---:"],
        ([row["distribution"], row["stage"], row["reason_code"], row["stage_denominator"], row["count"], _percent(row["rate"])] for row in result["distribution_attrition"]),
    )
    attrition_pair = _render_table(
        ["Pair", "Family type", "Reason", "Denominator", "Count", "Rate"], ["---", "---", "---", "---:", "---:", "---:"],
        ([row["pair"], row["family_type"], row["reason_code"], row["stage_denominator"], row["count"], _percent(row["rate"])] for row in result["pair_attrition"]),
    )
    text = f"""# UnitTrace Phase 0R-X Report

## A. Historical context

- Original Phase 0R decision: `GO` under v4.1.
- Post–Phase 0R audit decision: `REDESIGN_REQUIRED`.
- UnitTrace v4.2 prospectively defines this Phase 0R-X cross-family rerun. The immutable historical records are `PHASE0_REPORT.md` and `PHASE0_AUDIT_REPORT.md`; their SHA-256 hashes passed verification.

## B. Frozen environment

- Debian: `{historical_config['repositories']['debian']['release']}`, suite `{historical_config['repositories']['debian']['suite']}`, amd64.
- Ubuntu: `{historical_config['repositories']['ubuntu']['release']}`, suite `{historical_config['repositories']['ubuntu']['suite']}`, amd64.
- Fedora: release `{historical_config['repositories']['fedora']['release']}` release/updates state, x86_64.
- Arch: `{historical_config['repositories']['arch']['release']}`, x86_64.
- Evaluator: `{environment['evaluator_version']}`; SHA-256 `{environment['evaluator_digest']}`; runtime bundle `{environment['evaluator_bundle_digest']}`.
- Policy SHA-256: `{environment['security_policy_hash']}`.
- Execution environment: `{environment['vm_os_release']}`, kernel `{environment['kernel_version']}`, `{environment['vm_architecture']}`, virtualization `{environment['virtualization_mode']}`, Python `{platform.python_version()}`.
- Frozen-input checks: {verification['checks_passed']}/{verification['checks_total']} passed. All four repository adapters remained usable. Repositories were **not refrozen**.

## C. Cross-family eligibility population

- Total eligible projects: **{metrics['cross_family_eligible_population']}**.
- Rule: {sampling['eligibility_rule']}.
- Pair coverage: `{json.dumps(sampling['pair_coverage'], sort_keys=True)}`.
- Eligibility consumed only the archived repository/package/service provenance metadata fields `{', '.join(sampling['eligibility_metadata_fields'])}`. `outcome_fields_used` is the empty list; systemd values, exposure, divergence, and transformations were not read.

## D. Deterministic pilot selection

- Namespace: `{sampling['namespace']}`.
- Population size: {sampling['candidate_population']}.
- Pilot size: {sampling['selected_projects']} (intended size {sampling['intended_pilot_size']}).
- Algorithm: `{sampling['rule']}`.
- Selection timestamp: `{sampling['selection_timestamp_utc']}`.
- Eligible-population SHA-256: `{sampling['eligible_population_sha256']}`.
- Selected-project manifest SHA-256: `{sampling['selected_pilot_sha256']}`.

## E. Artifact integrity

P0R-A-X: **{metrics['gate_statuses']['P0R-A-X']}**. Reproducibly fetched/extracted artifacts: {metrics['artifacts_ok']}/{metrics['artifacts_total']} ({_percent(metrics['artifact_rate'])}); frozen adapters: 4/4. Reused cache entries were accepted only after SHA-256 agreement, and new entries were hashed in `artifacts/phase0x/raw/package_artifact_manifest.json`.

## F. Analyzer integrity

P0R-B-X: **{metrics['gate_statuses']['P0R-B-X']}**. Analyzable/deterministically classified P/E states: {metrics['states_analyzable']}/{metrics['states_total']} ({_percent(metrics['analyzable_rate'])}). Mandatory fixtures: {metrics['fixtures_passed']}/{metrics['fixtures_total']}; drop-in precedence, reset semantics, aliases, masked units, type-wide `service.d`, and effective configuration loading all remained mandatory. Raw output is under `artifacts/phase0x/raw/evaluator/`.

## G. Pairwise support

{pair_table}

Debian ↔ Ubuntu is retained as `DERIVATIVE_FAMILY` and is excluded from every blocking cross-family numerator. Divergence values are pilot feasibility signals, not ecosystem effect estimates.

## H. C1X cross-family aggregate

- Projects: **{metrics['cross_family_projects']}**.
- Tier-A lineages: **{metrics['cross_family_tier_a_lineages']}**.
- Comparable lineages: **{metrics['cross_family_comparable_lineages']}**.
- Differing lineages: **{metrics['cross_family_differing_lineages']}**.

## I. P0R-CX

P0R-CX: **{metrics['gate_statuses']['P0R-CX']}**. Observed {metrics['cross_family_projects']} projects (threshold ≥30) and {metrics['cross_family_tier_a_lineages']} deduplicated Tier-A lineages (threshold ≥40). Pair counts were not summed to form the union.

## J. P0R-D-X

Complete Debian–Ubuntu–Fedora–Arch support: **{metrics['four_way_projects']} projects / {metrics['four_way_lineages']} Tier-A lineages**. This is descriptive and non-blocking under v4.2.

## K. C3X provenance

- C3X: **{metrics['c3x_projects']} projects / {metrics['c3x_lineages']} lineages**.
- General C3: {metrics['c3_projects']} projects / {metrics['c3_lineages']} lineages (descriptive only).
- Cross-family candidate dimensions: {metrics['candidate_dimensions']}; resolved candidate dimensions: {metrics['resolved_candidate_dimensions']}.
- `c3x_projects_exclusively_dependent_on_U1 = {metrics['c3x_projects_exclusively_dependent_on_U1']}`.
- `c3x_projects_if_U1_only_projects_excluded = {metrics['c3x_projects_if_U1_only_projects_excluded']}`.

{u_table}

Validated U1 observations remain in the primary cohort. No unresolved dimension was imputed.

### Per-dimension retention

{dimension_table}

## L. P0R-EX

P0R-EX: **{metrics['gate_statuses']['P0R-EX']}**. C3X contains {metrics['c3x_projects']} projects (threshold ≥30). Usable cross-family provenance lineages: {metrics['usable_cross_family_provenance_lineages']}/{metrics['cross_family_c3_candidate_lineages']} = {_percent(metrics['provenance_retention'])} (threshold ≥50%).

## M. P0R-FX

P0R-FX: **{metrics['gate_statuses']['P0R-FX']}**.

1. Differing cross-family comparable lineages: {metrics['cross_family_differing_lineages']} (threshold ≥25).
2. Cross-family divergence rate: {metrics['cross_family_differing_lineages']}/{metrics['cross_family_comparable_lineages']} = {_percent(metrics['cross_family_divergence_rate'])} (threshold ≥10%).
3. Provenance-resolved cross-family lineages with a resolved U→P transformation: {metrics['cross_family_transformed_u_p_lineages']} (threshold ≥25).

No hypothesis test was performed, and the pilot divergence rate is not an ecosystem effect estimate.

## N. Matching-mode distribution

{mode_table}

Zero counts are shown explicitly. No evidence mode was upgraded manually.

## O. Tier-A invariant audit

- Audited: {metrics['tier_a_lineages_audited']} lineages.
- Passed: {metrics['tier_a_lineages_passing']} lineages.
- Violations: {metrics['tier_a_lineages_audited'] - metrics['tier_a_lineages_passing']}.
- Violation types: `{json.dumps(metrics['tier_a_violation_types'], sort_keys=True)}`.
- Blocking status: **{metrics['tier_a_blocking_violation']}**.

The programmatic suite verifies exact upstream grouping, deterministic executable normalization, one member per distribution, rejection of unresolved multiplicity, no basename/fuzzy/manual rescue, pre-outcome matching, no policy inputs to matching, and disjoint accepted/ambiguous sets.

## P. Attrition

Pre-match missing observations are not assigned to hypothetical pairs. Fedora/Arch attrition remains visible rather than pooled away.

### By distribution

{attrition_distribution}

### By deterministically established pair

{attrition_pair}

## Q. Determinism

- Input-manifest hash: `{metrics['input_manifest_hash']}`.
- Selected-pilot hash: `{metrics['selected_pilot_hash']}`.
- Normalized-output hash: `{determinism['normalized_output_hash']}`.
- Two unchanged-input runs byte-equivalent after excluding timestamps/raw logs: **{determinism['byte_equivalent_normalized_outputs']}**.

## R. Final decision

`{final_decision}`

`RQ3d_DISABLED`

The decision uses the frozen v4.2 thresholds without reinterpretation. P0R-D-X is non-blocking. No full census was started.

## Complete gate record

{gate_table}
"""
    REPORT.write_text(text, encoding="utf-8")
    return final_decision


def run() -> dict[str, Any]:
    historical_hashes = {path: sha256_file(path) for path in HISTORICAL_REPORTS}
    verification = verify_frozen_inputs()
    _, pilot_packages = prepare_selection()
    acquire_packages(pilot_packages)
    first = run_scientific_pass()
    first_hashes = _normalized_hashes()
    second = run_scientific_pass()
    second_hashes = _normalized_hashes()
    material = json.dumps(second_hashes, sort_keys=True, separators=(",", ":")).encode()
    determinism = {
        "input_manifest_hash": verification["input_manifest_hash"],
        "selected_pilot_hash": read_json(ARTIFACTS / "normalized/sampling_manifest.json")["selected_pilot_sha256"],
        "normalized_targets": list(NORMALIZED_TARGETS),
        "first_run_hashes": first_hashes,
        "second_run_hashes": second_hashes,
        "byte_equivalent_normalized_outputs": first_hashes == second_hashes,
        "normalized_output_hash": hashlib.sha256(material).hexdigest(),
        "excluded_from_comparison": ["raw evaluator output metadata", "retrieval timestamps", "structured logs", "determinism_manifest.json", "PHASE0X_REPORT.md"],
    }
    atomic_json(ARTIFACTS / "determinism_manifest.json", determinism)
    decision = write_report(second, determinism)
    after = {path: sha256_file(path) for path in HISTORICAL_REPORTS}
    if historical_hashes != after:
        raise RuntimeError("historical scientific report changed during Phase 0R-X")
    result = read_json(ARTIFACTS / "phase0x_result.json")
    result["final_decision"] = decision
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="UnitTrace v4.2 Phase 0R-X cross-family rerun")
    parser.add_argument("command", choices=("verify", "select", "fetch", "analyze", "run"))
    arguments = parser.parse_args()
    if arguments.command == "verify":
        verify_frozen_inputs()
    elif arguments.command == "select":
        verify_frozen_inputs()
        prepare_selection()
    elif arguments.command == "fetch":
        verify_frozen_inputs()
        _, packages = prepare_selection()
        acquire_packages(packages)
    elif arguments.command == "analyze":
        run_scientific_pass()
    else:
        run()


if __name__ == "__main__":
    main()
