from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import phase0x
from .fixtures import run_semantic_fixtures
from .io import atomic_json, read_json, sha256_file, write_csv
from .pipeline import (
    analyze_states,
    cross_distribution_transformations,
    extract_pilot_packages,
    layer_transformations,
    match_lineages,
    prepare_distribution_bases,
)
from .repositories import fetch_pilot_packages
from .sources import evaluate_upstream, extract_pristine_sources, resolve_upstream_artifacts


ROOT = Path(__file__).resolve().parents[2]
HISTORICAL = ROOT / "artifacts"
ARTIFACTS = HISTORICAL / "full"
PHASE0X_ARTIFACTS = HISTORICAL / "phase0x"
ELIGIBLE_HASH = "0c8c8f8d5e6963bb51c82ff3ff7d1c11cf031b2afd59287b3a155a2f8a37044d"
SPEC_HASH = "1a728e40c8fdffaff25542f45fba727241487d7766e7710f84b6c60e78e9b136"
FROZEN_SOURCE_FAILURES = {
    ("fedora", "vnstat"),
    ("fedora", "xrdp"),
    ("arch", "ulogd"),
    ("arch", "unrealircd"),
    ("arch", "upower"),
    ("arch", "uptimed"),
    ("arch", "util-linux"),
    ("arch", "v2ray"),
    ("arch", "valkey"),
    ("arch", "vaultwarden"),
    ("arch", "vnstat"),
    ("arch", "vsftpd"),
    ("arch", "webhook"),
    ("arch", "wesnoth"),
    ("arch", "wsdd"),
    ("arch", "xpra"),
    ("arch", "yggdrasil"),
    ("arch", "zeroc-ice"),
    ("arch", "zram-generator"),
}
FROZEN_PACKAGE_FAILURES = {
    ("fedora", "coturn"),
    ("fedora", "glances"),
    ("fedora", "thermald"),
}
NORMALIZED_TARGETS = tuple(phase0x.NORMALIZED_TARGETS) + (
    "normalized/project_terminal_states.csv",
    "normalized/full_census_packages.csv",
)


def _activate_full_namespace() -> None:
    phase0x.ARTIFACTS = ARTIFACTS


def _merge_hardlink_tree(source: Path, destination: Path) -> None:
    if not source.exists():
        return
    for item in source.rglob("*"):
        relative = item.relative_to(source)
        target = destination / relative
        if item.is_symlink():
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists() and not target.is_symlink():
                target.symlink_to(os.readlink(item))
        elif item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif item.is_file() and not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(item, target)
            except OSError:
                shutil.copy2(item, target)


def verify_and_prepare() -> list[dict[str, str]]:
    """Verify immutable inputs and materialize the complete 469-project census."""
    _activate_full_namespace()
    verification = phase0x.verify_frozen_inputs()
    if not verification["all_checks_pass"]:
        raise RuntimeError("frozen input verification failed")
    observed_spec = sha256_file(ROOT / "unittrace_article_spec_v4_2.md")
    if observed_spec != SPEC_HASH:
        raise RuntimeError(f"v4.2 protocol hash changed: {observed_spec}")

    packages = phase0x.read_csv(HISTORICAL / "normalized/repository_packages.csv")
    services = phase0x.read_csv(HISTORICAL / "normalized/repository_services.csv")
    config = phase0x.load_config()
    eligible, no_url = phase0x.construct_eligible_population(packages, config["selection_namespace"])
    fields = [
        "canonical_upstream_id",
        "selection_hash",
        "distribution_count",
        "distributions",
        "eligible_cross_family_pairs",
        "package_count",
    ]
    write_csv(ARTIFACTS / "normalized/eligible_population.csv", eligible, fields)
    observed_population_hash = sha256_file(ARTIFACTS / "normalized/eligible_population.csv")
    phase0x_population_hash = sha256_file(PHASE0X_ARTIFACTS / "normalized/eligible_population.csv")
    if len(eligible) != 469 or observed_population_hash != ELIGIBLE_HASH or phase0x_population_hash != ELIGIBLE_HASH:
        raise RuntimeError(
            "eligible population differs from Phase 0R-X: "
            f"count={len(eligible)}, reconstructed={observed_population_hash}, phase0x={phase0x_population_hash}"
        )
    eligible_ids = {row["canonical_upstream_id"] for row in eligible}
    census_packages = [row for row in packages if row["canonical_upstream_id"] in eligible_ids]
    write_csv(ARTIFACTS / "normalized/selected_projects.csv", eligible, fields)
    write_csv(ARTIFACTS / "normalized/full_census_packages.csv", census_packages, list(packages[0]))
    # Compatibility with the frozen Phase 0 implementation, where this table was
    # named for its then-current pilot rather than for a census.
    write_csv(ARTIFACTS / "normalized/pilot_packages.csv", census_packages, list(packages[0]))
    write_csv(ARTIFACTS / "normalized/repository_packages.csv", packages, list(packages[0]))
    write_csv(ARTIFACTS / "normalized/repository_services.csv", services, list(services[0]))
    # Eligibility exclusions are an input to the scientific-pass exclusion
    # table.  Once a completed census exists, a verification-only invocation
    # must not replace the comprehensive table with this precursor.
    eligibility_exclusions = ARTIFACTS / "checkpoints/eligibility_exclusions.csv"
    write_csv(
        eligibility_exclusions,
        no_url,
        ["entity_type", "entity_id", "stage", "reason_code", "technical_detail"],
    )
    if not (ARTIFACTS / "normalized/project_terminal_states.csv").exists():
        write_csv(
            ARTIFACTS / "normalized/exclusions.csv",
            no_url,
            ["entity_type", "entity_id", "stage", "reason_code", "technical_detail"],
        )
    prior_path = ARTIFACTS / "normalized/census_manifest.json"
    prior = read_json(prior_path) if prior_path.exists() else {}
    atomic_json(
        prior_path,
        {
            "study_run_id": "unittrace-v4.2-full-census",
            "created_utc": prior.get("created_utc") or datetime.now(timezone.utc).isoformat(),
            "authoritative_protocol": "unittrace_article_spec_v4_2.md",
            "authoritative_protocol_sha256": observed_spec,
            "eligible_projects": len(eligible),
            "package_observations": len(census_packages),
            "eligible_population_sha256": observed_population_hash,
            "phase0x_eligible_population_sha256": phase0x_population_hash,
            "population_match": True,
            "census_not_sample": True,
            "repositories_refrozen": False,
            "rq3d_status": "RQ3d_DISABLED",
            "bootstrap_namespace": "unittrace:v4.2:full-census:project-bootstrap",
            "bootstrap_seed": 420260809,
        },
    )
    atomic_json(
        ARTIFACTS / "normalized/sampling_manifest.json",
        {
            "phase0_run_id": "unittrace-v4.2-full-census",
            "candidate_population": len(eligible),
            "selected_projects": len(eligible),
            "intended_pilot_size": len(eligible),
            "population_below_intended_size": False,
            "namespace": config["selection_namespace"],
            "rule": "complete census of the frozen Phase 0R-X eligible-population manifest",
            "selection_timestamp_utc": prior.get("created_utc") or datetime.now(timezone.utc).isoformat(),
            "eligible_population_sha256": observed_population_hash,
            "selected_pilot_sha256": observed_population_hash,
            "eligibility_rule": "canonical upstream project has service-shipping package candidates in at least one preregistered cross-family distribution pair",
            "eligibility_metadata_fields": config["eligibility_metadata_fields"],
            "forbidden_eligibility_fields": config["forbidden_eligibility_fields"],
            "outcome_fields_used": [],
            "outcome_inspected_before_selection": False,
            "pair_coverage": {
                label: sum(label in row["eligible_cross_family_pairs"].split(";") for row in eligible)
                for _, _, label, family in phase0x.PAIR_SPECS
                if family == "CROSS_FAMILY"
            },
            "rq3d_status": "RQ3d_DISABLED",
            "census_not_sample": True,
        },
    )
    atomic_json(
        ARTIFACTS / "manifests/software_corrections.json",
        {
            "corrections_before_full_outcome_generation": [
                {
                    "id": "FULL-001",
                    "scope": "full census only; historical Phase 0 artifacts unchanged",
                    "defect": "Phase 0 implementation did not emit the preregistered P-to-E transformation table",
                    "correction": "compare pinned-evaluator normalized P and E states and emit P_E transitions",
                    "outcome_dependent": False,
                },
                {
                    "id": "FULL-002",
                    "scope": "full census U-to-P provenance categories",
                    "defect": "all changed U-to-P states were previously labeled MODIFIED",
                    "correction": "use resolved set-state transitions to distinguish ADDED, REMOVED, and MODIFIED",
                    "outcome_dependent": False,
                },
                {
                    "id": "FULL-003",
                    "scope": "full-census extracted-root manifest",
                    "defect": "root manifest attempted to content-hash executable-only non-systemd package members after the enclosing package artifact was already hash-verified",
                    "correction": "record path, mode, size, and an explicit unreadable-member marker; retain content hashes for readable files",
                    "outcome_dependent": False,
                },
                {
                    "id": "FULL-004",
                    "scope": "full-census effective-root construction",
                    "defect": "the generic copytree overlay did not replace existing symlinks when the focal and base systemd packages shared paths",
                    "correction": "apply later-package-wins replacement semantics for files, directories, aliases, and masks in deterministic path order",
                    "outcome_dependent": False,
                },
            ],
            "reproducibility_corrections_after_outcome_generation": [
                {
                    "id": "FULL-005",
                    "scope": "verification-only command after a completed census",
                    "defect": "verify replaced the comprehensive normalized exclusion table with the eligibility-stage precursor",
                    "correction": "write eligibility exclusions to the checkpoint namespace and preserve an existing completed exclusion table",
                    "outcome_dependent": False,
                    "affected_scientific_observations": False,
                    "recovery": "rebuilt exclusions from frozen normalized inputs and recovered the prior deterministic SHA-256 exactly",
                },
                {
                    "id": "FULL-006",
                    "scope": "U1 value-only template dimension mask and every affected full-census U-to-P observation",
                    "defect": "when User=/DynamicUser= contained an unresolved value placeholder, RemoveIPC and SupplementaryGroups were evaluated under the synthetic root-user fallback and incorrectly marked resolved",
                    "detection": "post-hoc automated U1 render validation; all 132 disagreements were confined to these two context-dependent assessments in 67 U1 observations",
                    "correction": "mark RemoveIPC and SupplementaryGroups VALUE_UNRESOLVED whenever the service identity value is unresolved, then rerun both normalized scientific passes from frozen inputs and all downstream analyses",
                    "outcome_dependent": False,
                    "affected_scientific_observations": True,
                    "historical_normalized_hashes": {
                        "policy_states.csv": "c9caea2c3344d6567add8de02740d5d87f48d20ed1c8fc214ae3fe163780c41d",
                        "transformations.csv": "992f50b73e8821277f11bf412408d3bae880099c0e0d0ab5e93f5dc69f40a613",
                    },
                    "historical_affected_u_p_rows": 132,
                    "historical_affected_categories": {"ADDED": 89, "MODIFIED": 43},
                    "corrected_normalized_hashes": "populated automatically after the corrected deterministic rerun",
                },
                {
                    "id": "FULL-007",
                    "scope": "frozen full-census source acquisition manifest",
                    "defect": "the FULL-006 full rerun called the network-capable source-record path instead of reusing the completed frozen source manifest, converting 2 Fedora and 17 Arch terminal source failures into later successes",
                    "detection": "C3X increased from the authoritative completed-study 233 projects/371 lineages to 237/377 even though the U1 resolution correction could not logically add provenance",
                    "correction": "restore the 19 contemporaneously identified frozen failure keys, exclude later-downloaded sources, require both scientific passes to reuse the restored manifest, and rerun all normalized and downstream analyses",
                    "outcome_dependent": False,
                    "affected_scientific_observations": True,
                    "accidental_refetch_manifest_sha256": "1ce3bc542010edbe67d0a3109ad44d0be15d52e0b451c27511e9340a207415bc",
                    "recovery_basis": "authoritative STUDY_REPORT source-success totals (Fedora 401/406; Arch 243/291), acquisition timestamps, and the exact current-success delta; original failure-detail strings were not guessed",
                    "later_downloaded_files_retained_but_scientifically_excluded": True,
                    "frozen_failure_keys": sorted(f"{distribution}:{source}" for distribution, source in FROZEN_SOURCE_FAILURES),
                },
                {
                    "id": "FULL-008",
                    "scope": "frozen full-census binary-package acquisition manifest",
                    "defect": "later deterministic reruns could retry the three authoritative Fedora binary-artifact failures; thermald, and subsequently glances during correction verification, became available after the completed-study freeze",
                    "detection": "artifact success increased from the authoritative 1,739/1,742 to 1,740/1,742 and the E-only complete four-way cohort increased from 76 projects/115 lineages to 77/116",
                    "correction": "restore Fedora coturn, glances, and thermald to their frozen fetch-failure states after cache verification, retain any later downloads only as non-scientific cache material, and rerun both normalized passes and all downstream analyses",
                    "outcome_dependent": False,
                    "affected_scientific_observations": True,
                    "recovery_basis": "authoritative STUDY_REPORT names and totals (Fedora coturn, glances, and thermald; 1,739/1,742 successes), the exact one-record current delta, and acquisition timestamps",
                    "later_downloaded_files_retained_but_scientifically_excluded": True,
                    "frozen_failure_keys": sorted(f"{distribution}:{package}" for distribution, package in FROZEN_PACKAGE_FAILURES),
                },
            ],
            "historical_reports_modified": False,
        },
    )
    return census_packages


def _record_full006_after_hashes() -> None:
    path = ARTIFACTS / "manifests/software_corrections.json"
    corrections = read_json(path)
    entry = next(
        row
        for row in corrections["reproducibility_corrections_after_outcome_generation"]
        if row["id"] == "FULL-006"
    )
    entry["corrected_normalized_hashes"] = {
        "policy_states.csv": sha256_file(ARTIFACTS / "normalized/policy_states.csv"),
        "transformations.csv": sha256_file(ARTIFACTS / "normalized/transformations.csv"),
    }
    entry["corrected_affected_u_p_rows_retained"] = 0
    entry["rerun_from_frozen_inputs"] = True
    entry["deterministic_two_pass_verification"] = True
    atomic_json(path, corrections)


def _restore_frozen_source_manifest() -> None:
    path = ARTIFACTS / "raw/source_artifact_manifest.json"
    records = read_json(path)
    restored: list[dict[str, Any]] = []
    for row in records:
        if (row.get("distribution"), row.get("source_name")) in FROZEN_SOURCE_FAILURES:
            row = {
                **row,
                "status": "SOURCE_FETCH_FAILURE",
                "detail": "RESTORED_FROZEN_FAILURE_DETAIL_UNAVAILABLE_AFTER_FULL007_MANIFEST_OVERWRITE",
                "files": [],
            }
        restored.append(row)
    fedora_success = sum(row.get("distribution") == "fedora" and row.get("status") == "SUCCESS" for row in restored)
    arch_success = sum(row.get("distribution") == "arch" and row.get("status") == "SUCCESS" for row in restored)
    if (fedora_success, arch_success) != (401, 243):
        raise RuntimeError(f"restored frozen source totals differ: Fedora={fedora_success}, Arch={arch_success}")
    atomic_json(path, restored)
    atomic_json(
        ARTIFACTS / "manifests/source_manifest_recovery.json",
        {
            "correction_id": "FULL-007",
            "restored_manifest_sha256": sha256_file(path),
            "fedora_success": fedora_success,
            "fedora_total": 406,
            "arch_success": arch_success,
            "arch_total": 291,
            "restored_failure_keys": sorted(f"{distribution}:{source}" for distribution, source in FROZEN_SOURCE_FAILURES),
            "raw_later_downloads_scientifically_excluded": True,
        },
    )


def _restore_frozen_package_manifest() -> list[dict[str, Any]]:
    path = ARTIFACTS / "raw/package_artifact_manifest.json"
    records = read_json(path)
    restored: list[dict[str, Any]] = []
    for row in records:
        if (row.get("distribution"), row.get("name")) in FROZEN_PACKAGE_FAILURES:
            row = {
                **row,
                "fetch_status": "FAILURE",
                "extract_status": "NOT_ATTEMPTED",
                "observed_sha256": "",
                "failure": "RESTORED_FROZEN_FAILURE_DETAIL_UNAVAILABLE_AFTER_FULL008_MANIFEST_OVERWRITE",
            }
            row.pop("retrieved_at_utc", None)
            row.pop("root_manifest_hash", None)
            row.pop("service_count", None)
        restored.append(row)
    successes = sum(row.get("fetch_status") == "SUCCESS" for row in restored)
    failed = sorted(
        f"{row.get('distribution')}:{row.get('name')}"
        for row in restored
        if row.get("fetch_status") != "SUCCESS"
    )
    if successes != 1739 or failed != ["fedora:coturn", "fedora:glances", "fedora:thermald"]:
        raise RuntimeError(f"restored frozen package totals differ: successes={successes}, failed={failed}")
    atomic_json(path, restored)
    atomic_json(
        ARTIFACTS / "manifests/package_manifest_recovery.json",
        {
            "correction_id": "FULL-008",
            "restored_manifest_sha256": sha256_file(path),
            "successes": successes,
            "total": len(restored),
            "restored_failure_keys": sorted(
                f"{distribution}:{package}" for distribution, package in FROZEN_PACKAGE_FAILURES
            ),
            "all_frozen_failure_keys": failed,
            "raw_later_downloads_scientifically_excluded": True,
        },
    )
    return restored


def _reuse_verified_caches() -> None:
    for source_root in (HISTORICAL, PHASE0X_ARTIFACTS):
        for relative in ("raw/packages", "raw/sources", "cache/arch-packaging", "cache/srpm"):
            _merge_hardlink_tree(source_root / relative, ARTIFACTS / relative)


def acquire() -> list[dict[str, Any]]:
    packages = verify_and_prepare()
    _reuse_verified_caches()
    fetch_pilot_packages(packages, ARTIFACTS)
    fetched = _restore_frozen_package_manifest()
    _restore_frozen_source_manifest()
    return fetched


def _source_records(packages: list[dict[str, str]], reuse_manifest: bool) -> list[dict[str, Any]]:
    path = ARTIFACTS / "raw/source_artifact_manifest.json"
    if reuse_manifest and path.exists():
        return read_json(path)
    return phase0x._source_records(packages)


def scientific_pass(reuse_source_manifest: bool = False) -> dict[str, Any]:
    _activate_full_namespace()
    packages = phase0x.read_csv(ARTIFACTS / "normalized/full_census_packages.csv")
    historical_config = read_json(ROOT / phase0x.load_config()["historical_config"])
    evaluator = Path(historical_config["evaluator"]["path"])
    policy = ROOT / historical_config["evaluator"]["policy"]
    fixtures = run_semantic_fixtures(evaluator, policy, ARTIFACTS)
    fetch_manifest = read_json(ARTIFACTS / "raw/package_artifact_manifest.json")
    manifest, units = extract_pilot_packages(fetch_manifest, ARTIFACTS)
    source_records = _source_records(packages, reuse_source_manifest)
    inventories = extract_pristine_sources(source_records, ARTIFACTS)
    lineages = match_lineages(units, ARTIFACTS, inventories, packages)
    prepare_distribution_bases(phase0x.read_csv(ARTIFACTS / "normalized/repository_packages.csv"), ARTIFACTS)
    states = analyze_states(lineages, units, evaluator, policy, ARTIFACTS)
    upstream = resolve_upstream_artifacts(lineages, inventories, ARTIFACTS)
    states, upstream_transformations = evaluate_upstream(upstream, states, evaluator, policy, ARTIFACTS)
    transformations = (
        cross_distribution_transformations(states, ARTIFACTS)
        + upstream_transformations
        + layer_transformations(states, ARTIFACTS, "P", "E")
    )
    write_csv(
        ARTIFACTS / "normalized/transformations.csv",
        transformations,
        [
            "lineage_id",
            "distribution",
            "transition",
            "assessment_id",
            "semantic_category",
            "provenance_category",
            "exposure_delta",
            "source_resolved",
            "destination_resolved",
        ],
    )
    result = phase0x._summarize(
        manifest,
        lineages,
        units,
        states,
        upstream,
        transformations,
        bool(fixtures["all_pass"]),
        packages,
    )
    _write_project_terminal_states(eligible=phase0x.read_csv(ARTIFACTS / "normalized/eligible_population.csv"), lineages=lineages)
    return result


def _write_project_terminal_states(eligible: list[dict[str, str]], lineages: list[dict[str, Any]]) -> None:
    cohorts = phase0x.read_csv(ARTIFACTS / "normalized/cohorts.csv")
    c1x = {row["canonical_upstream_id"] for row in cohorts if row["cohort"] == "C1X"}
    c3x = {row["canonical_upstream_id"] for row in cohorts if row["cohort"] == "C3X"}
    ambiguous = {row["canonical_upstream_id"] for row in lineages if row["match_status"] == "SERVICE_LINEAGE_AMBIGUOUS"}
    rows: list[dict[str, Any]] = []
    for project in eligible:
        identifier = project["canonical_upstream_id"]
        if identifier in c3x:
            state = "C3X_RETAINED"
        elif identifier in c1x:
            state = "C1X_RETAINED_PROVENANCE_UNRESOLVED"
        elif identifier in ambiguous:
            state = "SERVICE_LINEAGE_AMBIGUOUS"
        else:
            state = "NO_TIER_A_PARTNER"
        rows.append(
            {
                "canonical_upstream_id": identifier,
                "terminal_state": state,
                "c1x_retained": identifier in c1x,
                "c3x_retained": identifier in c3x,
            }
        )
    write_csv(
        ARTIFACTS / "normalized/project_terminal_states.csv",
        rows,
        ["canonical_upstream_id", "terminal_state", "c1x_retained", "c3x_retained"],
    )


def _normalized_hashes() -> dict[str, str]:
    return {relative: sha256_file(ARTIFACTS / relative) for relative in NORMALIZED_TARGETS if (ARTIFACTS / relative).is_file()}


def run() -> dict[str, Any]:
    acquire()
    first = scientific_pass(reuse_source_manifest=True)
    first_hashes = _normalized_hashes()
    second = scientific_pass(reuse_source_manifest=True)
    second_hashes = _normalized_hashes()
    material = json.dumps(second_hashes, sort_keys=True, separators=(",", ":")).encode()
    determinism = {
        "normalized_targets": sorted(second_hashes),
        "first_run_hashes": first_hashes,
        "second_run_hashes": second_hashes,
        "byte_equivalent_normalized_outputs": first_hashes == second_hashes,
        "normalized_output_hash": hashlib.sha256(material).hexdigest(),
        "bootstrap_seed": 420260809,
        "rq3d_status": "RQ3d_DISABLED",
    }
    atomic_json(ARTIFACTS / "manifests/determinism_manifest.json", determinism)
    if not determinism["byte_equivalent_normalized_outputs"]:
        raise RuntimeError("full-census normalized outputs are not byte-equivalent")
    metrics = second["metrics"]
    metrics["determinism_pass"] = True
    metrics["eligible_projects_terminal"] = len(phase0x.read_csv(ARTIFACTS / "normalized/project_terminal_states.csv"))
    metrics["rq3d_status"] = "RQ3d_DISABLED"
    atomic_json(ARTIFACTS / "analysis/full_census_pipeline_metrics.json", metrics)
    _record_full006_after_hashes()
    return metrics


def determinism_from_current() -> dict[str, Any]:
    """Use the completed current pass as run 1 and regenerate run 2."""
    first_hashes = _normalized_hashes()
    second = scientific_pass(reuse_source_manifest=True)
    second_hashes = _normalized_hashes()
    material = json.dumps(second_hashes, sort_keys=True, separators=(",", ":")).encode()
    determinism = {
        "normalized_targets": sorted(second_hashes),
        "first_run_hashes": first_hashes,
        "second_run_hashes": second_hashes,
        "byte_equivalent_normalized_outputs": first_hashes == second_hashes,
        "normalized_output_hash": hashlib.sha256(material).hexdigest(),
        "bootstrap_seed": 420260809,
        "rq3d_status": "RQ3d_DISABLED",
    }
    atomic_json(ARTIFACTS / "manifests/determinism_manifest.json", determinism)
    if not determinism["byte_equivalent_normalized_outputs"]:
        differing = sorted(key for key in set(first_hashes) | set(second_hashes) if first_hashes.get(key) != second_hashes.get(key))
        raise RuntimeError(f"full-census normalized outputs are not byte-equivalent: {differing}")
    metrics = second["metrics"]
    metrics["determinism_pass"] = True
    metrics["normalized_output_hash"] = determinism["normalized_output_hash"]
    metrics["eligible_projects_terminal"] = len(phase0x.read_csv(ARTIFACTS / "normalized/project_terminal_states.csv"))
    metrics["rq3d_status"] = "RQ3d_DISABLED"
    atomic_json(ARTIFACTS / "analysis/full_census_pipeline_metrics.json", metrics)
    _record_full006_after_hashes()
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="UnitTrace v4.2 full frozen census")
    parser.add_argument("command", choices=("verify", "fetch", "analyze", "determinism", "run"))
    args = parser.parse_args()
    if args.command == "verify":
        verify_and_prepare()
    elif args.command == "fetch":
        acquire()
    elif args.command == "analyze":
        scientific_pass(reuse_source_manifest=(ARTIFACTS / "raw/source_artifact_manifest.json").exists())
    elif args.command == "determinism":
        determinism_from_current()
    else:
        run()


if __name__ == "__main__":
    main()
