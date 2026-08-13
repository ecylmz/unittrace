from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .gates import calculate_gates, scientific_decision
from .io import atomic_json, sha256_file, write_csv
from .model import DimensionStatus, UArtifactClass


def derive_metrics(
    manifest: list[dict[str, Any]], lineages: list[dict[str, Any]], states: list[dict[str, Any]],
    upstream: list[dict[str, Any]], transformations: list[dict[str, Any]], derivations: list[dict[str, Any]],
    fixtures_pass: bool, artifacts: Path,
) -> tuple[dict[str, Any], list[Any], str, str]:
    matched = [row for row in lineages if row["match_status"] == "MATCHED"]
    matched_ids = {row["lineage_id"] for row in matched}
    matched_projects = {row["canonical_upstream_id"] for row in matched}
    distributions_by_lineage: dict[str, set[str]] = defaultdict(set)
    project_by_lineage: dict[str, str] = {}
    for row in matched:
        distributions_by_lineage[row["lineage_id"]].add(row["distribution"])
        project_by_lineage[row["lineage_id"]] = row["canonical_upstream_id"]
    four_way_lineages = {lineage for lineage, distributions in distributions_by_lineage.items() if distributions == {"debian", "ubuntu", "fedora", "arch"}}
    four_way_projects = {project_by_lineage[lineage] for lineage in four_way_lineages}
    state_status: dict[tuple[str, str, str], str] = {}
    for row in states:
        if row["layer"] in {"P", "E"}:
            state_status[(row["lineage_id"], row["distribution"], row["layer"])] = row["analysis_status"]
    usable_lineages = {
        row["lineage_id"] for row in states
        if row["layer"] == "U" and row["dimension_provenance_status"] in {DimensionStatus.PRESENT_RESOLVED.value, DimensionStatus.ABSENT_RESOLVED.value}
    }
    c3_projects = {project_by_lineage[lineage] for lineage in usable_lineages if lineage in project_by_lineage}
    rq2_comparable = {row["lineage_id"] for row in transformations if row["transition"] == "E_CROSS_DISTRIBUTION"}
    rq2_different = {row["lineage_id"] for row in transformations if row["transition"] == "E_CROSS_DISTRIBUTION" and row["semantic_category"] == "DIFFERENT"}
    up_transformed = {row["lineage_id"] for row in transformations if row["transition"] == "U_P" and row["semantic_category"] != "UNCHANGED"}
    resolved_derivations = [row for row in derivations if row["resolution_status"] == "RESOLVED"]
    c2d = [row for row in resolved_derivations if int(row["comparable_dimension_count"]) > 0]
    metrics: dict[str, Any] = {
        "all_four_enumerators": all((artifacts / f"raw/repositories/{distribution}/freeze_records.json").exists() for distribution in ("debian", "ubuntu", "fedora", "arch")),
        "artifacts_ok": sum(row.get("fetch_status") == "SUCCESS" and row.get("extract_status") == "SUCCESS" for row in manifest),
        "artifacts_total": len(manifest),
        "states_analyzable": sum(status in {"ANALYZABLE", "MASKED_EFFECTIVE_UNIT", "NOT_APPLICABLE"} for status in state_status.values()),
        "states_total": len(state_status),
        "fixtures_pass": fixtures_pass,
        "tier_a_projects": len(matched_projects),
        "tier_a_lineages": len(matched_ids),
        "tier_a_candidate_lineages": len({row["lineage_id"] for row in lineages}),
        "four_way_projects": len(four_way_projects),
        "four_way_lineages": len(four_way_lineages),
        "c3_projects": len(c3_projects),
        "c3_usable_lineages": len(usable_lineages & matched_ids),
        "c3_candidate_lineages": len(matched_ids),
        "rq2_different_lineages": len(rq2_different),
        "rq2_comparable_lineages": len(rq2_comparable),
        "up_transformed_lineages": len(up_transformed),
        "ancestor_projects": len({row["canonical_upstream_id"] for row in resolved_derivations}),
        "c2d_lineages": len(c2d),
        "ubuntu_projects": len({row["canonical_upstream_id"] for row in derivations}),
        "ubuntu_lineages": len(derivations),
    }
    gates = calculate_gates(metrics)
    decision, rq3d = scientific_decision(gates)
    metrics["decision"] = decision
    metrics["rq3d_status"] = rq3d
    atomic_json(artifacts / "normalized/phase0_metrics.json", metrics)
    write_csv(artifacts / "normalized/phase0_gate_results.csv", [row.to_dict() for row in gates], ["gate_id", "metric_name", "numerator", "denominator", "value", "threshold", "status", "evidence_artifact"])
    return metrics, gates, decision, rq3d


def write_complete_exclusions(
    manifest: list[dict[str, Any]], lineages: list[dict[str, Any]], states: list[dict[str, Any]],
    upstream: list[dict[str, Any]], derivations: list[dict[str, Any]], artifacts: Path,
) -> list[dict[str, Any]]:
    import csv

    path = artifacts / "normalized/exclusions.csv"
    existing = list(csv.DictReader(path.open(encoding="utf-8"))) if path.exists() else []
    rows: list[dict[str, Any]] = list(existing)
    for record in manifest:
        if record.get("fetch_status") != "SUCCESS":
            rows.append({"entity_type": "package", "entity_id": f"{record['distribution']}:{record['name']}", "stage": "artifact_fetch", "reason_code": "ARTIFACT_FETCH_FAILURE", "technical_detail": record.get("failure", "")})
        elif record.get("extract_status") != "SUCCESS":
            rows.append({"entity_type": "package", "entity_id": f"{record['distribution']}:{record['name']}", "stage": "artifact_extraction", "reason_code": "ARTIFACT_EXTRACTION_FAILURE", "technical_detail": record.get("failure", "")})
    for lineage in lineages:
        if lineage["match_status"] == "SERVICE_LINEAGE_AMBIGUOUS":
            rows.append({"entity_type": "service_lineage", "entity_id": f"{lineage['distribution']}:{lineage['unit_path']}", "stage": "tier_a_matching", "reason_code": "SERVICE_LINEAGE_AMBIGUOUS", "technical_detail": f"candidate_count={lineage['candidate_count']}"})
    matched_members = {(row["distribution"], row["binary_package_id"], row["unit_path"]) for row in lineages if row["match_status"] == "MATCHED"}
    unit_path = artifacts / "normalized/service_units.csv"
    for unit in csv.DictReader(unit_path.open(encoding="utf-8")):
        key = (unit["distribution"], unit["binary_package_id"], unit["unit_path"])
        if key in matched_members:
            continue
        if unit["mask_state"] == "MASKED_EFFECTIVE_UNIT":
            reason = "MASKED_EFFECTIVE_UNIT"
        elif unit["canonical_target"] != unit["unit_path"]:
            reason = "DUPLICATE_ALIAS"
        else:
            reason = "NO_TIER_A_PARTNER"
        rows.append({"entity_type": "service_unit", "entity_id": ":".join(key), "stage": "tier_a_matching", "reason_code": reason, "technical_detail": unit["canonical_target"]})
    seen_state_failures: set[tuple[str, str, str]] = set()
    for state in states:
        if state["analysis_status"] == "ANALYZER_FAILURE":
            key = (state["lineage_id"], state["distribution"], state["layer"])
            if key not in seen_state_failures:
                rows.append({"entity_type": "policy_state", "entity_id": ":".join(key), "stage": "semantic_evaluation", "reason_code": "ANALYZER_FAILURE", "technical_detail": state["description_normalized"]})
                seen_state_failures.add(key)
    for item in upstream:
        if item["u_artifact_class"] == UArtifactClass.U4_NO_UPSTREAM_STATIC_OR_TEMPLATE_UNIT.value:
            reason = "U4_NO_UPSTREAM_UNIT"
        elif item["u_artifact_class"] == UArtifactClass.U5_AMBIGUOUS_OR_UNRESOLVED.value:
            reason = "U5_AMBIGUOUS_OR_UNRESOLVED"
        else:
            continue
        rows.append({"entity_type": "upstream_artifact", "entity_id": f"{item['distribution']}:{item['lineage_id']}", "stage": "upstream_recovery", "reason_code": reason, "technical_detail": item["resolution_detail"]})
    for item in derivations:
        if item["resolution_status"] != "RESOLVED":
            rows.append({"entity_type": "distribution_derivation", "entity_id": f"ubuntu:{item['lineage_id']}", "stage": "ubuntu_ancestry", "reason_code": "DEBIAN_ANCESTOR_UNRESOLVED", "technical_detail": item["derivation_evidence_uri_or_path"]})
    unique = {(row["entity_type"], row["entity_id"], row["stage"], row["reason_code"], row["technical_detail"]): row for row in rows}
    normalized = [unique[key] for key in sorted(unique)]
    write_csv(path, normalized, ["entity_type", "entity_id", "stage", "reason_code", "technical_detail"])
    return normalized


def write_cohorts(lineages: list[dict[str, Any]], states: list[dict[str, Any]], upstream: list[dict[str, Any]], derivations: list[dict[str, Any]], artifacts: Path) -> None:
    matched = [row for row in lineages if row["match_status"] == "MATCHED"]
    by_lineage: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in matched:
        by_lineage[row["lineage_id"]].append(row)
    usable = {row["lineage_id"] for row in states if row["layer"] == "U" and row["dimension_provenance_status"] in {DimensionStatus.PRESENT_RESOLVED.value, DimensionStatus.ABSENT_RESOLVED.value}}
    fully_rendered = {row["lineage_id"] for row in upstream if row["u_artifact_class"] in {UArtifactClass.U0_STATIC.value, UArtifactClass.U3_GENERATED_DETERMINISTIC.value}}
    c2d = {row["lineage_id"] for row in derivations if row["resolution_status"] == "RESOLVED" and int(row["comparable_dimension_count"]) > 0}
    rows: list[dict[str, Any]] = []
    for lineage_id, members in sorted(by_lineage.items()):
        project = members[0]["canonical_upstream_id"]
        distributions = sorted({row["distribution"] for row in members})
        memberships = ["C1"]
        if set(distributions) == {"arch", "debian", "fedora", "ubuntu"}:
            memberships.append("C2")
        if lineage_id in usable:
            memberships.append("C3")
        if lineage_id in usable and lineage_id in fully_rendered:
            memberships.append("C3F")
        if lineage_id in c2d:
            memberships.append("C2D")
        for cohort in memberships:
            rows.append({"cohort": cohort, "lineage_id": lineage_id, "canonical_upstream_id": project, "distributions": ";".join(distributions), "distribution_count": len(distributions)})
    write_csv(artifacts / "normalized/cohorts.csv", rows, ["cohort", "lineage_id", "canonical_upstream_id", "distributions", "distribution_count"])


def write_distribution_snapshots(config: dict[str, Any], artifacts: Path) -> None:
    import hashlib

    base_records = {row["distribution"]: row for row in json.loads((artifacts / "raw/base_package_manifest.json").read_text())}
    rows: list[dict[str, Any]] = []
    for distribution in ("debian", "ubuntu", "fedora", "arch"):
        records = json.loads((artifacts / f"raw/repositories/{distribution}/freeze_records.json").read_text())
        material = "\n".join(sorted(row["sha256"] for row in records)).encode()
        repository = config["repositories"][distribution]
        rows.append({
            "distribution_id": distribution,
            "snapshot_timestamp": config["data_freeze_timestamp"],
            "release_label": repository["release"],
            "architecture": repository["architecture"],
            "distribution_family": repository["family"],
            "parent_distribution_id": "debian" if distribution == "ubuntu" else "",
            "repo_metadata_hash": hashlib.sha256(material).hexdigest(),
            "root_manifest_hash": base_records[distribution]["root_manifest_hash"],
        })
    write_csv(artifacts / "normalized/distribution_snapshots.csv", rows, ["distribution_id", "snapshot_timestamp", "release_label", "architecture", "distribution_family", "parent_distribution_id", "repo_metadata_hash", "root_manifest_hash"])


def write_determinism_manifest(artifacts: Path) -> dict[str, Any]:
    targets = [
        "normalized/service_lineages.csv", "normalized/policy_states.csv", "normalized/upstream_artifacts.csv",
        "normalized/transformations.csv", "normalized/distribution_derivation.csv", "normalized/exclusions.csv",
        "normalized/phase0_gate_results.csv", "normalized/phase0_metrics.json", "normalized/cohorts.csv",
        "normalized/distribution_snapshots.csv", "normalized/semantic_fixture_results.json", "security_assessment_schema.json",
    ]
    current = {path: sha256_file(artifacts / path) for path in targets}
    manifest_path = artifacts / "determinism_manifest.json"
    previous = json.loads(manifest_path.read_text()).get("current_hashes") if manifest_path.exists() else None
    result = {"targets": targets, "previous_run_available": previous is not None, "byte_equivalent_to_previous_run": previous == current if previous is not None else None, "current_hashes": current, "previous_hashes": previous}
    atomic_json(manifest_path, result)
    return result


def write_report(
    metrics: dict[str, Any], gates: list[Any], decision: str, rq3d: str, manifest: list[dict[str, Any]],
    lineages: list[dict[str, Any]], states: list[dict[str, Any]], upstream: list[dict[str, Any]],
    transformations: list[dict[str, Any]], derivations: list[dict[str, Any]], artifacts: Path, report_path: Path,
) -> None:
    environment = json.loads((artifacts / "execution_environment.json").read_text())
    sampling = json.loads((artifacts / "normalized/sampling_manifest.json").read_text())
    package_rows = list(__import__("csv").DictReader((artifacts / "normalized/repository_packages.csv").open()))
    repo_counts = Counter(row["distribution"] for row in package_rows)
    attrition = Counter()
    attrition["pilot_projects"] = sampling["selected_projects"]
    attrition["pilot_packages"] = len(manifest)
    attrition["artifact_success"] = metrics["artifacts_ok"]
    attrition["artifact_failure"] = metrics["artifacts_total"] - metrics["artifacts_ok"]
    attrition["tier_a_lineages"] = metrics["tier_a_lineages"]
    attrition["tier_a_projects"] = metrics["tier_a_projects"]
    attrition["c3_lineages"] = metrics["c3_usable_lineages"]
    attrition["c3_projects"] = metrics["c3_projects"]
    u_counts = Counter(row["u_artifact_class"] for row in upstream)
    u_total = len(upstream)
    rate_keys = [
        ("u_static_rate", UArtifactClass.U0_STATIC.value),
        ("u_template_value_only_rate", UArtifactClass.U1_TEMPLATE_VALUE_ONLY.value),
        ("u_template_structural_rate", UArtifactClass.U2_TEMPLATE_STRUCTURAL.value),
        ("u_generated_deterministic_rate", UArtifactClass.U3_GENERATED_DETERMINISTIC.value),
        ("u_no_unit_rate", UArtifactClass.U4_NO_UPSTREAM_STATIC_OR_TEMPLATE_UNIT.value),
        ("u_ambiguous_rate", UArtifactClass.U5_AMBIGUOUS_OR_UNRESOLVED.value),
    ]
    u_rates = {name: (u_counts[artifact_class] / u_total if u_total else 0) for name, artifact_class in rate_keys}
    u_states = [row for row in states if row["layer"] == "U"]
    dimension_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for row in u_states:
        dimension_counts[row["assessment_id"]][row["dimension_provenance_status"]] += 1
    candidate_dimension_count = u_total * len(dimension_counts)
    resolved_dimension_count = sum(counter[DimensionStatus.PRESENT_RESOLVED.value] + counter[DimensionStatus.ABSENT_RESOLVED.value] for counter in dimension_counts.values())
    derivation_counts = Counter(row["derivation_mode"] for row in derivations)
    determinism = json.loads((artifacts / "determinism_manifest.json").read_text()) if (artifacts / "determinism_manifest.json").exists() else {"byte_equivalent_to_previous_run": None}
    exclusion_counts = Counter(row["reason_code"] for row in __import__("csv").DictReader((artifacts / "normalized/exclusions.csv").open(encoding="utf-8")))

    def available(value: Any) -> str:
        return "UNAVAILABLE" if value is None or value == "" else str(value)

    gate_lines = ["| Gate | Metric | Numerator | Denominator | Value | Threshold | Status | Artifact |", "|---|---|---:|---:|---:|---|---|---|"]
    for gate in gates:
        value = "NA" if gate.value is None else f"{gate.value:.4f}"
        gate_lines.append(f"| {gate.gate_id} | {gate.metric_name} | {gate.numerator} | {gate.denominator} | {value} | {gate.threshold} | {gate.status.value} | `{gate.evidence_artifact}` |")
    dimension_lines = ["| Assessment | Resolved | Observed U rows | Retention |", "|---|---:|---:|---:|"]
    for assessment_id in sorted(dimension_counts):
        counter = dimension_counts[assessment_id]
        resolved = counter[DimensionStatus.PRESENT_RESOLVED.value] + counter[DimensionStatus.ABSENT_RESOLVED.value]
        dimension_lines.append(f"| {assessment_id} | {resolved} | {sum(counter.values())} | {resolved / u_total if u_total else 0:.4f} |")
    text = f"""# UnitTrace Phase 0R Report

## Environment

- Run: `{environment['environment_id']}`
- Research VM: {available(environment['vm_os_release'])}; kernel `{available(environment['kernel_version'])}`; architecture `{available(environment['vm_architecture'])}`.
- Virtualization: `{available(environment['virtualization_mode'])}`; machine `{available(environment['vm_machine_type'])}`; CPU `{available(environment['vm_cpu_model'])}`; vCPU `{available(environment['vm_vcpu_count'])}`; RAM `{available(environment['vm_memory_mb'])}` MiB.
- Proxmox VE version, host architecture, VM image digest, and snapshot identifier: **UNAVAILABLE inside the VM and not guessed**.
- Python `{available(environment['python_version'])}`; evaluator `{available(environment['evaluator_version'])}`; evaluator SHA-256 `{available(environment['evaluator_digest'])}`.
- Security policy SHA-256 `{available(environment['security_policy_hash'])}`; policy is the archived empty override object, which retains the pinned evaluator's built-in per-test policy.
- Evaluator runtime bundle SHA-256 `{available(environment.get('evaluator_bundle_digest'))}` covers the analyzer and its linked libraries.
- Package tools: apt `{available(environment['package_managers']['apt'])}`; dpkg `{available(environment['package_managers']['dpkg'])}`; Fedora/Arch handled by deterministic repository/archive adapters.
- Filesystem and storage details are preserved in `artifacts/execution_environment.json`.

## Repository Freeze

| Distribution | Exact state | Architecture | Service-shipping packages enumerated | Frozen evidence |
|---|---|---|---:|---|
| Debian | 13.6 trixie stable Release dated 2026-07-11 | amd64 | {repo_counts['debian']} | `artifacts/raw/repositories/debian/freeze_records.json` |
| Ubuntu | 26.04 LTS resolute Release dated 2026-04-23 | amd64 | {repo_counts['ubuntu']} | `artifacts/raw/repositories/ubuntu/freeze_records.json` |
| Fedora | 44 release plus frozen updates repomd | x86_64 | {repo_counts['fedora']} | `artifacts/raw/repositories/fedora/freeze_records.json` |
| Arch | Archive snapshot 2026-08-09, core/extra/multilib | x86_64 | {repo_counts['arch']} | `artifacts/raw/repositories/arch/freeze_records.json` |

Repository metadata and every fetched package/source artifact are hashed. No repository was changed after outcome inspection.

## Deterministic Sampling

- Candidate population: **{sampling['candidate_population']}** canonical upstream projects present in at least two frozen service-package populations.
- Selected pilot: **{sampling['selected_projects']}** projects before outcome inspection.
- Rule: `{sampling['rule']}`.
- Namespace: `{sampling['namespace']}`.
- Complete population and pilot are in `artifacts/normalized/pilot_candidates.csv` and `artifacts/normalized/pilot_projects.csv`.

## Attrition

| Stage | Count |
|---|---:|
""" + "\n".join(f"| {key} | {value} |" for key, value in attrition.items()) + "\n\nReason-code counts:\n\n" + ("\n".join(f"- `{key}`: {value}" for key, value in sorted(exclusion_counts.items())) or "- None") + f"""

## Gate Table

{"\n".join(gate_lines)}

## Matching

- Strict Tier-A lineages: **{metrics['tier_a_lineages']}**.
- Distinct Tier-A upstream projects: **{metrics['tier_a_projects']}**.
- Complete four-way lineages: **{metrics['four_way_lineages']}** across **{metrics['four_way_projects']}** projects.
- P0R-D {'passes' if metrics['four_way_projects'] >= 20 else 'fails its preferred target; the preregistered pairwise-primary fallback applies only if the blocking gates pass'}.
- Evidence uses only `UNAMBIGUOUS_EXECUTABLE_LINEAGE`; no basename-only, fuzzy, or manual rescue was used.
- Explicit C1/C2/C2D/C3/C3F membership is archived in `artifacts/normalized/cohorts.csv`.

## Provenance

Upstream-artifact observations: **{u_total}**.

| Mandatory metric | Value |
|---|---:|
""" + "\n".join(f"| `{key}` | {value:.4f} |" for key, value in u_rates.items()) + f"""
| candidate dimensions | {candidate_dimension_count} |
| resolved candidate dimensions | {resolved_dimension_count} |
| percentage candidate dimensions retained | {resolved_dimension_count / candidate_dimension_count if candidate_dimension_count else 0:.4f} |
| distinct provenance-resolved upstream projects | {metrics['c3_projects']} |

U0–U5 counts: {json.dumps(dict(sorted(u_counts.items())), sort_keys=True)}.

### Per-Dimension Resolution

{"\n".join(dimension_lines)}

Unresolved dimensions were not imputed.

## Variation

- Comparable Tier-A lineages for RQ2 feasibility: **{metrics['rq2_comparable_lineages']}**.
- Lineages with at least one cross-distribution effective-policy difference: **{metrics['rq2_different_lineages']}**.
- Provenance-resolved lineages with at least one U→P transformation: **{metrics['up_transformed_lineages']}**.

These are Phase-0 feasibility counts, not ecosystem effect estimates or hypothesis tests.

## Ubuntu Ancestry

- `SYNC`: {derivation_counts['SYNC']}.
- `MERGE_WITH_DELTA`: {derivation_counts['MERGE_WITH_DELTA']}.
- `DERIVATION_UNRESOLVED`: {derivation_counts['DERIVATION_UNRESOLVED']}.
- Exact ancestor-resolved projects: {metrics['ancestor_projects']}.
- C2D lineages with comparable dimensions: {metrics['c2d_lineages']}.

SYNC requires exact same source name/version records independently present in frozen official Debian and Ubuntu metadata. MERGE_WITH_DELTA requires an exact prior non-Ubuntu Debian version in the authoritative focal Ubuntu source package changelog; version similarity alone is never used.

## Threats/Problems Found

- Proxmox host-level identifiers were not exposed to the VM; all such fields are explicitly unavailable rather than guessed.
- Fedora SRPM and Arch `.SRCINFO`/packaging-commit adapters recover exact frozen source inputs; cases without a unique upstream service mapping remain U5 and were never manually rescued.
- Package-local P uses only focal package fragments. E overlays the focal package on the frozen distribution's systemd-package root; static configuration from unrelated dependency packages is not introduced unless owned by the focal or systemd package.
- The deterministic pilot is dominated by the Debian–Ubuntu derivative-family intersection; interpretation cannot treat these as independent packaging families.
- Byte-equivalence to the immediately preceding normalized run: **{available(determinism.get('byte_equivalent_to_previous_run'))}** (`artifacts/determinism_manifest.json`).

## Final Decision

`{decision}`

`{rq3d}`

The decision follows the literal blocking-gate rule: P0R-A, P0R-B, P0R-C, P0R-E, and P0R-F must all pass for GO. P0R-D is preferred/non-blocking with pairwise fallback; P0R-G controls only RQ3d. No threshold was changed after observing results.
"""
    report_path.write_text(text, encoding="utf-8")
