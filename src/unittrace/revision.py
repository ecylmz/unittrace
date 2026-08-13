from __future__ import annotations

import csv
import hashlib
import json
import shlex
import shutil
import statistics
import tempfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np

from .analysis import (
    ANALYSIS,
    ARTIFACTS,
    BOOTSTRAPS,
    FIGURES,
    NORMALIZED,
    RESOLVED,
    TABLES,
    _endpoint_seed,
    _group,
    assessment_family,
    cluster_ratio_ci,
    cluster_stat_ci,
    pairwise_divergence,
    presentation_order_pair_rows,
    read_csv,
)
from .io import atomic_json, sha256_file, write_csv
from .phase0x import PAIR_SPECS
from .systemd import (
    SUBSTITUTION,
    evaluate_unit,
    make_minimal_root,
    parse_service_assignments,
    project_service_template,
)


ROOT = Path(__file__).resolve().parents[2]
VALIDATION = ARTIFACTS / "validation/u1_projector"
EVALUATOR = Path("/usr/bin/systemd-analyze")
POLICY = ROOT / "config/security-policy.json"
REVISION_CLASSIFICATION = "post-hoc exploratory/explanatory"


def _cohorts() -> tuple[dict[str, set[str]], dict[str, str]]:
    cohorts: dict[str, set[str]] = defaultdict(set)
    projects: dict[str, str] = {}
    for row in read_csv(NORMALIZED / "cohorts.csv"):
        cohorts[row["cohort"]].add(row["lineage_id"])
        projects[row["lineage_id"]] = row["canonical_upstream_id"]
    return dict(cohorts), projects


def _state_indexes(
    states: Iterable[dict[str, str]],
) -> tuple[dict[tuple[str, str, str, str], dict[str, str]], dict[tuple[str, str, str], set[str]]]:
    index: dict[tuple[str, str, str, str], dict[str, str]] = {}
    assessments: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for row in states:
        if row["analysis_status"] != "ANALYZABLE" or not row["assessment_id"]:
            continue
        key = (row["lineage_id"], row["distribution"], row["layer"], row["assessment_id"])
        index[key] = row
        assessments[key[:3]].add(row["assessment_id"])
    return index, assessments


def classify_divergence_source(
    u_left: tuple[str, ...] | None,
    u_right: tuple[str, ...] | None,
    p_left: tuple[str, ...],
    p_right: tuple[str, ...],
    e_left: tuple[str, ...],
    e_right: tuple[str, ...],
) -> str:
    if u_left is None or u_right is None:
        return "UNRESOLVED"
    upstream_differs = u_left != u_right
    effective_differs = e_left != e_right
    if upstream_differs and not effective_differs:
        return "DOWNSTREAM_CONVERGED"
    if not effective_differs:
        return "NO_FINAL_DIFFERENCE"
    if not upstream_differs:
        return "DOWNSTREAM_INTRODUCED"
    if u_left == p_left == e_left and u_right == p_right == e_right:
        return "UPSTREAM_DIFFERENCE_INHERITED"
    return "DOWNSTREAM_AMPLIFIED_OR_MODIFIED"


def divergence_attribution(
    states: list[dict[str, str]], cohorts: dict[str, set[str]], projects: dict[str, str]
) -> tuple[
    list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]],
    list[dict[str, Any]], list[dict[str, Any]],
]:
    index, assessments = _state_indexes(states)
    observations: list[dict[str, Any]] = []
    for left, right, pair, family_type in PAIR_SPECS:
        if family_type != "CROSS_FAMILY":
            continue
        for lineage in sorted(cohorts["C1X"]):
            common = assessments[(lineage, left, "E")] & assessments[(lineage, right, "E")]
            families: dict[str, list[str]] = defaultdict(list)
            for assessment in common:
                families[assessment_family(assessment)].append(assessment)
            for family, family_assessments in sorted(families.items()):
                ordered = sorted(family_assessments)

                def vector(distribution: str, layer: str) -> tuple[str, ...]:
                    return tuple(index[(lineage, distribution, layer, item)]["normalized_state"] for item in ordered)

                e_left = vector(left, "E")
                e_right = vector(right, "E")
                resolved = all(
                    (lineage, distribution, layer, item) in index
                    for distribution in (left, right)
                    for layer in ("U", "P", "E")
                    for item in ordered
                ) and all(
                    index[(lineage, distribution, "U", item)]["dimension_provenance_status"] in RESOLVED
                    for distribution in (left, right)
                    for item in ordered
                )
                u_left = vector(left, "U") if resolved else None
                u_right = vector(right, "U") if resolved else None
                category = classify_divergence_source(
                    u_left,
                    u_right,
                    vector(left, "P"),
                    vector(right, "P"),
                    e_left,
                    e_right,
                )
                observations.append(
                    {
                        "pair": pair,
                        "left_distribution": left,
                        "right_distribution": right,
                        "lineage_id": lineage,
                        "project": projects[lineage],
                        "assessment_family": family,
                        "effective_different": e_left != e_right,
                        "source_category": category,
                        "provenance_resolved": resolved,
                        "analysis_classification": REVISION_CLASSIFICATION,
                        "observational_unit": "cross-family lineage-assessment-family",
                    }
                )

    summaries: list[dict[str, Any]] = []
    final_difference_summaries: list[dict[str, Any]] = []
    resolved_difference_summaries: list[dict[str, Any]] = []
    for pair, pair_rows in sorted(_group(observations, lambda row: row["pair"]).items()):
        for category in (
            "UPSTREAM_DIFFERENCE_INHERITED",
            "DOWNSTREAM_INTRODUCED",
            "DOWNSTREAM_AMPLIFIED_OR_MODIFIED",
            "DOWNSTREAM_CONVERGED",
            "NO_FINAL_DIFFERENCE",
            "UNRESOLVED",
        ):
            point, low, high, project_count = cluster_ratio_ci(
                pair_rows,
                lambda row, category=category: int(row["source_category"] == category),
                lambda _: 1,
                f"revision:source:all:{pair}:{category}",
            )
            summaries.append(
                {
                    "pair": pair,
                    "source_category": category,
                    "numerator": sum(row["source_category"] == category for row in pair_rows),
                    "denominator": len(pair_rows),
                    "projects": project_count,
                    "proportion": point,
                    "ci_low": low,
                    "ci_high": high,
                    "analysis_classification": REVISION_CLASSIFICATION,
                    "observational_unit": "cross-family lineage-assessment-family",
                }
            )
        differing = [row for row in pair_rows if row["effective_different"]]
        for category in (
            "UPSTREAM_DIFFERENCE_INHERITED",
            "DOWNSTREAM_INTRODUCED",
            "DOWNSTREAM_AMPLIFIED_OR_MODIFIED",
            "UNRESOLVED",
        ):
            point, low, high, project_count = cluster_ratio_ci(
                differing,
                lambda row, category=category: int(row["source_category"] == category),
                lambda _: 1,
                f"revision:source:effective-difference:{pair}:{category}",
            )
            final_difference_summaries.append(
                {
                    "pair": pair,
                    "source_category": category,
                    "numerator": sum(row["source_category"] == category for row in differing),
                    "denominator": len(differing),
                    "projects": project_count,
                    "proportion": point,
                    "ci_low": low,
                    "ci_high": high,
                    "analysis_classification": REVISION_CLASSIFICATION,
                    "observational_unit": "E-differing cross-family lineage-assessment-family",
                }
            )
        resolved_differing = [row for row in differing if row["source_category"] != "UNRESOLVED"]
        for category in (
            "UPSTREAM_DIFFERENCE_INHERITED",
            "DOWNSTREAM_INTRODUCED",
            "DOWNSTREAM_AMPLIFIED_OR_MODIFIED",
        ):
            point, low, high, project_count = cluster_ratio_ci(
                resolved_differing,
                lambda row, category=category: int(row["source_category"] == category),
                lambda _: 1,
                f"revision:source:resolved-effective-difference:{pair}:{category}",
            )
            resolved_difference_summaries.append(
                {
                    "pair": pair,
                    "source_category": category,
                    "numerator": sum(row["source_category"] == category for row in resolved_differing),
                    "denominator": len(resolved_differing),
                    "projects": project_count,
                    "proportion": point,
                    "ci_low": low,
                    "ci_high": high,
                    "analysis_classification": REVISION_CLASSIFICATION,
                    "observational_unit": "provenance-resolved E-differing cross-family lineage-assessment-family",
                }
            )

    lineage_rows: list[dict[str, Any]] = []
    for (pair, lineage), rows in sorted(_group(observations, lambda row: (row["pair"], row["lineage_id"])).items()):
        differing = [row for row in rows if row["effective_different"]]
        categories = {row["source_category"] for row in differing}
        if not differing:
            category = "NO_FINAL_DIFFERENCE"
        elif categories == {"UNRESOLVED"}:
            category = "UNRESOLVED"
        elif "UNRESOLVED" in categories:
            category = "PARTLY_UNRESOLVED"
        elif categories == {"UPSTREAM_DIFFERENCE_INHERITED"}:
            category = "UPSTREAM_ONLY"
        elif categories == {"DOWNSTREAM_INTRODUCED"}:
            category = "DOWNSTREAM_INTRODUCED_ONLY"
        elif categories == {"DOWNSTREAM_AMPLIFIED_OR_MODIFIED"}:
            category = "DOWNSTREAM_AMPLIFIED_ONLY"
        else:
            category = "MIXED_RESOLVED_SOURCES"
        lineage_rows.append(
            {
                "pair": pair,
                "lineage_id": lineage,
                "project": rows[0]["project"],
                "source_profile": category,
                "differing_families": len(differing),
                "resolved_differing_families": sum(row["source_category"] != "UNRESOLVED" for row in differing),
                "analysis_classification": REVISION_CLASSIFICATION,
                "observational_unit": "cross-family lineage",
            }
        )
    return observations, summaries, final_difference_summaries, resolved_difference_summaries, lineage_rows


def divergence_magnitude(
    states: list[dict[str, str]], cohorts: dict[str, set[str]], projects: dict[str, str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    index, assessments = _state_indexes(states)
    rows: list[dict[str, Any]] = []
    for left, right, pair, family_type in PAIR_SPECS:
        if family_type != "CROSS_FAMILY":
            continue
        for lineage in sorted(cohorts["C1X"]):
            common = assessments[(lineage, left, "E")] & assessments[(lineage, right, "E")]
            families: dict[str, list[str]] = defaultdict(list)
            for assessment in common:
                families[assessment_family(assessment)].append(assessment)
            if not families:
                continue
            different = sum(
                any(
                    index[(lineage, left, "E", item)]["normalized_state"]
                    != index[(lineage, right, "E", item)]["normalized_state"]
                    for item in family_assessments
                )
                for family_assessments in families.values()
            )
            rows.append(
                {
                    "pair": pair,
                    "lineage_id": lineage,
                    "project": projects[lineage],
                    "different_families": different,
                    "comparable_families": len(families),
                    "disagreement_proportion": different / len(families),
                    "magnitude_bin": "0" if different == 0 else ("1" if different == 1 else ("2–3" if different <= 3 else "≥4")),
                    "analysis_classification": "derived descriptive analysis",
                    "observational_unit": "cross-family lineage",
                }
            )
    summaries: list[dict[str, Any]] = []
    for pair, pair_rows in sorted(_group(rows, lambda row: row["pair"]).items()):
        differing = [row for row in pair_rows if row["different_families"] > 0]
        for scope, selected in (("ALL_COMPARABLE", pair_rows), ("DIVERGENT_ONLY", differing)):
            median, low, high, project_count = cluster_stat_ci(
                selected,
                "disagreement_proportion",
                f"revision:magnitude:median:{pair}:{scope}",
            )
            values = [row["disagreement_proportion"] for row in selected]
            summary = {
                "pair": pair,
                "scope": scope,
                "lineages": len(selected),
                "projects": project_count,
                "median": median,
                "median_ci_low": low,
                "median_ci_high": high,
                "iqr_low": float(np.quantile(values, 0.25)) if values else None,
                "iqr_high": float(np.quantile(values, 0.75)) if values else None,
                "p90": float(np.quantile(values, 0.90)) if values else None,
                "maximum": max(values) if values else None,
                "exactly_one": sum(row["different_families"] == 1 for row in selected),
                "two_to_three": sum(2 <= row["different_families"] <= 3 for row in selected),
                "four_or_more": sum(row["different_families"] >= 4 for row in selected),
                "analysis_classification": "derived descriptive analysis",
                "observational_unit": "cross-family lineage",
            }
            summaries.append(summary)
    return rows, summaries


def cluster_rate_contrast_ci(
    focal: list[dict[str, Any]], reference: list[dict[str, Any]], endpoint: str
) -> tuple[float, float, float, int]:
    projects = sorted({row["project"] for row in focal} | {row["project"] for row in reference})
    values: dict[str, list[float]] = {project: [0.0, 0.0, 0.0, 0.0] for project in projects}
    for row in focal:
        values[row["project"]][0] += int(row["differing"])
        values[row["project"]][1] += 1
    for row in reference:
        values[row["project"]][2] += int(row["differing"])
        values[row["project"]][3] += 1
    matrix = np.asarray([values[project] for project in projects])
    totals = matrix.sum(axis=0)
    point = float(totals[0] / totals[1] - totals[2] / totals[3])
    rng = np.random.default_rng(_endpoint_seed(endpoint))
    bootstrap: list[float] = []
    for _ in range(BOOTSTRAPS):
        sample = matrix[rng.integers(0, len(matrix), len(matrix))].sum(axis=0)
        if sample[1] and sample[3]:
            bootstrap.append(float(sample[0] / sample[1] - sample[2] / sample[3]))
    return point, float(np.quantile(bootstrap, 0.025)), float(np.quantile(bootstrap, 0.975)), len(projects)


def derivative_contrasts(pair_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    reference = [row for row in pair_rows if row["pair"] == "Debian ↔ Ubuntu"]
    output: list[dict[str, Any]] = []
    for pair, rows in sorted(_group(
        [row for row in pair_rows if row["family_type"] == "CROSS_FAMILY"], lambda row: row["pair"]
    ).items()):
        point, low, high, projects = cluster_rate_contrast_ci(
            rows, reference, f"revision:derivative-contrast:{pair}"
        )
        output.append(
            {
                "contrast": f"{pair} minus Debian ↔ Ubuntu",
                "cross_family_pair": pair,
                "cross_family_numerator": sum(row["differing"] for row in rows),
                "cross_family_denominator": len(rows),
                "derivative_numerator": sum(row["differing"] for row in reference),
                "derivative_denominator": len(reference),
                "absolute_percentage_point_difference": point * 100,
                "ci_low_percentage_points": low * 100,
                "ci_high_percentage_points": high * 100,
                "cluster_projects_union": projects,
                "analysis_classification": REVISION_CLASSIFICATION,
                "observational_unit": "pairwise lineage with upstream-project cluster",
            }
        )
    return output


def grouped_transform_records(
    transformations: list[dict[str, str]], cohorts: dict[str, set[str]], projects: dict[str, str]
) -> list[dict[str, Any]]:
    eligible = [
        row
        for row in transformations
        if row["transition"] == "U_P" and row["lineage_id"] in cohorts["C3X"]
    ]
    output: list[dict[str, Any]] = []
    for (distribution, lineage, family), rows in sorted(_group(
        eligible,
        lambda row: (row["distribution"], row["lineage_id"], assessment_family(row["assessment_id"])),
    ).items()):
        categories = {row["provenance_category"] for row in rows if row["provenance_category"] != "INHERITED_SAME"}
        category = (
            "INHERITED_SAME"
            if not categories
            else ("ADDED" if categories == {"ADDED"} else ("REMOVED" if categories == {"REMOVED"} else "MODIFIED"))
        )
        output.append(
            {
                "distribution": distribution,
                "lineage_id": lineage,
                "project": projects[lineage],
                "assessment_family": family,
                "category": category,
            }
        )
    return output


def transformation_family_tables(
    composite: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    family_rows: list[dict[str, Any]] = []
    change_rates: list[dict[str, Any]] = []
    for distribution in ("ALL", "debian", "ubuntu", "fedora", "arch"):
        selected = composite if distribution == "ALL" else [row for row in composite if row["distribution"] == distribution]
        point, low, high, projects = cluster_ratio_ci(
            selected,
            lambda row: int(row["category"] != "INHERITED_SAME"),
            lambda _: 1,
            f"revision:rq3:grouped-change:{distribution}",
        )
        change_rates.append(
            {
                "distribution": distribution,
                "changed": sum(row["category"] != "INHERITED_SAME" for row in selected),
                "denominator": len(selected),
                "projects": projects,
                "change_rate": point,
                "ci_low": low,
                "ci_high": high,
                "analysis_classification": "derived descriptive analysis with pre-specified clustered uncertainty",
                "observational_unit": "lineage-distribution assessment family",
            }
        )
        for family, rows in sorted(_group(selected, lambda row: row["assessment_family"]).items()):
            changed = sum(row["category"] != "INHERITED_SAME" for row in rows)
            estimate, ci_low, ci_high, project_count = cluster_ratio_ci(
                rows,
                lambda row: int(row["category"] != "INHERITED_SAME"),
                lambda _: 1,
                f"revision:rq3:family:{distribution}:{family}",
            )
            family_rows.append(
                {
                    "distribution": distribution,
                    "assessment_family": family,
                    "added": sum(row["category"] == "ADDED" for row in rows),
                    "removed": sum(row["category"] == "REMOVED" for row in rows),
                    "modified": sum(row["category"] == "MODIFIED" for row in rows),
                    "total_changed": changed,
                    "denominator": len(rows),
                    "projects": project_count,
                    "change_rate": estimate,
                    "ci_low": ci_low,
                    "ci_high": ci_high,
                    "analysis_classification": "derived descriptive analysis",
                    "observational_unit": "lineage-distribution assessment family",
                }
            )
    return family_rows, change_rates


def _exec_target(unit: dict[str, str]) -> Path | None:
    try:
        token = shlex.split(unit["exec_start"])[0].lstrip("-+!:@")
    except (IndexError, ValueError):
        return None
    if not token.startswith("/"):
        return None
    return Path(unit["root"]) / token.lstrip("/")


def matching_corroboration(
    lineages: list[dict[str, str]], upstream: list[dict[str, str]], cohorts: dict[str, set[str]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    units = read_csv(NORMALIZED / "service_units.csv")
    unit_index = {(row["distribution"], row["binary_package_id"], row["unit_path"]): row for row in units}
    upstream_index = {(row["lineage_id"], row["distribution"]): row for row in upstream}
    members: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in lineages:
        if row["match_status"] == "MATCHED":
            members[row["lineage_id"]].append(row)
    observations: list[dict[str, Any]] = []
    for lineage in sorted(cohorts["C1"]):
        rows = members[lineage]
        unit_hashes = Counter(
            unit_index.get((row["distribution"], row["binary_package_id"], row["unit_path"]), {}).get("unit_hash", "")
            for row in rows
        )
        upstream_hashes = Counter(
            upstream_index.get((lineage, row["distribution"]), {}).get("u_artifact_hash", "") for row in rows
        )
        source_names = Counter(
            upstream_index.get((lineage, row["distribution"]), {}).get("source_package_id", "") for row in rows
        )
        owned_members = 0
        for row in rows:
            unit = unit_index.get((row["distribution"], row["binary_package_id"], row["unit_path"]), {})
            target = _exec_target(unit) if unit else None
            owned_members += bool(target and (target.exists() or target.is_symlink()))
        signals = {
            "exact_cross_distribution_unit_content": any(value and count >= 2 for value, count in unit_hashes.items()),
            "shared_upstream_artifact_hash": any(value and count >= 2 for value, count in upstream_hashes.items()),
            "execstart_target_package_owned_in_two_or_more_members": owned_members >= 2,
            "shared_source_package_name": any(value and count >= 2 for value, count in source_names.items()),
        }
        strong_signals = (
            signals["exact_cross_distribution_unit_content"],
            signals["shared_upstream_artifact_hash"],
            signals["execstart_target_package_owned_in_two_or_more_members"],
        )
        observations.append(
            {
                "lineage_id": lineage,
                "canonical_upstream_id": rows[0]["canonical_upstream_id"],
                "distribution_members": len(rows),
                "package_owned_exec_members": owned_members,
                **signals,
                "any_strong_orthogonal_corroboration": any(strong_signals),
                "any_orthogonal_corroboration": any(signals.values()),
                "c1x": lineage in cohorts["C1X"],
                "analysis_classification": "post-hoc construct-validation analysis",
                "primary_membership_changed": False,
            }
        )
    summaries: list[dict[str, Any]] = []
    for cohort, selected in (
        ("C1", observations),
        ("C1X", [row for row in observations if row["c1x"]]),
    ):
        for signal in (
            "exact_cross_distribution_unit_content",
            "shared_upstream_artifact_hash",
            "execstart_target_package_owned_in_two_or_more_members",
            "shared_source_package_name",
            "any_strong_orthogonal_corroboration",
            "any_orthogonal_corroboration",
        ):
            summaries.append(
                {
                    "cohort": cohort,
                    "signal": signal,
                    "corroborated_lineages": sum(row[signal] for row in selected),
                    "lineages": len(selected),
                    "proportion": sum(row[signal] for row in selected) / len(selected),
                    "analysis_classification": "post-hoc construct-validation analysis",
                    "primary_membership_changed": False,
                }
            )
    return observations, summaries


def matching_construct_validity_sensitivity(
    states: list[dict[str, str]],
    transformations: list[dict[str, str]],
    cohorts: dict[str, set[str]],
    projects: dict[str, str],
    corroboration: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Restrict existing RQ2/RQ3 estimands to pre-existing corroboration signals.

    These post-hoc subsets do not alter C1X/C3X membership, matching semantics,
    policy normalization, comparability, or bootstrap clustering.  The RQ3 rows
    are filtered only after the existing grouped observational units are built.
    """
    definitions = (
        (
            "EXECSTART_CORROBORATED",
            "execstart_target_package_owned_in_two_or_more_members",
            "package_owned_normalized_execstart_target_in_two_or_more_members",
        ),
        (
            "UPSTREAM_HASH_CORROBORATED",
            "shared_upstream_artifact_hash",
            "shared_recovered_upstream_artifact_hash",
        ),
        (
            "STRONG_SIGNAL_UNION",
            "any_strong_orthogonal_corroboration",
            "byte_identical_unit_or_shared_upstream_hash_or_package_owned_execstart",
        ),
    )
    corroboration_by_lineage = {row["lineage_id"]: row for row in corroboration if row["c1x"]}
    primary_lineage_rows, _, _, _ = pairwise_divergence(states, cohorts, projects)
    primary_cross = [row for row in primary_lineage_rows if row["family_type"] == "CROSS_FAMILY"]
    primary_by_lineage = _group(primary_cross, lambda row: row["lineage_id"])
    primary_comparable = [
        any(row["differing"] for row in rows)
        for rows in primary_by_lineage.values()
    ]
    if not primary_comparable:
        raise RuntimeError("empty primary RQ2 comparison while constructing matching sensitivity")
    primary_rate = sum(primary_comparable) / len(primary_comparable)
    overall_rows: list[dict[str, Any]] = []
    pairwise_rows: list[dict[str, Any]] = []
    rq3_rows: list[dict[str, Any]] = []

    # Build the primary RQ3 observational units once, then apply lineage-only
    # filters.  This preserves the established denominator construction.
    grouped_rq3 = grouped_transform_records(transformations, cohorts, projects)

    for subset, signal, signal_label in definitions:
        selected = {
            lineage
            for lineage, row in corroboration_by_lineage.items()
            if bool(row[signal])
        }
        sensitivity_cohorts = {**cohorts, subset: selected}
        lineage_rows, summaries, _, _ = pairwise_divergence(
            states, sensitivity_cohorts, projects, subset=subset
        )
        cross_lineage_rows = [
            row for row in lineage_rows if row["family_type"] == "CROSS_FAMILY"
        ]
        by_lineage = _group(cross_lineage_rows, lambda row: row["lineage_id"])
        comparable = [
            {
                "project": rows[0]["project"],
                "lineage_id": lineage,
                "differing": any(row["differing"] for row in rows),
            }
            for lineage, rows in sorted(by_lineage.items())
        ]
        rate, low, high, comparable_projects = cluster_ratio_ci(
            comparable,
            lambda row: int(row["differing"]),
            lambda _: 1,
            f"matching-construct-validity:rq2:{subset}:overall",
        )
        if rate is None:
            raise RuntimeError(f"empty RQ2 matching sensitivity subset: {subset}")
        overall_rows.append(
            {
                "subset": subset,
                "analysis": subset,
                "supporting_signal": signal_label,
                "retained_projects": len({projects[lineage] for lineage in selected}),
                "retained_matches": len(selected),
                "comparable_projects": comparable_projects,
                "comparable_matches": len(comparable),
                "differing_matches": sum(row["differing"] for row in comparable),
                "divergence_rate": rate,
                "ci_low": low,
                "ci_high": high,
                "primary_divergence_rate": primary_rate,
                "absolute_percentage_point_difference_from_primary": abs(rate - primary_rate) * 100,
                "analysis_classification": "matching-construct-validity sensitivity analysis",
                "primary_membership_changed": False,
                "observational_unit": "C1X lineage with at least one comparable cross-family pair",
            }
        )
        for row in summaries:
            if row["family_type"] != "CROSS_FAMILY":
                continue
            pairwise_rows.append(
                {
                    "subset": subset,
                    "analysis": subset,
                    "supporting_signal": signal_label,
                    "pair": row["pair"],
                    "retained_projects": row["matched_projects"],
                    "retained_matches": row["tier_a_lineages"],
                    "comparable_projects": row["comparable_projects"],
                    "comparable_matches": row["comparable_lineages"],
                    "differing_matches": row["differing_lineages"],
                    "divergence_rate": row["divergence_rate"],
                    "ci_low": row["divergence_ci_low"],
                    "ci_high": row["divergence_ci_high"],
                    "analysis_classification": "matching-construct-validity sensitivity analysis",
                    "primary_membership_changed": False,
                    "observational_unit": "pairwise C1X lineage",
                }
            )

        if subset not in {"EXECSTART_CORROBORATED", "STRONG_SIGNAL_UNION"}:
            continue
        selected_c3x = selected & cohorts["C3X"]
        selected_grouped = [row for row in grouped_rq3 if row["lineage_id"] in selected_c3x]
        rq3_rate, rq3_low, rq3_high, observed_projects = cluster_ratio_ci(
            selected_grouped,
            lambda row: int(row["category"] != "INHERITED_SAME"),
            lambda _: 1,
            f"matching-construct-validity:rq3:{subset}:overall",
        )
        if rq3_rate is None:
            raise RuntimeError(f"empty RQ3 matching sensitivity subset: {subset}")
        rq3_rows.append(
            {
                "subset": subset,
                "analysis": subset,
                "supporting_signal": signal_label,
                "retained_c3x_projects": len({projects[lineage] for lineage in selected_c3x}),
                "retained_c3x_matches": len(selected_c3x),
                "projects_with_resolved_observations": observed_projects,
                "resolved_policy_group_observations": len(selected_grouped),
                "changed_observations": sum(
                    row["category"] != "INHERITED_SAME" for row in selected_grouped
                ),
                "change_rate": rq3_rate,
                "ci_low": rq3_low,
                "ci_high": rq3_high,
                "analysis_classification": "secondary matching-construct-validity sensitivity analysis",
                "primary_membership_changed": False,
                "observational_unit": "resolved C3X lineage-distribution assessment family",
            }
        )
    return overall_rows, pairwise_rows, rq3_rows


def render_u1_with_packaged_substitutions(template: str, packaged: str) -> tuple[str | None, tuple[str, ...]]:
    assignments = parse_service_assignments(packaged)
    output: list[str] = []
    missing: set[str] = set()
    emitted: set[str] = set()
    in_service = False
    for raw_line in template.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_service = stripped.casefold() == "[service]"
            output.append(raw_line)
            continue
        if stripped.startswith(("#", ";")):
            output.append(raw_line)
            continue
        if in_service and "=" in raw_line and SUBSTITUTION.search(raw_line.split("=", 1)[1]):
            directive = raw_line.split("=", 1)[0].strip()
            if directive not in assignments:
                missing.add(directive)
                continue
            if directive not in emitted:
                output.extend(f"{directive}={value}" for value in assignments[directive])
                emitted.add(directive)
            continue
        output.append(raw_line)
    if missing:
        return None, tuple(sorted(missing))
    return "\n".join(output) + "\n", ()


def _normalized_evaluator_rows(rows: list[dict[str, Any]]) -> dict[str, str]:
    return {
        (row.get("json_field") or row.get("name")): json.dumps(
            {"set": row.get("set"), "exposure": row.get("exposure"), "description": row.get("description")},
            sort_keys=True,
        )
        for row in rows
    }


def u1_projector_validation(
    states: list[dict[str, str]], upstream: list[dict[str, str]], lineages: list[dict[str, str]], cohorts: dict[str, set[str]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    units = read_csv(NORMALIZED / "service_units.csv")
    unit_index = {(row["distribution"], row["binary_package_id"], row["unit_path"]): row for row in units}
    member_index = {
        (row["lineage_id"], row["distribution"]): row for row in lineages if row["match_status"] == "MATCHED"
    }
    u_state_index = {
        (row["lineage_id"], row["distribution"], row["assessment_id"]): row
        for row in states
        if row["layer"] == "U" and row["analysis_status"] == "ANALYZABLE"
    }
    candidates: list[dict[str, Any]] = []
    for row in upstream:
        if row["u_artifact_class"] != "U1_TEMPLATE_VALUE_ONLY" or row["lineage_id"] not in cohorts["C3X"]:
            continue
        member = member_index.get((row["lineage_id"], row["distribution"]))
        unit = unit_index.get((member["distribution"], member["binary_package_id"], member["unit_path"])) if member else None
        source = Path(row["u_source_path"])
        packaged = Path(unit["root"]) / member["unit_path"] if unit and member else None
        if source.exists() and packaged and packaged.exists():
            template_text = source.read_text(encoding="utf-8", errors="replace")
            packaged_text = packaged.read_text(encoding="utf-8", errors="replace")
            rendered, missing = render_u1_with_packaged_substitutions(template_text, packaged_text)
        else:
            template_text = packaged_text = ""
            rendered, missing = None, ("ARTIFACT_UNAVAILABLE",)
        candidates.append(
            {
                "upstream": row,
                "template": template_text,
                "packaged": packaged_text,
                "rendered": rendered,
                "missing": missing,
            }
        )

    VALIDATION.mkdir(parents=True, exist_ok=True)

    def validate(candidate: dict[str, Any]) -> dict[str, Any]:
        upstream_row = candidate["upstream"]
        if candidate["rendered"] is None:
            return {
                "lineage_id": upstream_row["lineage_id"],
                "distribution": upstream_row["distribution"],
                "status": "UNRESOLVED_SUBSTITUTION",
                "missing_substitutions": ";".join(candidate["missing"]),
                "fine_resolved": 0,
                "fine_exact": 0,
                "grouped_resolved": 0,
                "grouped_exact": 0,
                "literal_assignments": 0,
                "literal_assignments_preserved": 0,
                "disagreeing_assessments": "",
                "cache_sha256": "",
            }
        cache_key = hashlib.sha256(
            b"unittrace:u1-projector-validation:v1\0"
            + candidate["template"].encode()
            + b"\0"
            + candidate["packaged"].encode()
            + b"\0"
            + sha256_file(EVALUATOR).encode()
            + b"\0"
            + sha256_file(POLICY).encode()
        ).hexdigest()
        cache_path = VALIDATION / f"{cache_key}.json"
        if cache_path.exists():
            evaluation = json.loads(cache_path.read_text(encoding="utf-8"))
        else:
            with tempfile.TemporaryDirectory(prefix="render-", dir=VALIDATION) as temporary:
                root = Path(temporary)
                make_minimal_root(root)
                unit_name = "unittrace-u1-validation.service"
                (root / "usr/lib/systemd/system" / unit_name).write_text(candidate["rendered"], encoding="utf-8")
                status, rows, detail = evaluate_unit(EVALUATOR, POLICY, root, unit_name)
                evaluation = {"status": status, "detail": detail, "states": _normalized_evaluator_rows(rows)}
                atomic_json(cache_path, evaluation)
        if evaluation["status"] != "ANALYZABLE":
            return {
                "lineage_id": upstream_row["lineage_id"],
                "distribution": upstream_row["distribution"],
                "status": evaluation["status"],
                "missing_substitutions": "",
                "fine_resolved": 0,
                "fine_exact": 0,
                "grouped_resolved": 0,
                "grouped_exact": 0,
                "literal_assignments": 0,
                "literal_assignments_preserved": 0,
                "disagreeing_assessments": "",
                "cache_sha256": sha256_file(cache_path),
            }
        comparable: list[tuple[str, bool]] = []
        for (lineage, distribution, assessment), old in u_state_index.items():
            if lineage != upstream_row["lineage_id"] or distribution != upstream_row["distribution"]:
                continue
            if old["dimension_provenance_status"] not in RESOLVED or assessment not in evaluation["states"]:
                continue
            comparable.append((assessment, old["normalized_state"] == evaluation["states"][assessment]))
        families: dict[str, list[bool]] = defaultdict(list)
        for assessment, agrees in comparable:
            families[assessment_family(assessment)].append(agrees)
        projection = project_service_template(candidate["template"])
        projected_assignments = parse_service_assignments(projection.projected_text)
        rendered_assignments = parse_service_assignments(candidate["rendered"])
        literal_total = sum(len(values) for values in projected_assignments.values())
        literal_preserved = sum(
            min(Counter(values)[value], Counter(rendered_assignments.get(directive, []))[value])
            for directive, values in projected_assignments.items()
            for value in set(values)
        )
        return {
            "lineage_id": upstream_row["lineage_id"],
            "distribution": upstream_row["distribution"],
            "status": "VALIDATED",
            "missing_substitutions": "",
            "fine_resolved": len(comparable),
            "fine_exact": sum(agrees for _, agrees in comparable),
            "grouped_resolved": len(families),
            "grouped_exact": sum(all(values) for values in families.values()),
            "literal_assignments": literal_total,
            "literal_assignments_preserved": literal_preserved,
            "disagreeing_assessments": ";".join(sorted(assessment for assessment, agrees in comparable if not agrees)),
            "cache_sha256": sha256_file(cache_path),
        }

    with ThreadPoolExecutor(max_workers=16) as executor:
        observations = list(executor.map(validate, candidates))
    validated = [row for row in observations if row["status"] == "VALIDATED"]
    summary = [
        {
            "candidate_observations": len(observations),
            "validated_observations": len(validated),
            "unresolved_observations": len(observations) - len(validated),
            "fine_resolved": sum(row["fine_resolved"] for row in validated),
            "fine_exact": sum(row["fine_exact"] for row in validated),
            "fine_agreement": (
                sum(row["fine_exact"] for row in validated) / sum(row["fine_resolved"] for row in validated)
            ),
            "grouped_resolved": sum(row["grouped_resolved"] for row in validated),
            "grouped_exact": sum(row["grouped_exact"] for row in validated),
            "grouped_agreement": (
                sum(row["grouped_exact"] for row in validated) / sum(row["grouped_resolved"] for row in validated)
            ),
            "literal_assignments": sum(row["literal_assignments"] for row in validated),
            "literal_assignments_preserved": sum(row["literal_assignments_preserved"] for row in validated),
            "disagreeing_observations": sum(bool(row["disagreeing_assessments"]) for row in validated),
            "analysis_classification": "post-hoc construct-validation analysis",
            "interpretation": "Packaged values render only template value placeholders; agreement is evaluated exclusively on dimensions the frozen projector marked resolved.",
        }
    ]
    return observations, summary


def deterministic_examples(
    composite: list[dict[str, Any]],
    magnitudes: list[dict[str, Any]],
    attributions: list[dict[str, Any]],
    states: list[dict[str, str]],
) -> list[dict[str, Any]]:
    index, assessments = _state_indexes(states)
    selected: list[tuple[str, str, str, str, list[str], str]] = []
    changed = [row for row in composite if row["category"] != "INHERITED_SAME"]
    common_pattern = Counter((row["assessment_family"], row["category"]) for row in changed).most_common(1)[0][0]
    pattern_row = min(
        (row for row in changed if (row["assessment_family"], row["category"]) == common_pattern),
        key=lambda row: (row["lineage_id"], row["distribution"]),
    )
    selected.append((
        "MOST_COMMON_U_P_PATTERN",
        pattern_row["lineage_id"],
        pattern_row["distribution"],
        "",
        [pattern_row["assessment_family"]],
        f"most frequent family/category cell ({common_pattern[0]} {common_pattern[1]}), lexical tie-break",
    ))
    maximum = min(
        magnitudes,
        key=lambda row: (-row["different_families"], -row["disagreement_proportion"], row["pair"], row["lineage_id"]),
    )
    left, right = next((left, right) for left, right, pair, _ in PAIR_SPECS if pair == maximum["pair"])
    common = assessments[(maximum["lineage_id"], left, "E")] & assessments[(maximum["lineage_id"], right, "E")]
    families = sorted({assessment_family(item) for item in common if index[(maximum["lineage_id"], left, "E", item)]["normalized_state"] != index[(maximum["lineage_id"], right, "E", item)]["normalized_state"]})
    selected.append((
        "MAXIMUM_CROSS_FAMILY_MAGNITUDE",
        maximum["lineage_id"],
        left,
        right,
        families,
        "maximum differing grouped-family count, then proportion, pair, and lineage lexical tie-break",
    ))
    lineage_distribution = _group(composite, lambda row: (row["lineage_id"], row["distribution"]))
    inherited_candidates = [
        (key, rows)
        for key, rows in lineage_distribution.items()
        if all(row["category"] == "INHERITED_SAME" for row in rows)
    ]
    inherited_key, inherited_rows = min(
        inherited_candidates,
        key=lambda item: (-len(item[1]), item[0][0], item[0][1]),
    )
    selected.append((
        "MAXIMUM_RESOLVED_INHERITANCE",
        inherited_key[0],
        inherited_key[1],
        "",
        sorted(row["assessment_family"] for row in inherited_rows)[:4],
        "zero changed families, maximum resolved-family count, lexical tie-break; first four families displayed",
    ))
    converged = [row for row in attributions if row["source_category"] == "DOWNSTREAM_CONVERGED"]
    if converged:
        convergence = min(converged, key=lambda row: (row["pair"], row["lineage_id"], row["assessment_family"]))
        selected.append((
            "DOWNSTREAM_CONVERGENCE",
            convergence["lineage_id"],
            convergence["left_distribution"],
            convergence["right_distribution"],
            [convergence["assessment_family"]],
            "lexically first deterministically resolved downstream-converged family",
        ))
    output: list[dict[str, Any]] = []
    for example, lineage, left, right, families, rule in selected:
        for distribution in [left] + ([right] if right else []):
            for family in families:
                ids = sorted(
                    item for item in assessments[(lineage, distribution, "E")] if assessment_family(item) == family
                )
                output.append(
                    {
                        "example_type": example,
                        "selection_rule": rule,
                        "lineage_id": lineage,
                        "project": lineage.split("::", 1)[0],
                        "distribution": distribution,
                        "comparison_distribution": right if distribution == left else left,
                        "assessment_family": family,
                        "u_states": json.dumps(
                            [index[(lineage, distribution, "U", item)]["normalized_state"] for item in ids if (lineage, distribution, "U", item) in index],
                            separators=(",", ":"),
                        ),
                        "p_states": json.dumps(
                            [index[(lineage, distribution, "P", item)]["normalized_state"] for item in ids if (lineage, distribution, "P", item) in index],
                            separators=(",", ":"),
                        ),
                        "e_states": json.dumps(
                            [index[(lineage, distribution, "E", item)]["normalized_state"] for item in ids],
                            separators=(",", ":"),
                        ),
                        "analysis_classification": "post-hoc explanatory example selected by pre-declared deterministic rule",
                    }
                )
    return output


def _save_figure(fig: Any, stem: str) -> None:
    metadata = {
        "Creator": "UnitTrace revision pipeline",
        "CreationDate": datetime(2026, 8, 9, tzinfo=timezone.utc),
    }
    for extension in ("svg", "pdf", "png"):
        kwargs: dict[str, Any] = {"bbox_inches": "tight"}
        if extension == "png":
            kwargs["dpi"] = 300
        elif extension == "pdf":
            kwargs["metadata"] = metadata
        elif extension == "svg":
            kwargs["metadata"] = {"Date": "2026-08-09", "Creator": "UnitTrace revision pipeline"}
        fig.savefig(FIGURES / f"{stem}.{extension}", **kwargs)


def write_revision_figures(
    source_summary: list[dict[str, Any]], magnitude_summary: list[dict[str, Any]],
    change_rates: list[dict[str, Any]], family_rows: list[dict[str, Any]],
) -> None:
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

    plt.rcParams.update({
        "font.size": 8,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "figure.dpi": 160,
        "svg.hashsalt": "unittrace-v4.2-revision",
    })
    FIGURES.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(6.6, 2.0))
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    boxes = [(0.06, "U", "Corresponding upstream\nunit or template"), (0.39, "P", "Package-local\nservice policy"), (0.72, "E", "Clean distribution-\neffective policy")]
    for x, label, detail in boxes:
        ax.add_patch(FancyBboxPatch((x, .27), .22, .46, boxstyle="round,pad=0.015", facecolor="#f4f6f8", edgecolor="#44546a", linewidth=1))
        ax.text(x + .11, .59, label, ha="center", va="center", fontsize=13)
        ax.text(x + .11, .40, detail, ha="center", va="center", fontsize=8)
    for start, end, text in ((.28, .39, "packaging"), (.61, .72, "loading / precedence")):
        ax.add_patch(FancyArrowPatch((start, .50), (end, .50), arrowstyle="-|>", mutation_scale=10, color="#44546a"))
        ax.text((start + end) / 2, .64, text, ha="center", fontsize=7)
    ax.text(.5, .08, "Attribution asks whether an E-level difference was inherited, introduced, modified, or converged along this chain.", ha="center", fontsize=7.5)
    _save_figure(fig, "upe_provenance_flow"); plt.close(fig)

    pairs = [row["pair"] for row in source_summary if row["source_category"] == "UNRESOLVED"]
    categories = ["UPSTREAM_DIFFERENCE_INHERITED", "DOWNSTREAM_INTRODUCED", "DOWNSTREAM_AMPLIFIED_OR_MODIFIED", "UNRESOLVED"]
    labels = ["Inherited upstream", "Downstream introduced", "Downstream modified", "Unresolved"]
    colors = ["#4c78a8", "#59a14f", "#b279a2", "#9a9a9a"]
    fig, ax = plt.subplots(figsize=(6.6, 3.1)); bottom = np.zeros(len(pairs))
    for category, label, color in zip(categories, labels, colors):
        values = np.array([next(row["proportion"] for row in source_summary if row["pair"] == pair and row["source_category"] == category) for pair in pairs])
        ax.barh(pairs, values, left=bottom, label=label, color=color); bottom += values
    ax.invert_yaxis(); ax.set_xlim(0, 1); ax.set_xlabel("Share of E-differing lineage-policy-group observations")
    ax.legend(frameon=False, ncol=2, loc="lower center", bbox_to_anchor=(.5, 1.0)); _save_figure(fig, "divergence_source"); plt.close(fig)

    divergent = [row for row in magnitude_summary if row["scope"] == "DIVERGENT_ONLY"]
    fig, ax = plt.subplots(figsize=(6.6, 3.1)); y = np.arange(len(divergent)); left = np.zeros(len(divergent))
    for field, label, color in (("exactly_one", "1 group", "#9ecae1"), ("two_to_three", "2–3 groups", "#4c78a8"), ("four_or_more", "≥4 groups", "#315a7d")):
        values = np.array([row[field] / row["lineages"] for row in divergent])
        ax.barh(y, values, left=left, label=label, color=color); left += values
    ax.set_yticks(y, [row["pair"] for row in divergent]); ax.invert_yaxis(); ax.set_xlim(0, 1)
    ax.set_xlabel("Share among divergent matches"); ax.legend(frameon=False, ncol=3, loc="lower center", bbox_to_anchor=(.5, 1.0))
    _save_figure(fig, "divergence_magnitude"); plt.close(fig)

    distributions = ["debian", "ubuntu", "fedora", "arch"]
    fig, axes = plt.subplots(1, 2, figsize=(7.1, 3.0), gridspec_kw={"width_ratios": [1, 1.25]})
    rates = [next(row["change_rate"] for row in change_rates if row["distribution"] == distribution) for distribution in distributions]
    axes[0].bar(distributions, np.array(rates) * 100, color="#4c78a8")
    axes[0].set_ylabel("Changed resolved U→P policy groups (%)"); axes[0].set_ylim(0, max(rates) * 125)
    axes[0].set_title("A. Inheritance dominates")
    categories = [("added", "Added", "#59a14f"), ("removed", "Removed", "#e15759"), ("modified", "Modified", "#b279a2")]
    bottom = np.zeros(4)
    for field, label, color in categories:
        values = np.array([
            sum(row[field] for row in family_rows if row["distribution"] == distribution)
            for distribution in distributions
        ], dtype=float)
        axes[1].bar(distributions, values, bottom=bottom, label=label, color=color); bottom += values
    axes[1].set_ylabel("Changed lineage-policy-group observations"); axes[1].set_title("B. Composition of the changed minority")
    axes[1].legend(frameon=False, ncol=3, fontsize=7); fig.tight_layout()
    _save_figure(fig, "upstream_package_transformations"); plt.close(fig)


def _write_outputs(outputs: dict[str, list[dict[str, Any]]]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for name, rows in outputs.items():
        if not rows:
            continue
        fields = list(rows[0])
        ordered_rows = presentation_order_pair_rows(rows)
        write_csv(ANALYSIS / name, ordered_rows, fields)
        write_csv(TABLES / name, ordered_rows, fields)
        hashes[name] = sha256_file(ANALYSIS / name)
    return hashes


def run() -> dict[str, Any]:
    states = read_csv(NORMALIZED / "policy_states.csv")
    transformations = read_csv(NORMALIZED / "transformations.csv")
    upstream = read_csv(NORMALIZED / "upstream_artifacts.csv")
    lineages = read_csv(NORMALIZED / "service_lineages.csv")
    cohorts, projects = _cohorts()
    (
        attributions,
        attribution_all,
        attribution_differences,
        attribution_resolved_differences,
        attribution_lineages,
    ) = divergence_attribution(states, cohorts, projects)
    magnitude_rows, magnitude_summary = divergence_magnitude(states, cohorts, projects)
    primary_pair_rows = read_csv(ANALYSIS / "rq2_lineage_divergence.csv")
    pair_rows_typed = [
        {**row, "differing": row["differing"].casefold() == "true", "project": row["project"]}
        for row in primary_pair_rows
    ]
    contrasts = derivative_contrasts(pair_rows_typed)
    composite = grouped_transform_records(transformations, cohorts, projects)
    family_rows, change_rates = transformation_family_tables(composite)
    corroboration_rows, corroboration_summary = matching_corroboration(lineages, upstream, cohorts)
    sensitivity_overall, sensitivity_pairwise, sensitivity_rq3 = matching_construct_validity_sensitivity(
        states, transformations, cohorts, projects, corroboration_rows
    )
    u1_rows, u1_summary = u1_projector_validation(states, upstream, lineages, cohorts)
    examples = deterministic_examples(composite, magnitude_rows, attributions, states)
    outputs = {
        "revision_divergence_source_observations.csv": attributions,
        "revision_divergence_source_summary.csv": attribution_all,
        "revision_divergence_source_effective_differences.csv": attribution_differences,
        "revision_divergence_source_resolved_effective_differences.csv": attribution_resolved_differences,
        "revision_divergence_source_lineages.csv": attribution_lineages,
        "revision_divergence_magnitude_lineages.csv": magnitude_rows,
        "revision_divergence_magnitude_summary.csv": magnitude_summary,
        "revision_derivative_contrasts.csv": contrasts,
        "revision_rq3_family_transformations.csv": family_rows,
        "revision_rq3_grouped_change_rates.csv": change_rates,
        "revision_matching_corroboration.csv": corroboration_rows,
        "revision_matching_corroboration_summary.csv": corroboration_summary,
        "matching_construct_validity_rq2_overall.csv": sensitivity_overall,
        "matching_construct_validity_rq2_pairwise.csv": sensitivity_pairwise,
        "matching_construct_validity_rq3.csv": sensitivity_rq3,
        "revision_u1_projector_validation.csv": u1_rows,
        "revision_u1_projector_validation_summary.csv": u1_summary,
        "revision_deterministic_examples.csv": examples,
    }
    first = _write_outputs(outputs)
    second = _write_outputs(outputs)
    if first != second:
        raise RuntimeError("revision analysis outputs are not byte-equivalent")
    write_revision_figures(attribution_differences, magnitude_summary, change_rates, family_rows)
    # The premium renderer deliberately runs last so the prospectively frozen
    # analysis stays untouched while publication assets share one editorial skin.
    from .premium_figures import run as render_premium_figures

    premium_figures = render_premium_figures()
    manifest = {
        "analysis_classification": {
            "divergence_magnitude": "derived descriptive analysis; lineage magnitude was pre-specified in v4.2, revised bins are descriptive",
            "rq3_family_profile": "derived descriptive analysis of pre-specified RQ3 dimension frequencies",
            "divergence_source_attribution": REVISION_CLASSIFICATION,
            "derivative_contrasts": REVISION_CLASSIFICATION,
            "matching_corroboration": "post-hoc construct-validation analysis",
            "matching_construct_validity_sensitivity": "post-hoc matching-construct-validity sensitivity analysis",
            "u1_projector_validation": "post-hoc construct-validation analysis",
            "deterministic_examples": "post-hoc explanatory examples selected by fixed automatic rules",
        },
        "bootstrap_seed": 420260809,
        "bootstrap_replicates": BOOTSTRAPS,
        "output_hashes": first,
        "byte_equivalent_repeated_write": first == second,
        "frozen_normalized_input_sha256": json.loads((ARTIFACTS / "manifests/determinism_manifest.json").read_text())["normalized_output_hash"],
        "premium_figure_validation": "artifacts/full/manifests/premium_figure_validation.json",
        "premium_figure_validation_pass": premium_figures["all_pass"],
        "rq3d_status": "RQ3d_DISABLED",
    }
    atomic_json(ARTIFACTS / "manifests/revision_analysis_manifest.json", manifest)
    return manifest


if __name__ == "__main__":
    run()
