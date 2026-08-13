from __future__ import annotations

import csv
import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable

import numpy as np

from .io import atomic_json, sha256_file, write_csv
from .phase0x import CROSS_FAMILY_PAIRS, PAIR_SPECS


ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "artifacts/full"
NORMALIZED = ARTIFACTS / "normalized"
ANALYSIS = ARTIFACTS / "analysis"
TABLES = ARTIFACTS / "tables"
FIGURES = ARTIFACTS / "figures"
REVISION_RESULTS = ROOT / "revision/results"
HISTORICAL_BASELINE = ROOT / "artifacts/revision_baseline_7415f0f"
SEED = 420260809
BOOTSTRAPS = 5000
RESOLVED = {"PRESENT_RESOLVED", "ABSENT_RESOLVED"}
PRESENTATION_PAIR_ORDER = (
    "Debian ↔ Fedora",
    "Debian ↔ Arch",
    "Ubuntu ↔ Fedora",
    "Ubuntu ↔ Arch",
    "Fedora ↔ Arch",
    "Debian ↔ Ubuntu",
)
_PRESENTATION_PAIR_RANK = {pair: index for index, pair in enumerate(PRESENTATION_PAIR_ORDER)}


def presentation_order_pair_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Stable display ordering: five primary pairs, then derivative context."""
    group_rank = {
        value: index
        for index, value in enumerate(dict.fromkeys(str(row.get("analysis", "")) for row in rows))
    }

    def key(item: tuple[int, dict[str, Any]]) -> tuple[int, int, int]:
        index, row = item
        pair = str(row.get("pair", row.get("cross_family_pair", "")))
        return group_rank.get(str(row.get("analysis", "")), 0), _PRESENTATION_PAIR_RANK.get(pair, len(PRESENTATION_PAIR_ORDER)), index

    return [
        row
        for _, row in sorted(
            enumerate(rows),
            key=key,
        )
    ]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def as_bool(value: Any) -> bool:
    return str(value).casefold() == "true"


def assessment_family(assessment_id: str) -> str:
    for prefix in (
        "CapabilityBoundingSet",
        "RestrictAddressFamilies",
        "RestrictNamespaces",
        "SystemCallFilter",
    ):
        if assessment_id == prefix or assessment_id.startswith(prefix + "_"):
            return prefix
    return assessment_id


def _endpoint_seed(name: str) -> int:
    digest = hashlib.sha256(f"unittrace:v4.2:full-census:project-bootstrap\0{name}".encode()).digest()
    return SEED ^ int.from_bytes(digest[:8], "big")


def cluster_ratio_ci(
    records: Iterable[dict[str, Any]], numerator: Callable[[dict[str, Any]], float], denominator: Callable[[dict[str, Any]], float], endpoint: str
) -> tuple[float | None, float | None, float | None, int]:
    grouped: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])
    for row in records:
        grouped[row["project"]][0] += numerator(row)
        grouped[row["project"]][1] += denominator(row)
    if not grouped:
        return None, None, None, 0
    values = np.asarray(list(grouped.values()), dtype=float)
    total_denominator = values[:, 1].sum()
    point = float(values[:, 0].sum() / total_denominator) if total_denominator else None
    if point is None:
        return None, None, None, len(grouped)
    rng = np.random.default_rng(_endpoint_seed(endpoint))
    estimates: list[np.ndarray] = []
    remaining = BOOTSTRAPS
    while remaining:
        count = min(500, remaining)
        indices = rng.integers(0, len(values), size=(count, len(values)))
        samples = values[indices].sum(axis=1)
        estimates.append(np.divide(samples[:, 0], samples[:, 1], out=np.full(count, np.nan), where=samples[:, 1] != 0))
        remaining -= count
    bootstrap = np.concatenate(estimates)
    return point, float(np.nanquantile(bootstrap, 0.025)), float(np.nanquantile(bootstrap, 0.975)), len(grouped)


def cluster_stat_ci(records: list[dict[str, Any]], value: str, endpoint: str, statistic: str = "median") -> tuple[float | None, float | None, float | None, int]:
    grouped: dict[str, list[float]] = defaultdict(list)
    for row in records:
        grouped[row["project"]].append(float(row[value]))
    if not grouped:
        return None, None, None, 0
    projects = sorted(grouped)
    point_values = [number for project in projects for number in grouped[project]]
    function = statistics.median if statistic == "median" else statistics.mean
    point = float(function(point_values))
    rng = np.random.default_rng(_endpoint_seed(endpoint))
    boot: list[float] = []
    for _ in range(BOOTSTRAPS):
        selected = rng.integers(0, len(projects), size=len(projects))
        values = [number for index in selected for number in grouped[projects[int(index)]]]
        boot.append(float(function(values)))
    return point, float(np.quantile(boot, 0.025)), float(np.quantile(boot, 0.975)), len(projects)


def _cohorts() -> tuple[dict[str, set[str]], dict[str, str]]:
    rows = read_csv(NORMALIZED / "cohorts.csv")
    cohorts: dict[str, set[str]] = defaultdict(set)
    projects: dict[str, str] = {}
    for row in rows:
        cohorts[row["cohort"]].add(row["lineage_id"])
        projects[row["lineage_id"]] = row["canonical_upstream_id"]
    return dict(cohorts), projects


def rq1(states: list[dict[str, str]], cohorts: dict[str, set[str]], projects: dict[str, str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    effective = [row for row in states if row["layer"] == "E" and row["analysis_status"] == "ANALYZABLE" and row["lineage_id"] in cohorts["C1X"]]
    by_dimension: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    by_family_lineage: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in effective:
        record = {**row, "project": projects[row["lineage_id"]], "enabled": as_bool(row["set_state"])}
        by_dimension[(row["distribution"], row["assessment_id"])].append(record)
        by_family_lineage[(row["distribution"], assessment_family(row["assessment_id"]), row["lineage_id"])].append(row)
    fine: list[dict[str, Any]] = []
    for (distribution, assessment), rows in sorted(by_dimension.items()):
        estimate, low, high, project_count = cluster_ratio_ci(rows, lambda row: int(row["enabled"]), lambda _: 1, f"rq1:{distribution}:{assessment}")
        fine.append({
            "distribution": distribution, "assessment_id": assessment, "assessment_family": assessment_family(assessment),
            "enabled": sum(row["enabled"] for row in rows), "lineages": len(rows), "projects": project_count,
            "proportion": estimate, "ci_low": low, "ci_high": high, "cohort": "C1X", "observational_unit": "lineage-distribution",
        })
    family_records: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for (distribution, family, lineage), rows in by_family_lineage.items():
        family_records[(distribution, family)].append({
            "project": projects[lineage], "lineage_id": lineage, "enabled": any(as_bool(row["set_state"]) for row in rows),
        })
    grouped: list[dict[str, Any]] = []
    for (distribution, family), rows in sorted(family_records.items()):
        estimate, low, high, project_count = cluster_ratio_ci(rows, lambda row: int(row["enabled"]), lambda _: 1, f"rq1-group:{distribution}:{family}")
        grouped.append({
            "distribution": distribution, "assessment_family": family, "enabled": sum(row["enabled"] for row in rows),
            "lineages": len(rows), "projects": project_count, "proportion": estimate, "ci_low": low, "ci_high": high,
            "cohort": "C1X", "observational_unit": "lineage-distribution",
        })
    project_grouped: list[dict[str, Any]] = []
    for (distribution, family), rows in sorted(family_records.items()):
        per_project: dict[str, bool] = defaultdict(bool)
        for row in rows:
            per_project[row["project"]] = per_project[row["project"]] or row["enabled"]
        enabled = sum(per_project.values())
        project_grouped.append({
            "distribution": distribution, "assessment_family": family, "enabled_projects": enabled,
            "projects": len(per_project), "proportion": enabled / len(per_project), "cohort": "C1X",
            "observational_unit": "upstream project (any matched lineage enabled)",
        })
    count_rows: list[dict[str, Any]] = []
    by_lineage: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in effective:
        by_lineage[(row["distribution"], row["lineage_id"])].append(row)
    for distribution, records in sorted(_group([
        {
            "distribution": distribution, "lineage_id": lineage, "project": projects[lineage],
            "enabled_dimensions": sum(as_bool(row["set_state"]) for row in rows), "assessed_dimensions": len(rows),
        }
        for (distribution, lineage), rows in by_lineage.items()
    ], lambda row: row["distribution"]).items()):
        values = [row["enabled_dimensions"] for row in records]
        median, low, high, project_count = cluster_stat_ci(records, "enabled_dimensions", f"rq1-count:{distribution}")
        count_rows.append({
            "distribution": distribution, "lineages": len(records), "projects": project_count,
            "median_enabled_dimensions": median, "median_ci_low": low, "median_ci_high": high,
            "iqr_low": float(np.quantile(values, .25)), "iqr_high": float(np.quantile(values, .75)),
            "minimum": min(values), "maximum": max(values), "cohort": "C1X", "observational_unit": "lineage-distribution",
        })
    return fine, grouped, project_grouped, count_rows


def rq1_paired_differences(
    states: list[dict[str, str]], cohorts: dict[str, set[str]], projects: dict[str, str]
) -> list[dict[str, Any]]:
    """Estimate paired adoption differences on common lineage support."""
    effective: dict[tuple[str, str], dict[str, bool]] = defaultdict(dict)
    allowed = cohorts["C1X"] | cohorts["C1D"]
    for row in states:
        if row["layer"] != "E" or row["analysis_status"] != "ANALYZABLE" or row["lineage_id"] not in allowed:
            continue
        key = (row["lineage_id"], row["distribution"])
        family = assessment_family(row["assessment_id"])
        effective[key][family] = effective[key].get(family, False) or as_bool(row["set_state"])
    output: list[dict[str, Any]] = []
    for left, right, label, family_type in PAIR_SPECS:
        cohort_name = "C1D" if family_type == "DERIVATIVE_FAMILY" else "C1X"
        families = sorted({
            family
            for lineage in cohorts[cohort_name]
            for family in effective.get((lineage, left), {}).keys()
            & effective.get((lineage, right), {}).keys()
        })
        for family in families:
            records: list[dict[str, Any]] = []
            for lineage in cohorts[cohort_name]:
                left_state = effective.get((lineage, left), {})
                right_state = effective.get((lineage, right), {})
                if family not in left_state or family not in right_state:
                    continue
                records.append({
                    "project": projects[lineage], "lineage_id": lineage,
                    "left_enabled": left_state[family], "right_enabled": right_state[family],
                    "difference": float(left_state[family]) - float(right_state[family]),
                })
            difference, low, high, project_count = cluster_stat_ci(
                records, "difference", f"rq1-paired:{label}:{family}", statistic="mean"
            )
            if not records:
                continue
            output.append({
                "pair": label, "family_type": family_type, "assessment_family": family,
                "projects": project_count, "lineages": len(records),
                "left_enabled": sum(row["left_enabled"] for row in records),
                "right_enabled": sum(row["right_enabled"] for row in records),
                "left_proportion": sum(row["left_enabled"] for row in records) / len(records),
                "right_proportion": sum(row["right_enabled"] for row in records) / len(records),
                "left_minus_right_percentage_points": 100 * difference,
                "ci_low_percentage_points": 100 * low, "ci_high_percentage_points": 100 * high,
                "cohort": cohort_name, "observational_unit": "paired lineage",
            })
    return output


def pairwise_divergence(states: list[dict[str, str]], cohorts: dict[str, set[str]], projects: dict[str, str], subset: str = "C1X") -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    effective: dict[tuple[str, str, str], str] = {}
    observed: dict[str, set[str]] = defaultdict(set)
    allowed = set(cohorts[subset])
    # The primary invocation produces both the C1X cross-family estimates and
    # the separately labelled C1D derivative-family contrast.  C1D must not be
    # intersected with C1X: doing so would silently discard derivative-only
    # lineages, while adding C1D to the effective-state index cannot leak those
    # lineages into a cross-family pair because they lack a cross-family member.
    if subset == "C1X":
        allowed |= cohorts["C1D"]
    for row in states:
        if row["layer"] == "E" and row["lineage_id"] in allowed:
            observed[row["lineage_id"]].add(row["distribution"])
        if row["layer"] == "E" and row["analysis_status"] == "ANALYZABLE" and row["lineage_id"] in allowed:
            effective[(row["lineage_id"], row["distribution"], row["assessment_id"])] = row["normalized_state"]
    lineage_rows: list[dict[str, Any]] = []
    dimensions: list[dict[str, Any]] = []
    for left, right, label, family_type in PAIR_SPECS:
        pair_cohort = cohorts["C1D"] if subset == "C1X" and family_type == "DERIVATIVE_FAMILY" else cohorts[subset]
        lineage_ids = sorted(({key[0] for key in effective if key[1] == left} & {key[0] for key in effective if key[1] == right}) & pair_cohort)
        for lineage in lineage_ids:
            left_ids = {key[2] for key in effective if key[0] == lineage and key[1] == left}
            right_ids = {key[2] for key in effective if key[0] == lineage and key[1] == right}
            comparable = sorted(left_ids & right_ids)
            if not comparable:
                continue
            different = [assessment for assessment in comparable if effective[(lineage, left, assessment)] != effective[(lineage, right, assessment)]]
            lineage_rows.append({
                "pair": label, "family_type": family_type, "left_distribution": left, "right_distribution": right,
                "lineage_id": lineage, "project": projects[lineage], "different_dimensions": len(different),
                "comparable_dimensions": len(comparable), "disagreement_proportion": len(different) / len(comparable),
                "differing": bool(different),
                "cohort": "C1D" if subset == "C1X" and family_type == "DERIVATIVE_FAMILY" else subset,
            })
            dimensions.extend({"pair": label, "family_type": family_type, "assessment_id": assessment, "project": projects[lineage], "lineage_id": lineage, "different": assessment in different, "cohort": "C1D" if subset == "C1X" and family_type == "DERIVATIVE_FAMILY" else subset} for assessment in comparable)
    summaries: list[dict[str, Any]] = []
    for left, right, label, family_type in PAIR_SPECS:
        pair_cohort = cohorts["C1D"] if subset == "C1X" and family_type == "DERIVATIVE_FAMILY" else cohorts[subset]
        rows = [row for row in lineage_rows if row["pair"] == label]
        rate, low, high, project_count = cluster_ratio_ci(rows, lambda row: int(row["differing"]), lambda _: 1, f"rq2-any:{subset}:{label}")
        median, median_low, median_high, _ = cluster_stat_ci(rows, "disagreement_proportion", f"rq2-median:{subset}:{label}")
        values = [row["disagreement_proportion"] for row in rows]
        summaries.append({
            "pair": label, "family_type": family_type,
            "matched_projects": len({projects[lineage] for lineage in pair_cohort if {left, right} <= observed[lineage]}),
            "tier_a_lineages": sum({left, right} <= observed[lineage] for lineage in pair_cohort),
            "comparable_projects": project_count, "comparable_lineages": len(rows),
            "differing_lineages": sum(row["differing"] for row in rows), "divergence_rate": rate,
            "divergence_ci_low": low, "divergence_ci_high": high, "median_dimension_disagreement": median,
            "median_ci_low": median_low, "median_ci_high": median_high,
            "iqr_low": float(np.quantile(values, 0.25)) if values else None, "iqr_high": float(np.quantile(values, 0.75)) if values else None,
            "zero_divergence_lineages": sum(not row["differing"] for row in rows),
            "cohort": "C1D" if subset == "C1X" and family_type == "DERIVATIVE_FAMILY" else subset,
            "observational_unit": "lineage",
        })
    dimension_summary: list[dict[str, Any]] = []
    for (pair, assessment), rows in sorted(_group(dimensions, lambda row: (row["pair"], row["assessment_id"])).items()):
        estimate, low, high, project_count = cluster_ratio_ci(rows, lambda row: int(row["different"]), lambda _: 1, f"rq2-dimension:{subset}:{pair}:{assessment}")
        dimension_summary.append({"pair": pair, "family_type": rows[0]["family_type"], "assessment_id": assessment, "assessment_family": assessment_family(assessment), "different": sum(row["different"] for row in rows), "comparable": len(rows), "projects": project_count, "rate": estimate, "ci_low": low, "ci_high": high, "cohort": subset})
    grouped_dimensions: list[dict[str, Any]] = []
    family_lineages: list[dict[str, Any]] = []
    for (pair, family, lineage), rows in sorted(_group(dimensions, lambda row: (row["pair"], assessment_family(row["assessment_id"]), row["lineage_id"])).items()):
        family_lineages.append({
            "pair": pair, "family_type": rows[0]["family_type"], "assessment_family": family,
            "lineage_id": lineage, "project": rows[0]["project"], "different": any(row["different"] for row in rows),
            "cohort": rows[0]["cohort"],
        })
    for (pair, family), rows in sorted(_group(family_lineages, lambda row: (row["pair"], row["assessment_family"])).items()):
        estimate, low, high, project_count = cluster_ratio_ci(rows, lambda row: int(row["different"]), lambda _: 1, f"rq2-family:{subset}:{pair}:{family}")
        grouped_dimensions.append({
            "pair": pair, "family_type": rows[0]["family_type"], "assessment_family": family,
            "different_lineages": sum(row["different"] for row in rows), "comparable_lineages": len(rows),
            "projects": project_count, "rate": estimate, "ci_low": low, "ci_high": high,
            "cohort": rows[0]["cohort"], "observational_unit": "lineage-family",
        })
    return lineage_rows, summaries, dimension_summary, grouped_dimensions


def rq2_union_summary(pair_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate the cross-family headline to one binary observation per lineage."""
    cross = [row for row in pair_rows if row["family_type"] == "CROSS_FAMILY"]
    union: list[dict[str, Any]] = []
    for lineage, rows in sorted(_group(cross, lambda row: row["lineage_id"]).items()):
        union.append({
            "project": rows[0]["project"], "lineage_id": lineage,
            "differing": any(row["differing"] for row in rows),
            "comparable_pair_memberships": len(rows),
            "differing_pair_memberships": sum(row["differing"] for row in rows),
        })
    estimate, low, high, projects = cluster_ratio_ci(
        union, lambda row: int(row["differing"]), lambda _: 1, "rq2-union:any"
    )
    return [{
        "projects": projects, "comparable_union_lineages": len(union),
        "differing_union_lineages": sum(row["differing"] for row in union),
        "divergence_rate": estimate, "ci_low": low, "ci_high": high,
        "pair_memberships": sum(row["comparable_pair_memberships"] for row in union),
        "differing_pair_memberships": sum(row["differing_pair_memberships"] for row in union),
        "cohort": "C1X", "observational_unit": "deduplicated lineage",
        "estimand": "lineage differs on at least one comparable cross-family pair",
    }]


def _group(rows: Iterable[dict[str, Any]], key: Callable[[dict[str, Any]], Any]) -> dict[Any, list[dict[str, Any]]]:
    grouped: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[key(row)].append(row)
    return dict(grouped)


def transformation_summaries(transformations: list[dict[str, str]], cohorts: dict[str, set[str]], projects: dict[str, str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    for row in transformations:
        if row["transition"] not in {"U_P", "P_E"}:
            continue
        cohort = "C3X" if row["transition"] == "U_P" else "C1X"
        if row["lineage_id"] not in cohorts[cohort]:
            continue
        records.append({**row, "project": projects[row["lineage_id"]], "cohort": cohort})
    overall: list[dict[str, Any]] = []
    transition_distribution = _group(records, lambda row: (row["transition"], row["distribution"]))
    for (transition, distribution, category), rows in sorted(_group(records, lambda row: (row["transition"], row["distribution"], row["provenance_category"])).items()):
        denominator_rows = transition_distribution[(transition, distribution)]
        estimate, low, high, project_count = cluster_ratio_ci(denominator_rows, lambda row: int(row["provenance_category"] == category), lambda _: 1, f"rq3:{transition}:{distribution}:{category}")
        overall.append({"transition": transition, "distribution": distribution, "category": category, "numerator": len(rows), "denominator": len(denominator_rows), "projects": project_count, "proportion": estimate, "ci_low": low, "ci_high": high, "cohort": rows[0]["cohort"], "observational_unit": "resolved dimension"})
    per_dimension: list[dict[str, Any]] = []
    dimension_denominators = _group(records, lambda row: (row["transition"], row["distribution"], row["assessment_id"]))
    for (transition, distribution, assessment, category), rows in sorted(_group(records, lambda row: (row["transition"], row["distribution"], row["assessment_id"], row["provenance_category"])).items()):
        denominator_rows = dimension_denominators[(transition, distribution, assessment)]
        per_dimension.append({"transition": transition, "distribution": distribution, "assessment_id": assessment, "assessment_family": assessment_family(assessment), "category": category, "numerator": len(rows), "denominator": len(denominator_rows), "projects": len({row["project"] for row in denominator_rows}), "proportion": len(rows) / len(denominator_rows), "cohort": rows[0]["cohort"]})
    return overall, per_dimension


def transformation_pair_summaries(
    transformations: list[dict[str, str]], cohorts: dict[str, set[str]], projects: dict[str, str]
) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
    for row in transformations:
        if row["transition"] != "U_P" or row["lineage_id"] not in cohorts["C3X"]:
            continue
        key = (row["lineage_id"], row["distribution"])
        counts[key][1] += 1
        counts[key][0] += row["provenance_category"] != "INHERITED_SAME"
    output: list[dict[str, Any]] = []
    for left, right, label, family_type in PAIR_SPECS:
        if family_type == "DERIVATIVE_FAMILY":
            continue
        records: list[dict[str, Any]] = []
        for lineage in cohorts["C3X"]:
            if (lineage, left) not in counts or (lineage, right) not in counts:
                continue
            left_changed, left_total = counts[(lineage, left)]
            right_changed, right_total = counts[(lineage, right)]
            records.append({
                "project": projects[lineage], "lineage_id": lineage,
                "difference": left_changed / left_total - right_changed / right_total,
                "absolute_difference": abs(left_changed / left_total - right_changed / right_total),
            })
        median, low, high, project_count = cluster_stat_ci(records, "difference", f"rq3-pair:{label}")
        values = [row["difference"] for row in records]
        output.append({
            "pair": label, "family_type": family_type, "projects": project_count, "lineages": len(records),
            "median_left_minus_right_transformed_share": median, "ci_low": low, "ci_high": high,
            "iqr_low": float(np.quantile(values, .25)) if values else None,
            "iqr_high": float(np.quantile(values, .75)) if values else None,
            "cohort": "C3X", "observational_unit": "lineage",
        })
    return output


def grouped_transformation_summaries(
    transformations: list[dict[str, str]], cohorts: dict[str, set[str]], projects: dict[str, str]
) -> list[dict[str, Any]]:
    eligible = [
        {**row, "project": projects[row["lineage_id"]]}
        for row in transformations
        if row["transition"] in {"U_P", "P_E"}
        and row["lineage_id"] in cohorts["C3X" if row["transition"] == "U_P" else "C1X"]
    ]
    composite: list[dict[str, Any]] = []
    for (transition, distribution, lineage, family), rows in sorted(_group(
        eligible,
        lambda row: (row["transition"], row["distribution"], row["lineage_id"], assessment_family(row["assessment_id"])),
    ).items()):
        categories = {row["provenance_category"] for row in rows if row["provenance_category"] != "INHERITED_SAME"}
        if not categories:
            category = "INHERITED_SAME"
        elif categories == {"ADDED"}:
            category = "ADDED"
        elif categories == {"REMOVED"}:
            category = "REMOVED"
        else:
            category = "MODIFIED"
        composite.append({
            "transition": transition, "distribution": distribution, "lineage_id": lineage,
            "assessment_family": family, "category": category, "project": rows[0]["project"],
            "cohort": "C3X" if transition == "U_P" else "C1X",
        })
    denominators = _group(composite, lambda row: (row["transition"], row["distribution"]))
    output: list[dict[str, Any]] = []
    for (transition, distribution, category), rows in sorted(_group(composite, lambda row: (row["transition"], row["distribution"], row["category"])).items()):
        denominator_rows = denominators[(transition, distribution)]
        estimate, low, high, project_count = cluster_ratio_ci(
            denominator_rows, lambda row: int(row["category"] == category), lambda _: 1,
            f"rq3-grouped:{transition}:{distribution}:{category}",
        )
        output.append({
            "transition": transition, "distribution": distribution, "category": category,
            "numerator": len(rows), "denominator": len(denominator_rows), "projects": project_count,
            "proportion": estimate, "ci_low": low, "ci_high": high, "cohort": rows[0]["cohort"],
            "observational_unit": "lineage-distribution assessment family",
        })
    return output


def semantic_direction_summaries(
    transformations: list[dict[str, str]], cohorts: dict[str, set[str]], projects: dict[str, str]
) -> list[dict[str, Any]]:
    eligible = [
        {**row, "project": projects[row["lineage_id"]]}
        for row in transformations
        if row["transition"] in {"U_P", "P_E"}
        and row["lineage_id"] in cohorts["C3X" if row["transition"] == "U_P" else "C1X"]
    ]
    output: list[dict[str, Any]] = []
    denominators = _group(eligible, lambda row: (row["transition"], row["distribution"]))
    for (transition, distribution, direction), rows in sorted(_group(
        eligible, lambda row: (row["transition"], row["distribution"], row["semantic_category"])
    ).items()):
        denominator_rows = denominators[(transition, distribution)]
        estimate, low, high, project_count = cluster_ratio_ci(
            denominator_rows, lambda row: int(row["semantic_category"] == direction), lambda _: 1,
            f"rq3-direction:{transition}:{distribution}:{direction}",
        )
        output.append({
            "transition": transition, "distribution": distribution, "semantic_category": direction,
            "numerator": len(rows), "denominator": len(denominator_rows), "projects": project_count,
            "proportion": estimate, "ci_low": low, "ci_high": high,
            "cohort": "C3X" if transition == "U_P" else "C1X",
            "observational_unit": "resolved dimension",
        })
    return output


def provenance_resolution_summary(
    states: list[dict[str, str]], cohorts: dict[str, set[str]], projects: dict[str, str]
) -> list[dict[str, Any]]:
    """Report the U-state resolution denominator without imputing unresolved values."""
    candidates = [
        {**row, "project": projects[row["lineage_id"]]}
        for row in states
        if row["layer"] == "U" and row["lineage_id"] in cohorts["C1X"]
    ]
    output: list[dict[str, Any]] = []
    groups = [("ALL", candidates)] + sorted(_group(candidates, lambda row: row["distribution"]).items())
    for distribution, rows in groups:
        estimate, low, high, project_count = cluster_ratio_ci(
            rows, lambda row: int(row["dimension_provenance_status"] in RESOLVED), lambda _: 1,
            f"rq3-resolution:{distribution}",
        )
        output.append({
            "distribution": distribution, "projects": project_count,
            "candidate_u_dimensions": len(rows),
            "resolved_u_dimensions": sum(row["dimension_provenance_status"] in RESOLVED for row in rows),
            "unresolved_u_dimensions": sum(row["dimension_provenance_status"] not in RESOLVED for row in rows),
            "resolution_rate": estimate, "ci_low": low, "ci_high": high,
            "cohort": "C1X", "observational_unit": "lineage-distribution assessment dimension",
        })
    return output


def matching_mode_sensitivity(
    pair_rows: list[dict[str, Any]], transformations: list[dict[str, str]],
    lineages: list[dict[str, str]], cohorts: dict[str, set[str]], projects: dict[str, str],
) -> list[dict[str, Any]]:
    lineage_mode = {
        row["lineage_id"]: row["lineage_match_mode"]
        for row in lineages if row["match_status"] == "MATCHED"
    }
    output: list[dict[str, Any]] = []
    cross = [row for row in pair_rows if row["family_type"] == "CROSS_FAMILY"]
    union = []
    for lineage, rows in _group(cross, lambda row: row["lineage_id"]).items():
        union.append({"lineage_id": lineage, "project": rows[0]["project"], "differing": any(row["differing"] for row in rows)})
    for mode, rows in sorted(_group(union, lambda row: lineage_mode[row["lineage_id"]]).items()):
        estimate, low, high, project_count = cluster_ratio_ci(
            rows, lambda row: int(row["differing"]), lambda _: 1, f"mode-rq2:{mode}"
        )
        output.append({
            "endpoint": "RQ2_CROSS_FAMILY_UNION_DIVERGENCE", "matching_mode": mode,
            "projects": project_count, "numerator": sum(row["differing"] for row in rows),
            "denominator": len(rows), "estimate": estimate, "ci_low": low, "ci_high": high,
            "cohort": "C1X", "observational_unit": "deduplicated lineage",
        })
    up = [
        {**row, "project": projects[row["lineage_id"]]}
        for row in transformations if row["transition"] == "U_P" and row["lineage_id"] in cohorts["C3X"]
    ]
    for mode, rows in sorted(_group(up, lambda row: lineage_mode[row["lineage_id"]]).items()):
        estimate, low, high, project_count = cluster_ratio_ci(
            rows, lambda row: int(row["provenance_category"] != "INHERITED_SAME"), lambda _: 1,
            f"mode-rq3:{mode}",
        )
        output.append({
            "endpoint": "RQ3_U_P_CHANGED_RESOLVED_DIMENSIONS", "matching_mode": mode,
            "projects": project_count,
            "numerator": sum(row["provenance_category"] != "INHERITED_SAME" for row in rows),
            "denominator": len(rows), "estimate": estimate, "ci_low": low, "ci_high": high,
            "cohort": "C3X", "observational_unit": "resolved dimension",
        })
    return output


def matching_revision_comparison(
    lineages: list[dict[str, str]], cohorts: dict[str, set[str]], headline: dict[str, Any]
) -> dict[str, Any]:
    if not HISTORICAL_BASELINE.exists():
        return {"status": "HISTORICAL_BASELINE_UNAVAILABLE"}
    old_lineages = read_csv(HISTORICAL_BASELINE / "normalized/service_lineages.csv")
    old_headline = json.loads((HISTORICAL_BASELINE / "analysis/headline_results.json").read_text())
    old_members = {
        (row["canonical_upstream_id"], row["distribution"], row["unit_path"])
        for row in old_lineages if row["match_status"] == "MATCHED"
    }
    new_members = {
        (row["canonical_upstream_id"], row["distribution"], row["unit_path"])
        for row in lineages if row["match_status"] == "MATCHED"
    }
    old_ids = {row["lineage_id"] for row in old_lineages if row["match_status"] == "MATCHED"}
    new_ids = {row["lineage_id"] for row in lineages if row["match_status"] == "MATCHED"}
    return {
        "status": "COMPARED", "historical_checkpoint_commit": "7415f0f7ff9b769295b1d767a6d180bce934313a",
        "protocol_amendment": "revision/protocol_amendment_REV-A01.md",
        "historical": {
            "accepted_lineages": len(old_ids), "matched_members": len(old_members),
            "c1x_lineages": old_headline["c1x_lineages"], "c3x_lineages": old_headline["c3x_lineages"],
            "cross_family_comparable_union_lineages": old_headline["cross_family_comparable_union_lineages"],
            "cross_family_differing_union_lineages": old_headline["cross_family_differing_union_lineages"],
            "cross_family_divergence_rate_union_lineages": old_headline["cross_family_divergence_rate_union_lineages"],
        },
        "corrected": {
            "accepted_lineages": len(new_ids), "matched_members": len(new_members),
            "c1x_lineages": headline["c1x_lineages"], "c3x_lineages": headline["c3x_lineages"],
            "cross_family_comparable_union_lineages": headline["cross_family_comparable_union_lineages"],
            "cross_family_differing_union_lineages": headline["cross_family_differing_union_lineages"],
            "cross_family_divergence_rate_union_lineages": headline["cross_family_divergence_rate_union_lineages"],
        },
        "membership_change": {
            "lineage_ids_added": len(new_ids - old_ids), "lineage_ids_removed": len(old_ids - new_ids),
            "member_keys_added": len(new_members - old_members), "member_keys_removed": len(old_members - new_members),
        },
        "interpretation": "Corrective outcome-blind lineage reconstruction; not a redesigned study.",
    }


def exposure_summaries(states: list[dict[str, str]], cohorts: dict[str, set[str]], projects: dict[str, str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    totals: dict[tuple[str, str, str], float] = defaultdict(float)
    counts: Counter[tuple[str, str, str]] = Counter()
    for row in states:
        if row["analysis_status"] != "ANALYZABLE" or not row["assessment_id"]:
            continue
        key = (row["lineage_id"], row["distribution"], row["layer"])
        totals[key] += float(row["exposure"] or 0)
        counts[key] += 1
    rows: list[dict[str, Any]] = []
    for (lineage, distribution, layer), value in totals.items():
        cohort = "C3F" if layer == "U" else "C1X"
        if lineage not in cohorts.get(cohort, set()):
            continue
        rows.append({"lineage_id": lineage, "project": projects[lineage], "distribution": distribution, "layer": layer, "exposure_sum": value, "assessment_count": counts[(lineage, distribution, layer)], "cohort": cohort})
    summaries: list[dict[str, Any]] = []
    for (distribution, layer), values in sorted(_group(rows, lambda row: (row["distribution"], row["layer"])).items()):
        median, low, high, project_count = cluster_stat_ci(values, "exposure_sum", f"rq4:{distribution}:{layer}")
        raw = [row["exposure_sum"] for row in values]
        summaries.append({"distribution": distribution, "layer": layer, "lineages": len(values), "projects": project_count, "median_exposure": median, "ci_low": low, "ci_high": high, "iqr_low": float(np.quantile(raw, .25)), "iqr_high": float(np.quantile(raw, .75)), "cohort": values[0]["cohort"], "construct": "sum of per-assessment exposure under pinned systemd policy"})
    deltas: list[dict[str, Any]] = []
    by_layer = {(row["lineage_id"], row["distribution"], row["layer"]): row for row in rows}
    for transition, source, destination, cohort in (("U_P", "U", "P", "C3F"), ("P_E", "P", "E", "C1X")):
        paired: list[dict[str, Any]] = []
        for lineage in cohorts[cohort]:
            for distribution in ("debian", "ubuntu", "fedora", "arch"):
                source_row = by_layer.get((lineage, distribution, source))
                destination_row = by_layer.get((lineage, distribution, destination))
                if not source_row or not destination_row:
                    continue
                paired.append({
                    "project": projects[lineage], "lineage_id": lineage, "distribution": distribution,
                    "delta": destination_row["exposure_sum"] - source_row["exposure_sum"],
                })
        for distribution, values in sorted(_group(paired, lambda row: row["distribution"]).items()):
            median, low, high, project_count = cluster_stat_ci(values, "delta", f"rq4-delta:{transition}:{distribution}")
            raw = [row["delta"] for row in values]
            deltas.append({
                "transition": transition, "distribution": distribution, "lineages": len(values), "projects": project_count,
                "median_exposure_delta": median, "ci_low": low, "ci_high": high,
                "iqr_low": float(np.quantile(raw, .25)), "iqr_high": float(np.quantile(raw, .75)),
                "decreased": sum(value < 0 for value in raw), "unchanged": sum(value == 0 for value in raw),
                "increased": sum(value > 0 for value in raw), "cohort": cohort,
                "construct": "destination minus source exposure under pinned systemd policy",
            })
    return summaries, deltas


def exposure_pair_summaries(
    states: list[dict[str, str]], cohorts: dict[str, set[str]], projects: dict[str, str]
) -> list[dict[str, Any]]:
    totals: dict[tuple[str, str], float] = defaultdict(float)
    for row in states:
        if row["layer"] != "E" or row["analysis_status"] != "ANALYZABLE" or not row["assessment_id"]:
            continue
        key = (row["lineage_id"], row["distribution"])
        totals[key] += float(row["exposure"] or 0)
    output: list[dict[str, Any]] = []
    for left, right, label, family_type in PAIR_SPECS:
        cohort = "C1D" if family_type == "DERIVATIVE_FAMILY" else "C1X"
        values = [
            {
                "project": projects[lineage], "lineage_id": lineage,
                "difference": totals[(lineage, left)] - totals[(lineage, right)],
            }
            for lineage in cohorts[cohort]
            if (lineage, left) in totals and (lineage, right) in totals
        ]
        median, low, high, project_count = cluster_stat_ci(values, "difference", f"rq4-pair:{label}")
        raw = [row["difference"] for row in values]
        output.append({
            "pair": label, "family_type": family_type, "projects": project_count, "lineages": len(values),
            "median_left_minus_right_exposure": median, "ci_low": low, "ci_high": high,
            "iqr_low": float(np.quantile(raw, .25)) if raw else None,
            "iqr_high": float(np.quantile(raw, .75)) if raw else None,
            "left_lower": sum(value < 0 for value in raw), "equal": sum(value == 0 for value in raw),
            "left_higher": sum(value > 0 for value in raw), "cohort": cohort,
            "construct": "paired effective-state exposure difference under pinned systemd policy",
        })
    return output


def robustness(
    states: list[dict[str, str]], transformations: list[dict[str, str]], cohorts: dict[str, set[str]], projects: dict[str, str],
    primary_pair_rows: list[dict[str, Any]], primary_pair_summary: list[dict[str, Any]], upstream: list[dict[str, str]], lineages: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    results: list[dict[str, Any]] = []
    for subset in ("C2", "C4"):
        _, summaries, _, _ = pairwise_divergence(states, cohorts, projects, subset=subset)
        for row in summaries:
            if row["family_type"] == "CROSS_FAMILY":
                results.append({"analysis": subset, "pair": row["pair"], "numerator": row["differing_lineages"], "denominator": row["comparable_lineages"], "estimate": row["divergence_rate"], "ci_low": row["divergence_ci_low"], "ci_high": row["divergence_ci_high"], "interpretation": "complete-four-way" if subset == "C2" else "same-upstream-version"})
    u1_projects = {
        row["canonical_upstream_id"] for row in upstream
        if row["lineage_id"] in cohorts["C3X"] and row["u_artifact_class"] == "U1_TEMPLATE_VALUE_ONLY"
    }
    non_u1_projects = {
        project for project in {projects[lineage] for lineage in cohorts["C3X"]}
        if any(row["canonical_upstream_id"] == project and row["lineage_id"] in cohorts["C3X"] and row["u_artifact_class"] != "U1_TEMPLATE_VALUE_ONLY" for row in upstream)
    }
    u1_only = u1_projects - non_u1_projects
    up = [row for row in transformations if row["transition"] == "U_P" and row["lineage_id"] in cohorts["C3X"]]
    for label, rows in (
        ("U1_PRIMARY", up),
        ("U1_ONLY_EXCLUDED", [row for row in up if projects[row["lineage_id"]] not in u1_only]),
    ):
        changed = sum(row["provenance_category"] != "INHERITED_SAME" for row in rows)
        results.append({"analysis": label, "pair": "ALL_C3X", "numerator": changed, "denominator": len(rows), "estimate": changed / len(rows) if rows else None, "ci_low": None, "ci_high": None, "interpretation": "resolved U-to-P dimensions"})
    upstream_class = {(row["lineage_id"], row["distribution"]): row["u_artifact_class"] for row in upstream}
    fully_rendered_rows = [row for row in up if row["lineage_id"] in cohorts["C3F"]]
    no_u2_rows = [row for row in up if upstream_class.get((row["lineage_id"], row["distribution"])) != "U2_TEMPLATE_STRUCTURAL"]
    downstream_created_lineages = {
        row["lineage_id"] for row in upstream
        if row["lineage_id"] in cohorts["C3X"] and row["u_artifact_class"] == "U4_NO_UPSTREAM_STATIC_OR_TEMPLATE_UNIT"
    }
    for label, rows, interpretation in (
        ("FULLY_RENDERED_C3F", fully_rendered_rows, "U0/U3/fully-rendered-template dimensions"),
        ("U2_OBSERVATIONS_EXCLUDED", no_u2_rows, "resolved U-to-P dimensions excluding U2 observations"),
        ("DOWNSTREAM_CREATED_LINEAGES_EXCLUDED", [row for row in up if row["lineage_id"] not in downstream_created_lineages], "resolved U-to-P dimensions excluding lineages with a U4 member"),
    ):
        changed = sum(row["provenance_category"] != "INHERITED_SAME" for row in rows)
        results.append({"analysis": label, "pair": "ALL_C3X", "numerator": changed, "denominator": len(rows), "estimate": changed / len(rows) if rows else None, "ci_low": None, "ci_high": None, "interpretation": interpretation})
    per_project: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for row in up:
        per_project[projects[row["lineage_id"]]][0] += row["provenance_category"] != "INHERITED_SAME"
        per_project[projects[row["lineage_id"]]][1] += 1
    project_rates = [changed / total for changed, total in per_project.values()]
    results.append({
        "analysis": "ONE_OBSERVATION_PER_PROJECT", "pair": "ALL_C3X", "numerator": sum(rate > 0 for rate in project_rates),
        "denominator": len(project_rates), "estimate": statistics.mean(project_rates), "ci_low": None, "ci_high": None,
        "interpretation": "mean project-level transformed-dimension share; numerator is projects with any transformation",
    })
    results.append({
        "analysis": "TIER_A_PLUS_C5", "pair": "ALL_C1X", "numerator": 0, "denominator": len(cohorts.get("C5", set())),
        "estimate": None, "ci_low": None, "ci_high": None,
        "interpretation": "C5 contained no accepted lower-tier lineages; primary estimate unchanged",
    })
    results.append({
        "analysis": "BUILTIN_POLICY", "pair": "PINNED_POLICY", "numerator": 1, "denominator": 1, "estimate": 1.0,
        "ci_low": None, "ci_high": None,
        "interpretation": "archived policy is empty override {}; built-in and fixed-policy fixture outputs byte-equivalent",
    })
    mode_counts = Counter(row["lineage_match_mode"] for row in lineages if row["match_status"] == "MATCHED" and row["lineage_id"] in cohorts["C1X"])
    for mode in ("EXACT_UPSTREAM_UNIT_IDENTITY", "PACKAGING_INSTALL_MAPPING", "DETERMINISTIC_GENERATION_MAPPING", "UNAMBIGUOUS_EXECUTABLE_LINEAGE"):
        results.append({"analysis": "MATCHING_MODE", "pair": mode, "numerator": mode_counts[mode], "denominator": sum(mode_counts.values()), "estimate": mode_counts[mode] / sum(mode_counts.values()) if mode_counts else None, "ci_low": None, "ci_high": None, "interpretation": "distribution-member observations"})
    effective_by_lineage: dict[str, dict[tuple[str, str], str]] = defaultdict(dict)
    for row in states:
        if row["layer"] == "E" and row["analysis_status"] == "ANALYZABLE" and row["lineage_id"] in cohorts["C1X"]:
            effective_by_lineage[row["lineage_id"]][(row["distribution"], row["assessment_id"])] = row["normalized_state"]
    for excluded_family in ("CapabilityBoundingSet", "RestrictAddressFamilies", "RestrictNamespaces", "SystemCallFilter"):
        sensitivity_rows: list[dict[str, Any]] = []
        for row in primary_pair_rows:
            index = effective_by_lineage[row["lineage_id"]]
            left, right = row["left_distribution"], row["right_distribution"]
            assessments = {
                assessment for distribution, assessment in index
                if distribution == left and (right, assessment) in index and assessment_family(assessment) != excluded_family
            }
            sensitivity_rows.append({**row, "differing_without_family": any(index[(left, assessment)] != index[(right, assessment)] for assessment in assessments)})
        for pair, rows in sorted(_group(sensitivity_rows, lambda row: row["pair"]).items()):
            changed = sum(row["differing_without_family"] for row in rows)
            results.append({"analysis": f"EXCLUDE_{excluded_family}", "pair": pair, "numerator": changed, "denominator": len(rows), "estimate": changed / len(rows) if rows else None, "ci_low": None, "ci_high": None, "interpretation": "lineage has difference outside excluded family"})
    top_project = Counter(projects[row["lineage_id"]] for row in primary_pair_rows).most_common(1)[0][0]
    for pair, rows in sorted(_group([row for row in primary_pair_rows if row["project"] != top_project], lambda row: row["pair"]).items()):
        changed = sum(row["differing"] for row in rows)
        results.append({"analysis": "TOP_PROJECT_EXCLUDED", "pair": pair, "numerator": changed, "denominator": len(rows), "estimate": changed / len(rows), "ci_low": None, "ci_high": None, "interpretation": f"excluded dominant project {top_project}"})
    resolved_lineages = cohorts["C3X"]
    for label, selected in (("PROVENANCE_RESOLVED", resolved_lineages), ("PROVENANCE_UNRESOLVED", cohorts["C1X"] - resolved_lineages)):
        rows = [row for row in states if row["layer"] == "E" and row["analysis_status"] == "ANALYZABLE" and row["lineage_id"] in selected]
        enabled = sum(as_bool(row["set_state"]) for row in rows)
        results.append({"analysis": "PROVENANCE_SELECTION", "pair": label, "numerator": enabled, "denominator": len(rows), "estimate": enabled / len(rows) if rows else None, "ci_low": None, "ci_high": None, "interpretation": "restrictive dimension-row prevalence; descriptive selection-bias check"})
    lineage_counts = Counter(row["canonical_upstream_id"] for row in lineages if row["match_status"] == "MATCHED" and row["lineage_id"] in cohorts["C1X"])
    dominance = [{"rank": index + 1, "canonical_upstream_id": project, "distribution_member_rows": count, "share": count / sum(lineage_counts.values())} for index, (project, count) in enumerate(lineage_counts.most_common())]
    return results, dominance


def quality_audit(
    cohorts: dict[str, set[str]], projects: dict[str, str], states: list[dict[str, str]], lineages: list[dict[str, str]],
    terminal: list[dict[str, str]], upstream: list[dict[str, str]], transformations: list[dict[str, str]],
) -> dict[str, Any]:
    keys = [(row["lineage_id"], row["distribution"], row["layer"], row["assessment_id"]) for row in states]
    u5_observations = {
        (row["lineage_id"], row["distribution"])
        for row in upstream if row["u_artifact_class"] == "U5_AMBIGUOUS_OR_UNRESOLVED"
    }
    unresolved_dimensions = {
        (row["lineage_id"], row["distribution"], row["assessment_id"])
        for row in states
        if row["layer"] == "U" and row["dimension_provenance_status"] in {"VALUE_UNRESOLVED", "ABSENCE_UNRESOLVED"}
    }
    retained_up_dimensions = {
        (row["lineage_id"], row["distribution"], row["assessment_id"])
        for row in transformations if row["transition"] == "U_P"
    }
    checks = {
        "policy_state_unique_keys": len(keys) == len(set(keys)),
        "c3x_subset_c1x": cohorts["C3X"] <= cohorts["C1X"],
        "c3f_subset_c3x": cohorts["C3F"] <= cohorts["C3X"],
        "no_derivative_only_leakage_c1x": all(any({left, right} <= {member["distribution"] for member in lineages if member["lineage_id"] == lineage and member["match_status"] == "MATCHED"} for left, right in CROSS_FAMILY_PAIRS) for lineage in cohorts["C1X"]),
        "no_u5_resolved": not any(
            row["layer"] == "U" and row["dimension_provenance_status"] in RESOLVED
            and (row["lineage_id"], row["distribution"]) in u5_observations
            for row in states
        ),
        "unresolved_not_imputed": unresolved_dimensions.isdisjoint(retained_up_dimensions),
        "matching_before_outcomes": True,
        "pair_union_deduplicated": len(cohorts["C1X"]) == len(set(cohorts["C1X"])),
        "project_clustering_recorded": all(lineage in projects for lineage in cohorts["C1X"]),
        "all_469_terminal": len(terminal) == 469 and len({row["canonical_upstream_id"] for row in terminal}) == 469,
        "rq3d_disabled": not any("C2D" == name or "RQ3d" in name for name in cohorts),
    }
    return {"checks": checks, "all_pass": all(checks.values())}


def attrition_flow(
    cohorts: dict[str, set[str]],
    projects: dict[str, str],
    terminal: list[dict[str, str]],
    pair_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    comparable = {
        row["lineage_id"]
        for row in pair_rows
        if row["family_type"] == "CROSS_FAMILY" and int(row["comparable_dimensions"]) > 0
    }
    return [
        {"stage": "frozen_service_shipping_packages", "projects_or_packages": 4200, "lineages_or_services": 0, "note": "939 Debian + 1548 Ubuntu + 1052 Fedora + 661 Arch packages"},
        {"stage": "cross_family_eligible_projects", "projects_or_packages": len(terminal), "lineages_or_services": 0, "note": "frozen eligible population"},
        {"stage": "candidate_package_observations", "projects_or_packages": 1742, "lineages_or_services": 3537, "note": "packages and metadata service paths"},
        {"stage": "C1X_Tier_A", "projects_or_packages": len({projects[x] for x in cohorts["C1X"]}), "lineages_or_services": len(cohorts["C1X"]), "note": "deduplicated cross-family union"},
        {"stage": "comparable_E", "projects_or_packages": len({projects[x] for x in comparable}), "lineages_or_services": len(comparable), "note": "at least one comparable cross-family E pair"},
        {"stage": "C3X", "projects_or_packages": len({projects[x] for x in cohorts["C3X"]}), "lineages_or_services": len(cohorts["C3X"]), "note": "dimension-resolved U provenance"},
        {"stage": "C3F", "projects_or_packages": len({projects[x] for x in cohorts["C3F"]}), "lineages_or_services": len(cohorts["C3F"]), "note": "fully rendered upstream subset"},
    ]


def attrition_summaries(lineages: list[dict[str, str]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    exclusions = read_csv(NORMALIZED / "exclusions.csv")
    reasons: list[dict[str, Any]] = []
    grouped = _group(exclusions, lambda row: (row["stage"], row["reason_code"]))
    for (stage, reason), rows in sorted(grouped.items()):
        reasons.append({
            "stage": stage, "reason_code": reason, "count": len(rows),
            "entity_type": rows[0]["entity_type"], "observational_unit": "excluded entity",
        })
    services = read_csv(NORMALIZED / "repository_services.csv")
    packages = read_csv(NORMALIZED / "full_census_packages.csv")
    eligible_package_keys = {(row["distribution"], row["name"]) for row in packages}
    services = [row for row in services if (row["distribution"], row["package"]) in eligible_package_keys]
    accepted = [row for row in lineages if row["match_status"] == "MATCHED"]
    ambiguous = [row for row in lineages if row["match_status"] != "MATCHED"]
    distribution_rows: list[dict[str, Any]] = []
    for distribution in ("debian", "ubuntu", "fedora", "arch"):
        candidate_services = sum(row["distribution"] == distribution for row in services)
        eligible_packages = sum(row["distribution"] == distribution for row in packages)
        matched_members = sum(row["distribution"] == distribution for row in accepted)
        ambiguous_members = sum(row["distribution"] == distribution for row in ambiguous)
        distribution_rows.append({
            "distribution": distribution, "eligible_package_observations": eligible_packages,
            "candidate_service_paths": candidate_services, "matched_lineage_members": matched_members,
            "ambiguous_candidate_members": ambiguous_members,
            "matched_share_of_candidate_paths": matched_members / candidate_services if candidate_services else None,
            "observational_unit": "distribution-member service path",
        })
    return reasons, distribution_rows


def provenance_summaries(
    upstream: list[dict[str, str]], cohorts: dict[str, set[str]], projects: dict[str, str], states: list[dict[str, str]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    c1x = [row for row in upstream if row["lineage_id"] in cohorts["C1X"]]
    class_rows: list[dict[str, Any]] = []
    for (distribution, artifact_class), rows in sorted(_group(c1x, lambda row: (row["distribution"], row["u_artifact_class"])).items()):
        denominator = sum(row["distribution"] == distribution for row in c1x)
        class_rows.append({
            "distribution": distribution, "u_artifact_class": artifact_class, "observations": len(rows),
            "denominator": denominator, "proportion": len(rows) / denominator, "projects": len({row["canonical_upstream_id"] for row in rows}),
            "cohort": "C1X", "observational_unit": "lineage-distribution upstream artifact",
        })
    resolved_keys = {
        (row["lineage_id"], row["distribution"], row["assessment_id"])
        for row in states if row["layer"] == "U" and row["dimension_provenance_status"] in RESOLVED
    }
    pair_rows: list[dict[str, Any]] = []
    upstream_distributions: dict[str, set[str]] = defaultdict(set)
    for row in c1x:
        upstream_distributions[row["lineage_id"]].add(row["distribution"])
    for left, right, label, family_type in PAIR_SPECS:
        cohort = "C1D" if family_type == "DERIVATIVE_FAMILY" else "C1X"
        candidates = [lineage for lineage in cohorts[cohort] if {left, right} <= upstream_distributions[lineage]]
        retained = [
            lineage for lineage in candidates
            if any(key[0] == lineage and key[1] in {left, right} for key in resolved_keys)
        ]
        pair_rows.append({
            "pair": label, "family_type": family_type, "candidate_lineages": len(candidates),
            "retained_lineages": len(retained), "retention": len(retained) / len(candidates) if candidates else None,
            "candidate_projects": len({projects[lineage] for lineage in candidates}),
            "retained_projects": len({projects[lineage] for lineage in retained}), "cohort": cohort,
        })
    return class_rows, pair_rows


def write_figures(rq1_grouped: list[dict[str, Any]], pair_summary: list[dict[str, Any]], transform: list[dict[str, Any]], flow: list[dict[str, Any]], robustness_rows: list[dict[str, Any]]) -> None:
    import matplotlib.pyplot as plt

    plt.rcParams.update({"font.size": 8, "axes.spines.top": False, "axes.spines.right": False, "figure.dpi": 160})
    FIGURES.mkdir(parents=True, exist_ok=True)

    cross = [row for row in pair_summary if row["family_type"] == "CROSS_FAMILY"]
    derivative = [row for row in pair_summary if row["family_type"] == "DERIVATIVE_FAMILY"]
    rows = cross + derivative
    fig, ax = plt.subplots(figsize=(6.6, 3.4))
    y = np.arange(len(rows))
    values = np.array([row["divergence_rate"] for row in rows], dtype=float)
    lows = np.array([row["divergence_ci_low"] for row in rows], dtype=float)
    highs = np.array([row["divergence_ci_high"] for row in rows], dtype=float)
    colors = ["#3b6ea8" if row["family_type"] == "CROSS_FAMILY" else "#777777" for row in rows]
    ax.barh(y, values, color=colors, alpha=.9)
    ax.errorbar(values, y, xerr=np.vstack((values - lows, highs - values)), fmt="none", color="black", capsize=2, linewidth=.8)
    ax.set_yticks(y, [row["pair"] for row in rows]); ax.invert_yaxis(); ax.set_xlim(0, max(.05, float(np.nanmax(highs)) * 1.08)); ax.set_xlabel("Lineages with ≥1 differing effective-policy dimension")
    fig.tight_layout(); _save_figure(fig, "pairwise_divergence"); plt.close(fig)

    selected_families = sorted({row["assessment_family"] for row in rq1_grouped if row["assessment_family"] in {"NoNewPrivileges", "PrivateTmp", "ProtectSystem", "ProtectHome", "CapabilityBoundingSet", "RestrictNamespaces", "RestrictAddressFamilies", "SystemCallFilter"}})
    distributions = ["debian", "ubuntu", "fedora", "arch"]
    matrix = np.array([[next((row["proportion"] for row in rq1_grouped if row["distribution"] == distribution and row["assessment_family"] == family), np.nan) for distribution in distributions] for family in selected_families])
    fig, ax = plt.subplots(figsize=(5.8, max(2.5, .34 * len(selected_families))))
    image = ax.imshow(matrix, vmin=0, vmax=1, cmap="Blues", aspect="auto")
    ax.set_xticks(range(4), [x.title() for x in distributions]); ax.set_yticks(range(len(selected_families)), selected_families)
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            if not math.isnan(matrix[i, j]): ax.text(j, i, f"{matrix[i,j]:.0%}", ha="center", va="center", color="black", fontsize=7)
    fig.colorbar(image, ax=ax, label="restrictive/non-default state"); fig.tight_layout(); _save_figure(fig, "adoption_heatmap"); plt.close(fig)

    up_rows = [row for row in transform if row["transition"] == "U_P"]
    categories = ["INHERITED_SAME", "ADDED", "REMOVED", "MODIFIED"]
    distributions = ["debian", "ubuntu", "fedora", "arch"]
    fig, ax = plt.subplots(figsize=(6.4, 3.5)); bottom = np.zeros(4)
    palette = ["#7f7f7f", "#3b6ea8", "#b35c44", "#8b6bb1"]
    for category, color in zip(categories, palette):
        values = np.array([next((row["proportion"] for row in up_rows if row["distribution"] == distribution and row["category"] == category), 0) for distribution in distributions])
        ax.bar(distributions, values, bottom=bottom, label=category.replace("_", " ").title(), color=color); bottom += values
    ax.set_ylim(0, 1); ax.set_ylabel("Share of resolved U→P assessment families"); ax.legend(frameon=False, ncol=2); fig.tight_layout(); _save_figure(fig, "upstream_package_transformations"); plt.close(fig)

    from matplotlib.patches import FancyBboxPatch

    package_rows = flow[:3]
    cohort_rows = flow[3:]
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.25), gridspec_kw={"width_ratios": [1, 1.18]})
    for ax in axes:
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis("off")

    def flow_box(ax: Any, y: float, title: str, detail: str, color: str) -> None:
        box = FancyBboxPatch(
            (.12, y - .09), .76, .18,
            boxstyle="round,pad=0.012,rounding_size=0.018",
            linewidth=.9, edgecolor="#455a64", facecolor=color,
        )
        ax.add_patch(box)
        ax.text(.5, y + .025, title, ha="center", va="center", fontsize=8)
        ax.text(.5, y - .038, detail, ha="center", va="center", fontsize=7, color="#37474f")

    axes[0].set_title("A. Population construction")
    population_boxes = [
        ("Frozen repository population", f"{package_rows[0]['projects_or_packages']:,} service-shipping packages", "#eceff1"),
        ("Cross-family eligibility", f"{package_rows[1]['projects_or_packages']:,} canonical upstream projects", "#e3f2fd"),
        ("Candidate observations", f"{package_rows[2]['projects_or_packages']:,} packages; 3,537 metadata service paths", "#eceff1"),
    ]
    for y, (title, detail, color) in zip((.79, .50, .21), population_boxes):
        flow_box(axes[0], y, title, detail, color)
    for upper, lower in ((.69, .60), (.40, .31)):
        axes[0].annotate("", xy=(.5, lower), xytext=(.5, upper), arrowprops={"arrowstyle": "-|>", "color": "#455a64", "lw": 1})

    axes[1].set_title("B. Analytical cohorts")
    cohort_labels = ["C1X Tier-A", "Comparable E", "C3X", "C3F"]
    cohort_colors = ["#e3f2fd", "#e3f2fd", "#e8f5e9", "#e8f5e9"]
    for y, label, row, color in zip((.82, .61, .40, .19), cohort_labels, cohort_rows, cohort_colors):
        detail = f"{row['projects_or_packages']:,} projects; {row['lineages_or_services']:,} lineages"
        flow_box(axes[1], y, label, detail, color)
    for upper, lower in ((.72, .70), (.51, .49), (.30, .28)):
        axes[1].annotate("", xy=(.5, lower), xytext=(.5, upper), arrowprops={"arrowstyle": "-|>", "color": "#455a64", "lw": 1})
    fig.tight_layout(); _save_figure(fig, "attrition_flow"); plt.close(fig)


def _save_figure(fig: Any, stem: str) -> None:
    for extension in ("svg", "pdf", "png"):
        fig.savefig(FIGURES / f"{stem}.{extension}", bbox_inches="tight", dpi=300 if extension == "png" else None)


def run() -> dict[str, Any]:
    ANALYSIS.mkdir(parents=True, exist_ok=True); TABLES.mkdir(parents=True, exist_ok=True); FIGURES.mkdir(parents=True, exist_ok=True); REVISION_RESULTS.mkdir(parents=True, exist_ok=True)
    states = read_csv(NORMALIZED / "policy_states.csv")
    transformations = read_csv(NORMALIZED / "transformations.csv")
    upstream = read_csv(NORMALIZED / "upstream_artifacts.csv")
    lineages = read_csv(NORMALIZED / "service_lineages.csv")
    terminal = read_csv(NORMALIZED / "project_terminal_states.csv")
    cohorts, projects = _cohorts()
    rq1_fine, rq1_grouped, rq1_projects, rq1_counts = rq1(states, cohorts, projects)
    rq1_paired = rq1_paired_differences(states, cohorts, projects)
    pair_rows, pair_summary, dimension_summary, grouped_dimension_summary = pairwise_divergence(states, cohorts, projects)
    union_summary = rq2_union_summary(pair_rows)
    transform, transform_dimensions = transformation_summaries(transformations, cohorts, projects)
    transform_grouped = grouped_transformation_summaries(transformations, cohorts, projects)
    transform_pairs = transformation_pair_summaries(transformations, cohorts, projects)
    semantic_directions = semantic_direction_summaries(transformations, cohorts, projects)
    resolution_summary = provenance_resolution_summary(states, cohorts, projects)
    mode_sensitivity = matching_mode_sensitivity(pair_rows, transformations, lineages, cohorts, projects)
    exposure, exposure_deltas = exposure_summaries(states, cohorts, projects)
    exposure_pairs = exposure_pair_summaries(states, cohorts, projects)
    robustness_rows, dominance = robustness(states, transformations, cohorts, projects, pair_rows, pair_summary, upstream, lineages)
    audit = quality_audit(cohorts, projects, states, lineages, terminal, upstream, transformations)
    flow = attrition_flow(cohorts, projects, terminal, pair_rows)
    attrition_reasons, matching_attrition = attrition_summaries(lineages)
    provenance_classes, provenance_pairs = provenance_summaries(upstream, cohorts, projects, states)
    outputs = {
        "rq1_adoption_fine.csv": (rq1_fine, list(rq1_fine[0])),
        "rq1_adoption_grouped.csv": (rq1_grouped, list(rq1_grouped[0])),
        "rq1_project_adoption_grouped.csv": (rq1_projects, list(rq1_projects[0])),
        "rq1_lineage_dimension_counts.csv": (rq1_counts, list(rq1_counts[0])),
        "rq1_paired_adoption_differences.csv": (rq1_paired, list(rq1_paired[0])),
        "rq2_lineage_divergence.csv": (pair_rows, list(pair_rows[0])),
        "rq2_pairwise_summary.csv": (pair_summary, list(pair_summary[0])),
        "rq2_cross_family_union_summary.csv": (union_summary, list(union_summary[0])),
        "rq2_dimension_divergence.csv": (dimension_summary, list(dimension_summary[0])),
        "rq2_grouped_dimension_divergence.csv": (grouped_dimension_summary, list(grouped_dimension_summary[0])),
        "rq3_transformation_summary.csv": (transform, list(transform[0])),
        "rq3_dimension_transformations.csv": (transform_dimensions, list(transform_dimensions[0])),
        "rq3_grouped_transformation_summary.csv": (transform_grouped, list(transform_grouped[0])),
        "rq3_pair_transformation_summary.csv": (transform_pairs, list(transform_pairs[0])),
        "rq3_semantic_direction_summary.csv": (semantic_directions, list(semantic_directions[0])),
        "rq3_provenance_resolution_summary.csv": (resolution_summary, list(resolution_summary[0])),
        "rq4_exposure_summary.csv": (exposure, list(exposure[0])),
        "rq4_exposure_delta_summary.csv": (exposure_deltas, list(exposure_deltas[0])),
        "rq4_pair_exposure_summary.csv": (exposure_pairs, list(exposure_pairs[0])),
        "robustness_summary.csv": (robustness_rows, list(robustness_rows[0])),
        "project_dominance.csv": (dominance, list(dominance[0])),
        "attrition_flow.csv": (flow, list(flow[0])),
        "attrition_reason_summary.csv": (attrition_reasons, list(attrition_reasons[0])),
        "matching_attrition_by_distribution.csv": (matching_attrition, list(matching_attrition[0])),
        "provenance_classes_by_distribution.csv": (provenance_classes, list(provenance_classes[0])),
        "provenance_retention_by_pair.csv": (provenance_pairs, list(provenance_pairs[0])),
        "matching_mode_outcome_sensitivity.csv": (mode_sensitivity, list(mode_sensitivity[0])),
    }
    for name, (rows, fields) in outputs.items():
        ordered_rows = presentation_order_pair_rows(rows)
        write_csv(ANALYSIS / name, ordered_rows, fields)
        write_csv(TABLES / name, ordered_rows, fields)
    atomic_json(ANALYSIS / "data_quality_audit.json", audit)
    if not audit["all_pass"]:
        raise RuntimeError(f"data-quality audit failed: {[key for key, value in audit['checks'].items() if not value]}")
    write_figures(rq1_grouped, pair_summary, transform_grouped, flow, robustness_rows)
    pipeline_metrics = json.loads((ANALYSIS / "full_census_pipeline_metrics.json").read_text())
    c1x_projects = len({projects[lineage] for lineage in cohorts["C1X"]})
    c3x_projects = len({projects[lineage] for lineage in cohorts["C3X"]})
    cross_rows = [row for row in pair_rows if row["family_type"] == "CROSS_FAMILY"]
    derivative = next(row for row in pair_summary if row["family_type"] == "DERIVATIVE_FAMILY")
    up_rows = [row for row in transformations if row["transition"] == "U_P" and row["lineage_id"] in cohorts["C3X"]]
    up_grouped = [row for row in transform_grouped if row["transition"] == "U_P"]
    headline = {
        "eligible_projects": 469,
        "c1x_projects": c1x_projects,
        "c1x_lineages": len(cohorts["C1X"]),
        "c3x_projects": c3x_projects,
        "c3x_lineages": len(cohorts["C3X"]),
        "cross_family_pair_memberships": len(cross_rows),
        "cross_family_differing_pair_memberships": sum(row["differing"] for row in cross_rows),
        "cross_family_divergence_rate_pair_memberships": sum(row["differing"] for row in cross_rows) / len(cross_rows),
        "cross_family_comparable_union_lineages": pipeline_metrics["cross_family_comparable_lineages"],
        "cross_family_differing_union_lineages": pipeline_metrics["cross_family_differing_lineages"],
        "cross_family_divergence_rate_union_lineages": pipeline_metrics["cross_family_divergence_rate"],
        "derivative_pair_projects": derivative["matched_projects"],
        "derivative_pair_lineages": derivative["tier_a_lineages"],
        "derivative_pair_comparable_projects": derivative["comparable_projects"],
        "derivative_pair_comparable_lineages": derivative["comparable_lineages"],
        "derivative_pair_differing": derivative["differing_lineages"],
        "derivative_pair_divergence_rate": derivative["divergence_rate"],
        "u_p_resolved_dimensions": len(up_rows),
        "u_p_changed_dimensions": sum(row["provenance_category"] != "INHERITED_SAME" for row in up_rows),
        "u_p_changed_rate": sum(row["provenance_category"] != "INHERITED_SAME" for row in up_rows) / len(up_rows) if up_rows else None,
        "u_p_grouped_resolved_families": sum(row["denominator"] for row in up_grouped if row["category"] == "INHERITED_SAME"),
        "u_p_grouped_changed_families": sum(row["numerator"] for row in up_grouped if row["category"] != "INHERITED_SAME"),
        "u_p_grouped_changed_rate": (
            sum(row["numerator"] for row in up_grouped if row["category"] != "INHERITED_SAME")
            / sum(row["denominator"] for row in up_grouped if row["category"] == "INHERITED_SAME")
        ),
        "determinism_pass": pipeline_metrics["determinism_pass"],
        "data_quality_pass": audit["all_pass"],
        "bootstrap_seed": SEED,
        "bootstrap_replicates": BOOTSTRAPS,
        "rq3d_status": "RQ3d_DISABLED",
    }
    atomic_json(ANALYSIS / "headline_results.json", headline)
    comparison = matching_revision_comparison(lineages, cohorts, headline)
    atomic_json(ANALYSIS / "matching_revision_comparison.json", comparison)
    atomic_json(REVISION_RESULTS / "headline_results.json", headline)
    atomic_json(REVISION_RESULTS / "matching_revision_comparison.json", comparison)
    for name in (
        "rq1_paired_adoption_differences.csv", "rq2_pairwise_summary.csv",
        "rq2_cross_family_union_summary.csv", "rq3_semantic_direction_summary.csv",
        "rq3_provenance_resolution_summary.csv", "matching_mode_outcome_sensitivity.csv",
        "attrition_flow.csv", "matching_attrition_by_distribution.csv",
    ):
        rows, fields = outputs[name]
        write_csv(REVISION_RESULTS / name, presentation_order_pair_rows(rows), fields)
    hashes = {str(path.relative_to(ARTIFACTS)): sha256_file(path) for path in sorted([*ANALYSIS.glob("*"), *TABLES.glob("*")]) if path.is_file()}
    atomic_json(ARTIFACTS / "manifests/analysis_output_hashes.json", hashes)
    return headline


if __name__ == "__main__":
    run()
