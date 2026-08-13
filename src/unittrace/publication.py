from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path
from typing import Any

from .io import atomic_json, download, sha256_file


ROOT = Path(__file__).resolve().parents[2]
FULL = ROOT / "artifacts/full"
ANALYSIS = FULL / "analysis"
MANIFESTS = FULL / "manifests"
MANUSCRIPT = ROOT / "manuscript"
TOOLING = FULL / "tooling"

TECTONIC_VERSION = "0.16.9"
TECTONIC_ARCHIVE = TOOLING / f"tectonic-{TECTONIC_VERSION}-x86_64-unknown-linux-musl.tar.gz"
TECTONIC_BINARY = TOOLING / "tectonic"
TECTONIC_URL = (
    f"https://github.com/tectonic-typesetting/tectonic/releases/download/"
    f"tectonic%40{TECTONIC_VERSION}/tectonic-{TECTONIC_VERSION}-x86_64-unknown-linux-musl.tar.gz"
)
TECTONIC_ARCHIVE_SHA256 = "60b13a0826ae7ad9ce34b4a2df06bff2cfcfa6dda8a915477c0cbb84e1a4a902"
SOURCE_DATE_EPOCH = "1786233600"  # 2026-08-09T00:00:00Z, the frozen Arch snapshot date.


def _csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _macro_values() -> dict[str, str]:
    text = (MANUSCRIPT / "results.tex").read_text(encoding="utf-8")
    return dict(re.findall(r"\\newcommand\{\\([^}]+)\}\{([^}]*)\}", text))


def _integer(value: int | str) -> str:
    return f"{int(value):,}"


def _percent(value: float | str, digits: int = 1) -> str:
    return f"{float(value) * 100:.{digits}f}\\%"


def generate_result_macros() -> dict[str, str]:
    """Generate every repeated manuscript number from machine-readable results."""
    headline = json.loads((ANALYSIS / "headline_results.json").read_text())
    grouped = _csv(ANALYSIS / "rq3_grouped_transformation_summary.csv")
    fine = _csv(ANALYSIS / "rq3_transformation_summary.csv")
    pairs = {row["pair"]: row for row in _csv(ANALYSIS / "rq2_pairwise_summary.csv")}
    union = _csv(ANALYSIS / "rq2_cross_family_union_summary.csv")[0]
    rq1_paired = _csv(ANALYSIS / "rq1_paired_adoption_differences.csv")
    resolution = {row["distribution"]: row for row in _csv(ANALYSIS / "rq3_provenance_resolution_summary.csv")}
    semantic = _csv(ANALYSIS / "rq3_semantic_direction_summary.csv")
    mode_sensitivity = {
        (row["endpoint"], row["matching_mode"]): row
        for row in _csv(ANALYSIS / "matching_mode_outcome_sensitivity.csv")
    }
    exposure_pairs = _csv(ANALYSIS / "rq4_pair_exposure_summary.csv")
    pipeline_metrics = json.loads((ANALYSIS / "full_census_pipeline_metrics.json").read_text())
    pair_lineages = _csv(ANALYSIS / "rq2_lineage_divergence.csv")
    cohorts = _csv(FULL / "normalized/cohorts.csv")
    rates = {row["distribution"]: row for row in _csv(ANALYSIS / "revision_rq3_grouped_change_rates.csv")}
    u1 = _csv(ANALYSIS / "revision_u1_projector_validation_summary.csv")[0]
    corroboration = {
        (row["cohort"], row["signal"]): row
        for row in _csv(ANALYSIS / "revision_matching_corroboration_summary.csv")
    }
    matching_sensitivity = {
        row["subset"]: row
        for row in _csv(ANALYSIS / "matching_construct_validity_rq2_overall.csv")
    }
    magnitudes = {
        (row["pair"], row["scope"]): row
        for row in _csv(ANALYSIS / "revision_divergence_magnitude_summary.csv")
    }
    sources = {
        (row["pair"], row["source_category"]): row
        for row in _csv(ANALYSIS / "revision_divergence_source_effective_differences.csv")
    }
    resolved_sources = {
        (row["pair"], row["source_category"]): row
        for row in _csv(ANALYSIS / "revision_divergence_source_resolved_effective_differences.csv")
    }
    family_rows = [
        row for row in _csv(ANALYSIS / "revision_rq3_family_transformations.csv")
        if row["distribution"] == "ALL"
    ]
    contrasts = {
        row["cross_family_pair"]: row
        for row in _csv(ANALYSIS / "revision_derivative_contrasts.csv")
    }

    up = [row for row in grouped if row["transition"] == "U_P"]
    pe = [row for row in grouped if row["transition"] == "P_E"]
    fine_up = [row for row in fine if row["transition"] == "U_P"]
    grouped_denominator = sum(int(row["denominator"]) for row in up if row["category"] == "INHERITED_SAME")
    grouped_categories = {
        category: sum(int(row["numerator"]) for row in up if row["category"] == category)
        for category in ("INHERITED_SAME", "ADDED", "REMOVED", "MODIFIED")
    }
    grouped_changed = sum(grouped_categories[x] for x in ("ADDED", "REMOVED", "MODIFIED"))
    fine_denominator = sum(int(row["denominator"]) for row in fine_up if row["category"] == "INHERITED_SAME")
    fine_changed = sum(
        int(row["numerator"]) for row in fine_up if row["category"] != "INHERITED_SAME"
    )
    pe_denominator = sum(int(row["numerator"]) for row in pe if row["category"] == "INHERITED_SAME")
    selected_rq1_families = {
        "NoNewPrivileges", "PrivateTmp", "ProtectSystem", "ProtectHome",
        "CapabilityBoundingSet", "RestrictNamespaces", "RestrictAddressFamilies", "SystemCallFilter",
    }
    selected_rq1 = [
        row for row in rq1_paired
        if row["family_type"] == "CROSS_FAMILY" and row["assessment_family"] in selected_rq1_families
    ]
    exact_rq2 = mode_sensitivity[("RQ2_CROSS_FAMILY_UNION_DIVERGENCE", "EXACT_UPSTREAM_UNIT_IDENTITY")]
    executable_rq2 = mode_sensitivity[("RQ2_CROSS_FAMILY_UNION_DIVERGENCE", "UNAMBIGUOUS_EXECUTABLE_LINEAGE")]
    all_resolution = resolution["ALL"]
    semantic_up = [row for row in semantic if row["transition"] == "U_P"]

    values: dict[str, str] = {
        "EligibleProjects": _integer(headline["eligible_projects"]),
        "COneXProjects": _integer(headline["c1x_projects"]),
        "COneXLineages": _integer(headline["c1x_lineages"]),
        "ComparableUnion": _integer(headline["cross_family_comparable_union_lineages"]),
        "ComparableUnionProjects": _integer(
            len(
                {
                    row["project"]
                    for row in pair_lineages
                    if row["family_type"] == "CROSS_FAMILY" and int(row["comparable_dimensions"]) > 0
                }
            )
        ),
        "DifferingUnion": _integer(headline["cross_family_differing_union_lineages"]),
        "UnionRate": _percent(headline["cross_family_differing_union_lineages"] / headline["cross_family_comparable_union_lineages"], 2),
        "UnionCILow": _percent(union["ci_low"], 2),
        "UnionCIHigh": _percent(union["ci_high"], 2),
        "CThreeXProjects": _integer(headline["c3x_projects"]),
        "CThreeXLineages": _integer(headline["c3x_lineages"]),
        "GroupedResolved": _integer(grouped_denominator),
        "GroupedInherited": _integer(grouped_categories["INHERITED_SAME"]),
        "GroupedAdded": _integer(grouped_categories["ADDED"]),
        "GroupedRemoved": _integer(grouped_categories["REMOVED"]),
        "GroupedModified": _integer(grouped_categories["MODIFIED"]),
        "GroupedChanged": _integer(grouped_changed),
        "GroupedChangedRate": _percent(grouped_changed / grouped_denominator, 2),
        "FineResolved": _integer(fine_denominator),
        "FineChanged": _integer(fine_changed),
        "FineChangedRate": _percent(fine_changed / fine_denominator, 2),
        "PEGroupedResolved": _integer(pe_denominator),
        "DerivativeMatched": _integer(headline["derivative_pair_lineages"]),
        "DerivativeComparable": _integer(headline["derivative_pair_comparable_lineages"]),
        "DerivativeDiffering": _integer(headline["derivative_pair_differing"]),
        "DerivativeRate": _percent(headline["derivative_pair_divergence_rate"]),
        "BootstrapReplicates": _integer(headline["bootstrap_replicates"]),
        "BootstrapSeed": _integer(headline["bootstrap_seed"]),
        "AcceptedLineages": _integer(sum(int(row["lineages"]) for row in pipeline_metrics["matching_modes"] if row["cohort"] == "WHOLE_PILOT")),
        "ExactAcceptedLineages": _integer(next(row["lineages"] for row in pipeline_metrics["matching_modes"] if row["cohort"] == "WHOLE_PILOT" and row["match_mode"] == "EXACT_UPSTREAM_UNIT_IDENTITY")),
        "ExecutableAcceptedLineages": _integer(next(row["lineages"] for row in pipeline_metrics["matching_modes"] if row["cohort"] == "WHOLE_PILOT" and row["match_mode"] == "UNAMBIGUOUS_EXECUTABLE_LINEAGE")),
        "ExactCOneXLineages": _integer(next(row["lineages"] for row in pipeline_metrics["matching_modes"] if row["cohort"] == "C1X" and row["match_mode"] == "EXACT_UPSTREAM_UNIT_IDENTITY")),
        "ExecutableCOneXLineages": _integer(next(row["lineages"] for row in pipeline_metrics["matching_modes"] if row["cohort"] == "C1X" and row["match_mode"] == "UNAMBIGUOUS_EXECUTABLE_LINEAGE")),
        "ExactRQTwoDiffering": _integer(exact_rq2["numerator"]),
        "ExactRQTwoComparable": _integer(exact_rq2["denominator"]),
        "ExactRQTwoRate": _percent(exact_rq2["estimate"], 2),
        "ExactRQTwoCILow": _percent(exact_rq2["ci_low"]),
        "ExactRQTwoCIHigh": _percent(exact_rq2["ci_high"]),
        "ExecutableRQTwoDiffering": _integer(executable_rq2["numerator"]),
        "ExecutableRQTwoComparable": _integer(executable_rq2["denominator"]),
        "ExecutableRQTwoRate": _percent(executable_rq2["estimate"], 2),
        "ExecutableRQTwoCILow": _percent(executable_rq2["ci_low"]),
        "ExecutableRQTwoCIHigh": _percent(executable_rq2["ci_high"]),
        "RQOneSelectedContrasts": _integer(len(selected_rq1)),
        "RQOneSelectedMaximumGap": f"{max(abs(float(row['left_minus_right_percentage_points'])) for row in selected_rq1):.1f}",
        "RQOneSelectedIntervalsExcludingZero": _integer(sum(float(row["ci_low_percentage_points"]) > 0 or float(row["ci_high_percentage_points"]) < 0 for row in selected_rq1)),
        "ObservedUCandidateDimensions": _integer(all_resolution["candidate_u_dimensions"]),
        "ObservedUResolvedDimensions": _integer(all_resolution["resolved_u_dimensions"]),
        "ObservedUUnresolvedDimensions": _integer(all_resolution["unresolved_u_dimensions"]),
        "ObservedUResolutionRate": _percent(all_resolution["resolution_rate"], 2),
        "UPTightenedDimensions": _integer(sum(int(row["numerator"]) for row in semantic_up if row["semantic_category"] == "TIGHTENED_UNDER_FIXED_POLICY")),
        "UPRelaxedDimensions": _integer(sum(int(row["numerator"]) for row in semantic_up if row["semantic_category"] == "RELAXED_UNDER_FIXED_POLICY")),
        "UPEqualExposureChangedDimensions": _integer(sum(int(row["numerator"]) for row in semantic_up if row["semantic_category"] == "CHANGED_EQUAL_EXPOSURE")),
        "ExposureCrossLower": _integer(sum(int(row["left_lower"]) for row in exposure_pairs if row["family_type"] == "CROSS_FAMILY")),
        "ExposureCrossEqual": _integer(sum(int(row["equal"]) for row in exposure_pairs if row["family_type"] == "CROSS_FAMILY")),
        "ExposureCrossHigher": _integer(sum(int(row["left_higher"]) for row in exposure_pairs if row["family_type"] == "CROSS_FAMILY")),
        "UOneCandidates": _integer(u1["candidate_observations"]),
        "UOneValidated": _integer(u1["validated_observations"]),
        "UOneUnresolved": _integer(u1["unresolved_observations"]),
        "UOneGroupedResolved": _integer(u1["grouped_resolved"]),
        "UOneGroupedExact": _integer(u1["grouped_exact"]),
        "UOneGroupedAgreement": _percent(u1["grouped_agreement"], 1),
        "UOneFineResolved": _integer(u1["fine_resolved"]),
        "UOneFineExact": _integer(u1["fine_exact"]),
        "UOneFineAgreement": _percent(u1["fine_agreement"], 1),
        "UOneDisagreeingObservations": _integer(u1["disagreeing_observations"]),
        "UOneLiteralAssignments": _integer(u1["literal_assignments"]),
        "UOneLiteralPreserved": _integer(u1["literal_assignments_preserved"]),
    }
    for cohort in ("C1", "C1D", "C2", "C3", "C3F", "C4", "C5"):
        rows = [row for row in cohorts if row["cohort"] == cohort]
        label = {"C1": "COne", "C1D": "COneD", "C2": "CTwo", "C3": "CThree", "C3F": "CThreeF", "C4": "CFour", "C5": "CFive"}[cohort]
        values[f"{label}Projects"] = _integer(len({row["canonical_upstream_id"] for row in rows}))
        values[f"{label}Lineages"] = _integer(len({row["lineage_id"] for row in rows}))
    pair_labels = {
        "Debian ↔ Ubuntu": "DU", "Debian ↔ Fedora": "DF", "Debian ↔ Arch": "DA",
        "Ubuntu ↔ Fedora": "UF", "Ubuntu ↔ Arch": "UA", "Fedora ↔ Arch": "FA",
    }
    for pair, label in pair_labels.items():
        row = pairs[pair]
        for field, suffix in (("matched_projects", "Projects"), ("tier_a_lineages", "TierA"), ("comparable_lineages", "Comparable"), ("differing_lineages", "Differing")):
            values[f"{label}{suffix}"] = _integer(row[field])
        values[f"{label}Rate"] = _percent(row["divergence_rate"])
        values[f"{label}CILow"] = _percent(row["divergence_ci_low"])
        values[f"{label}CIHigh"] = _percent(row["divergence_ci_high"])
        if pair != "Debian ↔ Ubuntu":
            magnitude = magnitudes[(pair, "DIVERGENT_ONLY")]
            values[f"{label}MagnitudeMedian"] = _percent(magnitude["median"], 1)
            values[f"{label}MagnitudeMedianCILow"] = _percent(magnitude["median_ci_low"], 1)
            values[f"{label}MagnitudeMedianCIHigh"] = _percent(magnitude["median_ci_high"], 1)
            values[f"{label}MagnitudeIQRLow"] = _percent(magnitude["iqr_low"], 1)
            values[f"{label}MagnitudeIQRHigh"] = _percent(magnitude["iqr_high"], 1)
            values[f"{label}MagnitudePninety"] = _percent(magnitude["p90"], 1)
            values[f"{label}MagnitudeMaximum"] = _percent(magnitude["maximum"], 1)
            values[f"{label}ExactlyOne"] = _integer(magnitude["exactly_one"])
            values[f"{label}TwoThree"] = _integer(magnitude["two_to_three"])
            values[f"{label}FourPlus"] = _integer(magnitude["four_or_more"])
            for category, suffix in (
                ("UPSTREAM_DIFFERENCE_INHERITED", "SourceUpstream"),
                ("DOWNSTREAM_INTRODUCED", "SourceDownstream"),
                ("DOWNSTREAM_AMPLIFIED_OR_MODIFIED", "SourceMixed"),
                ("UNRESOLVED", "SourceUnresolved"),
            ):
                source = sources[(pair, category)]
                values[f"{label}{suffix}"] = _integer(source["numerator"])
                values[f"{label}SourceDenominator"] = _integer(source["denominator"])
                values[f"{label}{suffix}Rate"] = _percent(source["proportion"], 1)
                values[f"{label}{suffix}CILow"] = _percent(source["ci_low"], 1)
                values[f"{label}{suffix}CIHigh"] = _percent(source["ci_high"], 1)
                if category != "UNRESOLVED":
                    resolved_source = resolved_sources[(pair, category)]
                    values[f"{label}Resolved{suffix}"] = _integer(resolved_source["numerator"])
                    values[f"{label}ResolvedSourceDenominator"] = _integer(resolved_source["denominator"])
                    values[f"{label}Resolved{suffix}Rate"] = _percent(resolved_source["proportion"], 1)
                    values[f"{label}Resolved{suffix}CILow"] = _percent(resolved_source["ci_low"], 1)
                    values[f"{label}Resolved{suffix}CIHigh"] = _percent(resolved_source["ci_high"], 1)
            contrast = contrasts[pair]
            values[f"{label}DUContrast"] = f"{float(contrast['absolute_percentage_point_difference']):.1f}"
            values[f"{label}DUContrastLow"] = f"{float(contrast['ci_low_percentage_points']):.1f}"
            values[f"{label}DUContrastHigh"] = f"{float(contrast['ci_high_percentage_points']):.1f}"
    strong = corroboration[("C1X", "any_strong_orthogonal_corroboration")]
    weak_any = corroboration[("C1X", "any_orthogonal_corroboration")]
    values.update({
        "MatchStrong": _integer(strong["corroborated_lineages"]),
        "MatchStrongDenominator": _integer(strong["lineages"]),
        "MatchStrongRate": _percent(strong["proportion"], 1),
        "MatchAny": _integer(weak_any["corroborated_lineages"]),
        "MatchAnyRate": _percent(weak_any["proportion"], 1),
    })
    for subset, label in (
        ("EXECSTART_CORROBORATED", "ExecSensitivity"),
        ("UPSTREAM_HASH_CORROBORATED", "HashSensitivity"),
        ("STRONG_SIGNAL_UNION", "StrongUnionSensitivity"),
    ):
        row = matching_sensitivity[subset]
        values[f"{label}Projects"] = _integer(row["retained_projects"])
        values[f"{label}Matches"] = _integer(row["retained_matches"])
        values[f"{label}Comparable"] = _integer(row["comparable_matches"])
        values[f"{label}Differing"] = _integer(row["differing_matches"])
        values[f"{label}Rate"] = _percent(row["divergence_rate"])
        values[f"{label}CILow"] = _percent(row["ci_low"])
        values[f"{label}CIHigh"] = _percent(row["ci_high"])
        values[f"{label}PPDifference"] = (
            f"{float(row['absolute_percentage_point_difference_from_primary']):.1f}"
        )
    for signal, label in (
        ("exact_cross_distribution_unit_content", "MatchExactUnit"),
        ("shared_upstream_artifact_hash", "MatchSharedUpstream"),
        ("execstart_target_package_owned_in_two_or_more_members", "MatchOwnedExec"),
        ("shared_source_package_name", "MatchSharedSourceName"),
    ):
        row = corroboration[("C1X", signal)]
        values[label] = _integer(row["corroborated_lineages"])
        values[f"{label}Rate"] = _percent(row["proportion"], 1)
    for distribution, label in (("ALL", "Overall"), ("debian", "Debian"), ("ubuntu", "Ubuntu"), ("fedora", "Fedora"), ("arch", "Arch")):
        row = rates[distribution]
        values[f"{label}GroupedChanged"] = _integer(row["changed"])
        values[f"{label}GroupedDenominator"] = _integer(row["denominator"])
        values[f"{label}GroupedRate"] = _percent(row["change_rate"], 2)
        values[f"{label}GroupedCILow"] = _percent(row["ci_low"], 2)
        values[f"{label}GroupedCIHigh"] = _percent(row["ci_high"], 2)

    top_families = sorted(
        family_rows,
        key=lambda row: (-int(row["total_changed"]), row["assessment_family"]),
    )[:8]
    ordinals = ("One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight")
    for ordinal, row in zip(ordinals, top_families):
        values[f"TopFamily{ordinal}Name"] = row["assessment_family"]
        values[f"TopFamily{ordinal}Added"] = _integer(row["added"])
        values[f"TopFamily{ordinal}Removed"] = _integer(row["removed"])
        values[f"TopFamily{ordinal}Modified"] = _integer(row["modified"])
        values[f"TopFamily{ordinal}Changed"] = _integer(row["total_changed"])
        values[f"TopFamily{ordinal}Denominator"] = _integer(row["denominator"])
        values[f"TopFamily{ordinal}Rate"] = _percent(row["change_rate"], 2)

    lines = ["% Automatically generated from artifacts/full/analysis; do not edit numbers manually."]
    lines.extend(f"\\newcommand{{\\{name}}}{{{value}}}" for name, value in values.items())
    (MANUSCRIPT / "results.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return values


def numeric_audit() -> dict[str, Any]:
    headline = json.loads((ANALYSIS / "headline_results.json").read_text())
    pairs = {row["pair"]: row for row in _csv(ANALYSIS / "rq2_pairwise_summary.csv")}
    grouped = _csv(ANALYSIS / "rq3_grouped_transformation_summary.csv")
    rates = {row["distribution"]: row for row in _csv(ANALYSIS / "revision_rq3_grouped_change_rates.csv")}
    corroboration = {
        (row["cohort"], row["signal"]): row
        for row in _csv(ANALYSIS / "revision_matching_corroboration_summary.csv")
    }
    matching_sensitivity = {
        row["subset"]: row
        for row in _csv(ANALYSIS / "matching_construct_validity_rq2_overall.csv")
    }
    matching_sensitivity_pairs = _csv(
        ANALYSIS / "matching_construct_validity_rq2_pairwise.csv"
    )
    matching_sensitivity_rq3 = {
        row["subset"]: row
        for row in _csv(ANALYSIS / "matching_construct_validity_rq3.csv")
    }
    u1 = _csv(ANALYSIS / "revision_u1_projector_validation_summary.csv")[0]
    pair_lineages = _csv(ANALYSIS / "rq2_lineage_divergence.csv")
    premium_figures = json.loads((MANIFESTS / "premium_figure_validation.json").read_text())
    report = (ROOT / "STUDY_REPORT.md").read_text(encoding="utf-8")
    revision_report = (ROOT / "REVISION_REPORT.md").read_text(encoding="utf-8")
    manuscript = (MANUSCRIPT / "manuscript.tex").read_text(encoding="utf-8")
    figure_text = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((FULL / "figures").glob("*.svg"))
    )
    macros = _macro_values()
    grouped_resolved = sum(int(row["denominator"]) for row in grouped if row["transition"] == "U_P" and row["category"] == "INHERITED_SAME")
    grouped_changed = sum(int(row["numerator"]) for row in grouped if row["transition"] == "U_P" and row["category"] != "INHERITED_SAME")
    grouped_categories = {
        category: sum(
            int(row["numerator"])
            for row in grouped
            if row["transition"] == "U_P" and row["category"] == category
        )
        for category in ("INHERITED_SAME", "ADDED", "REMOVED", "MODIFIED")
    }
    pe_equal = sum(
        int(row["numerator"])
        for row in grouped
        if row["transition"] == "P_E" and row["category"] == "INHERITED_SAME"
    )
    comparable_projects = len(
        {
            row["project"]
            for row in pair_lineages
            if row["family_type"] == "CROSS_FAMILY" and int(row["comparable_dimensions"]) > 0
        }
    )
    canonical = {
        "eligible_projects": (headline["eligible_projects"], macros["EligibleProjects"]),
        "c1x_projects": (headline["c1x_projects"], macros["COneXProjects"]),
        "c1x_lineages": (headline["c1x_lineages"], macros["COneXLineages"]),
        "c3x_projects": (headline["c3x_projects"], macros["CThreeXProjects"]),
        "c3x_lineages": (headline["c3x_lineages"], macros["CThreeXLineages"]),
        "comparable_union": (headline["cross_family_comparable_union_lineages"], macros["ComparableUnion"]),
        "comparable_union_projects": (comparable_projects, macros["ComparableUnionProjects"]),
        "differing_union": (headline["cross_family_differing_union_lineages"], macros["DifferingUnion"]),
        "grouped_resolved": (grouped_resolved, macros["GroupedResolved"].replace(",", "")),
        "grouped_changed": (grouped_changed, macros["GroupedChanged"]),
        "grouped_inherited": (grouped_categories["INHERITED_SAME"], macros["GroupedInherited"]),
        "grouped_added": (grouped_categories["ADDED"], macros["GroupedAdded"]),
        "grouped_removed": (grouped_categories["REMOVED"], macros["GroupedRemoved"]),
        "grouped_modified": (grouped_categories["MODIFIED"], macros["GroupedModified"]),
        "p_e_equal": (pe_equal, macros["PEGroupedResolved"].replace(",", "")),
        "derivative_tier_a": (headline["derivative_pair_lineages"], macros["DerivativeMatched"]),
        "derivative_comparable": (headline["derivative_pair_comparable_lineages"], macros["DerivativeComparable"]),
        "derivative_differing": (headline["derivative_pair_differing"], macros["DerivativeDiffering"]),
    }
    checks: list[dict[str, Any]] = []
    for name, (source, macro) in canonical.items():
        passed = int(source) == int(str(macro).replace(",", ""))
        checks.append({"claim": name, "source_value": source, "macro_value": macro, "passed": passed})
    expected_pairs = {
        "Debian ↔ Ubuntu": (260, 467, 459, 19, 4.1),
        "Debian ↔ Fedora": (178, 335, 335, 61, 18.2),
        "Debian ↔ Arch": (130, 192, 192, 61, 31.8),
        "Ubuntu ↔ Fedora": (244, 443, 434, 78, 18.0),
        "Ubuntu ↔ Arch": (153, 239, 238, 57, 23.9),
        "Fedora ↔ Arch": (156, 258, 258, 55, 21.3),
    }
    for pair, expected in expected_pairs.items():
        row = pairs[pair]
        actual = (
            int(row["matched_projects"]), int(row["tier_a_lineages"]), int(row["comparable_lineages"]),
            int(row["differing_lineages"]), round(float(row["divergence_rate"]) * 100, 1),
        )
        checks.append({"claim": f"pair:{pair}", "source_value": actual, "display_value": expected, "passed": actual == expected})

    authoritative_exact = {
        "eligible_projects": (headline["eligible_projects"], 469),
        "c1x_projects": (headline["c1x_projects"], 375),
        "c1x_lineages": (headline["c1x_lineages"], 649),
        "comparable_projects": (comparable_projects, 373),
        "comparable_lineages": (headline["cross_family_comparable_union_lineages"], 645),
        "differing_union": (headline["cross_family_differing_union_lineages"], 164),
        "c3x_projects": (headline["c3x_projects"], 237),
        "c3x_lineages": (headline["c3x_lineages"], 418),
        "grouped_changed": (grouped_changed, 302),
        "grouped_resolved": (grouped_resolved, 39357),
        "grouped_inherited": (grouped_categories["INHERITED_SAME"], 39055),
        "grouped_added": (grouped_categories["ADDED"], 151),
        "grouped_removed": (grouped_categories["REMOVED"], 84),
        "grouped_modified": (grouped_categories["MODIFIED"], 67),
        "p_e_equal": (pe_equal, 66312),
        "matching_strong_union": (int(corroboration[("C1X", "any_strong_orthogonal_corroboration")]["corroborated_lineages"]), 558),
        "matching_exact_unit": (int(corroboration[("C1X", "exact_cross_distribution_unit_content")]["corroborated_lineages"]), 442),
        "matching_shared_upstream": (int(corroboration[("C1X", "shared_upstream_artifact_hash")]["corroborated_lineages"]), 422),
        "matching_owned_exec": (int(corroboration[("C1X", "execstart_target_package_owned_in_two_or_more_members")]["corroborated_lineages"]), 387),
        "matching_shared_source": (int(corroboration[("C1X", "shared_source_package_name")]["corroborated_lineages"]), 631),
        "matching_any_signal": (int(corroboration[("C1X", "any_orthogonal_corroboration")]["corroborated_lineages"]), 643),
        "u1_candidates": (int(u1["candidate_observations"]), 709),
        "u1_validated": (int(u1["validated_observations"]), 677),
        "u1_unresolved": (int(u1["unresolved_observations"]), 32),
        "u1_grouped_exact": (int(u1["grouped_exact"]), 24117),
        "u1_grouped_resolved": (int(u1["grouped_resolved"]), 24117),
        "u1_fine_exact": (int(u1["fine_exact"]), 54582),
        "u1_fine_resolved": (int(u1["fine_resolved"]), 54582),
        "u1_literal_preserved": (int(u1["literal_assignments_preserved"]), 5576),
        "u1_literal_assignments": (int(u1["literal_assignments"]), 5576),
    }
    checks.extend(
        {"claim": f"authoritative:{name}", "source_value": actual, "expected_value": expected, "passed": actual == expected}
        for name, (actual, expected) in authoritative_exact.items()
    )
    rate_checks = {
        "union_rate": (round(headline["cross_family_divergence_rate_union_lineages"] * 100, 1), 25.4),
        "grouped_change_rate": (round(grouped_changed / grouped_resolved * 100, 2), 0.77),
        "grouped_ci_low": (round(float(rates["ALL"]["ci_low"]) * 100, 2), 0.46),
        "grouped_ci_high": (round(float(rates["ALL"]["ci_high"]) * 100, 2), 1.16),
        "matching_strong_rate": (round(float(corroboration[("C1X", "any_strong_orthogonal_corroboration")]["proportion"]) * 100, 1), 86.0),
    }
    checks.extend(
        {"claim": f"authoritative:{name}", "source_value": actual, "expected_value": expected, "passed": actual == expected}
        for name, (actual, expected) in rate_checks.items()
    )
    expected_sensitivity = {
        "EXECSTART_CORROBORATED": (242, 387, 387, 107, 27.6, 20.8, 35.9, 2.2),
        "UPSTREAM_HASH_CORROBORATED": (215, 422, 419, 57, 13.6, 8.7, 20.8, 11.8),
        "STRONG_SIGNAL_UNION": (312, 558, 555, 123, 22.2, 16.1, 30.0, 3.3),
    }
    support_by_subset = {
        "EXECSTART_CORROBORATED": int(
            corroboration[("C1X", "execstart_target_package_owned_in_two_or_more_members")]["corroborated_lineages"]
        ),
        "UPSTREAM_HASH_CORROBORATED": int(
            corroboration[("C1X", "shared_upstream_artifact_hash")]["corroborated_lineages"]
        ),
        "STRONG_SIGNAL_UNION": int(
            corroboration[("C1X", "any_strong_orthogonal_corroboration")]["corroborated_lineages"]
        ),
    }
    expected_pairs = {"Debian ↔ Fedora", "Debian ↔ Arch", "Ubuntu ↔ Fedora", "Ubuntu ↔ Arch", "Fedora ↔ Arch"}
    for subset, expected in expected_sensitivity.items():
        row = matching_sensitivity[subset]
        actual = (
            int(row["retained_projects"]),
            int(row["retained_matches"]),
            int(row["comparable_matches"]),
            int(row["differing_matches"]),
            round(float(row["divergence_rate"]) * 100, 1),
            round(float(row["ci_low"]) * 100, 1),
            round(float(row["ci_high"]) * 100, 1),
            round(float(row["absolute_percentage_point_difference_from_primary"]), 1),
        )
        checks.append(
            {
                "claim": f"matching_sensitivity:{subset}:observed_result",
                "source_value": actual,
                "expected_value": expected,
                "passed": actual == expected,
            }
        )
        subset_pairs = [pair for pair in matching_sensitivity_pairs if pair["subset"] == subset]
        checks.extend(
            (
                {
                    "claim": f"matching_sensitivity:{subset}:parent_support",
                    "source_value": int(row["retained_matches"]),
                    "expected_value": support_by_subset[subset],
                    "passed": int(row["retained_matches"]) == support_by_subset[subset],
                },
                {
                    "claim": f"matching_sensitivity:{subset}:five_cross_family_pairs",
                    "source_value": sorted(pair["pair"] for pair in subset_pairs),
                    "expected_value": sorted(expected_pairs),
                    "passed": len(subset_pairs) == 5 and {pair["pair"] for pair in subset_pairs} == expected_pairs,
                },
                {
                    "claim": f"matching_sensitivity:{subset}:rate_arithmetic",
                    "passed": abs(
                        float(row["divergence_rate"])
                        - int(row["differing_matches"]) / int(row["comparable_matches"])
                    ) < 1e-12,
                },
                {
                    "claim": f"matching_sensitivity:{subset}:primary_preserved",
                    "passed": row["primary_membership_changed"].casefold() == "false"
                    and abs(float(row["primary_divergence_rate"]) - 164 / 645) < 1e-12,
                },
            )
        )
        checks.extend(
            {
                "claim": f"matching_sensitivity:{subset}:{pair['pair']}:rate_arithmetic",
                "passed": abs(
                    float(pair["divergence_rate"])
                    - int(pair["differing_matches"]) / int(pair["comparable_matches"])
                ) < 1e-12
                and pair["primary_membership_changed"].casefold() == "false",
            }
            for pair in subset_pairs
        )
    expected_rq3_sensitivity = {
        "EXECSTART_CORROBORATED": (148, 227, 24219, 146, 0.60, 0.33, 0.96),
        "STRONG_SIGNAL_UNION": (215, 383, 37233, 258, 0.69, 0.39, 1.09),
    }
    for subset, expected in expected_rq3_sensitivity.items():
        row = matching_sensitivity_rq3[subset]
        actual = (
            int(row["retained_c3x_projects"]),
            int(row["retained_c3x_matches"]),
            int(row["resolved_policy_group_observations"]),
            int(row["changed_observations"]),
            round(float(row["change_rate"]) * 100, 2),
            round(float(row["ci_low"]) * 100, 2),
            round(float(row["ci_high"]) * 100, 2),
        )
        checks.append(
            {
                "claim": f"matching_sensitivity:rq3:{subset}",
                "source_value": actual,
                "expected_value": expected,
                "passed": actual == expected
                and row["primary_membership_changed"].casefold() == "false",
            }
        )
    expected_distribution_rates = {
        "debian": (53, 8595, 0.62),
        "ubuntu": (68, 11271, 0.60),
        "fedora": (89, 12459, 0.71),
        "arch": (92, 7032, 1.31),
    }
    for distribution, expected in expected_distribution_rates.items():
        row = rates[distribution]
        actual = (int(row["changed"]), int(row["denominator"]), round(float(row["change_rate"]) * 100, 2))
        checks.append({"claim": f"rq3_distribution:{distribution}", "source_value": actual, "expected_value": expected, "passed": actual == expected})

    pair_order = ["Debian ↔ Fedora", "Debian ↔ Arch", "Ubuntu ↔ Fedora", "Ubuntu ↔ Arch", "Fedora ↔ Arch", "Debian ↔ Ubuntu"]
    ordered_csv_checks: list[dict[str, Any]] = []
    for directory in (ANALYSIS, FULL / "tables"):
        for path in sorted(directory.glob("*.csv")):
            rows = _csv(path)
            if not rows or not ({"pair", "cross_family_pair"} & set(rows[0])):
                continue
            groups: dict[str, list[dict[str, str]]] = {}
            for row in rows:
                groups.setdefault(row.get("analysis", "ALL"), []).append(row)
            for group, group_rows in groups.items():
                observed = list(
                    dict.fromkeys(
                        row.get("pair", row.get("cross_family_pair", ""))
                        for row in group_rows
                        if row.get("pair", row.get("cross_family_pair", "")) in pair_order
                    )
                )
                expected = [pair for pair in pair_order if pair in observed]
                ordered_csv_checks.append({"file": str(path.relative_to(ROOT)), "group": group, "observed": observed, "expected": expected, "passed": observed == expected})
    checks.append({"claim": "supplementary_pair_order", "files_checked": len(ordered_csv_checks), "passed": all(row["passed"] for row in ordered_csv_checks), "failures": [row for row in ordered_csv_checks if not row["passed"]]})

    def table_block(label: str) -> str:
        start = manuscript.index(f"\\label{{{label}}}")
        end = manuscript.index("\\end{table}", start)
        return manuscript[start:end]

    primary_tokens = ("D/F", "D/A", "U/F", "U/A", "F/A")
    manuscript_table_order = all(
        [table_block(label).index(token) for token in primary_tokens] == sorted(table_block(label).index(token) for token in primary_tokens)
        for label in ("tab:pairs", "tab:magnitude", "tab:source")
    ) and table_block("tab:pairs").index("D/U") > table_block("tab:pairs").index("F/A")
    document_claims = {
        "report_union": f"{headline['cross_family_differing_union_lineages']:,}/{headline['cross_family_comparable_union_lineages']:,}" in report,
        "report_grouped_transformation": f"{grouped_changed:,}/{grouped_resolved:,}" in report,
        "report_derivative": f"{headline['derivative_pair_differing']:,}/{headline['derivative_pair_comparable_lineages']:,}" in report,
        "manuscript_uses_result_macros": all(f"\\{name}" in manuscript for name in ("EligibleProjects", "COneXLineages", "DifferingUnion", "GroupedChanged")),
        "matching_sensitivity_reported": all(
            token in report
            for token in ("107/387", "57/419", "123/555", "matching-construct-validity sensitivity analysis")
        ),
        "matching_sensitivity_manuscript_macros": all(
            f"\\{name}" in manuscript
            for name in (
                "ExecSensitivityDiffering",
                "HashSensitivityDiffering",
                "StrongUnionSensitivityDiffering",
            )
        ),
        "p_e_negative_finding_explained_once": manuscript.count(
            "Because E was evaluated independently of P, this equality is an observed negative result"
        ) == 1,
        "abstract_excludes_phase0_percentages": "Phase 0" not in manuscript.split("\\end{abstract}", 1)[0],
        "rq3d_removed_from_article": "RQ3d" in report and "RQ3d" not in manuscript and "C2D" not in manuscript,
        "protocol_wording": all(term in manuscript.casefold() for term in ("before running the full census, we fixed", "the resulting population matches the pre-study manifest"))
        and "fixed before full-census outcome analysis" not in manuscript.casefold()
        and "preregistered" not in manuscript.casefold(),
        "revision_analyses_present": all(term in manuscript for term in ("source attribution", "policy-group disagreement", "U1 template validation")),
        "manuscript_pair_order": manuscript_table_order,
        "rq2_typo_removed": "66.7% to 69.4% or 69.4%" not in manuscript and "or \\DAMagnitudeMaximum" not in manuscript,
        "table2_distinct_bin_headers": all(term in table_block("tab:magnitude") for term in ("1 group", "2 to 3 groups", "$\\geq$4 groups")),
        "figure7_zero_mixed_reported": "none of the attributable cases falls into the amplified/modified category" in manuscript.casefold(),
        "no_adversarial_review_section": "\\section{Adversarial Review}" not in manuscript,
        "matching_corroboration_wording": all(
            term not in manuscript.casefold()
            for term in ("independent signals", "statistically independent")
        ) and "matching validation" in manuscript.casefold(),
        "internal_workflow_ids_removed": all(term not in manuscript for term in ("FULL-006", "FULL-007", "FULL-008", "Phase 0R-X", "revision request", "previous manuscript", "old U-to-P assessment rows")),
        "revision_report_corroboration_wording": "independently corroborates" not in revision_report.casefold() and "independent frozen signals" not in revision_report.casefold(),
        "moderated_divergence_wording": "widespread" not in manuscript.casefold(),
        "visual_highlights_removed": premium_figures["visual_encoding_audit"]["unexplained_focal_outlines"] == 0,
        "figure6_totals": premium_figures["visual_encoding_audit"]["figure6_changed_totals"] == {"Debian": 53, "Ubuntu": 68, "Fedora": 89, "Arch": 92},
        "schema_enums_removed_from_article": all(
            term not in manuscript and term.replace("_", "\\_") not in manuscript
            for term in ("PRESENT_RESOLVED", "ABSENT_RESOLVED", "VALUE_UNRESOLVED", "ABSENCE_UNRESOLVED")
        ),
        "figure_policy_group_terminology": all(
            term not in figure_text
            for term in (
                "GROUPED FAMILY ADOPTION",
                "effective-policy family",
                "1 family",
                "2 to 3 families",
                "≥4 families",
                "WITHIN-LINEAGE DIVERGENCE MAGNITUDE",
                "Changed resolved U→P families (%)",
                "lineage–family observations",
            )
        ),
    }
    checks.extend({"claim": key, "passed": value} for key, value in document_claims.items())
    result = {
        "documents_checked": ["STUDY_REPORT.md", "REVISION_REPORT.md", "manuscript/manuscript.tex", "manuscript/results.tex", "artifacts/full/analysis/*.csv", "artifacts/full/analysis/matching_construct_validity_*.csv", "artifacts/full/figures/*"],
        "checks": checks, "all_pass": all(row["passed"] for row in checks),
        "figure_numeric_provenance": {
            "pairwise_divergence": "rq2_pairwise_summary.csv",
            "adoption_heatmap": "rq1_adoption_grouped.csv",
            "upstream_package_transformations": "rq3_grouped_transformation_summary.csv",
            "attrition_flow": "attrition_flow.csv",
            "divergence_magnitude": "revision_divergence_magnitude_summary.csv",
            "divergence_source": "revision_divergence_source_effective_differences.csv",
            "upe_provenance_flow": "fixed U/P/E study design",
        },
    }
    atomic_json(ANALYSIS / "numeric_consistency_audit.json", result)
    _assert(result["all_pass"], "numeric consistency audit failed")
    return result


def literature_manifest() -> dict[str, Any]:
    records = [
        {"key": "dunlap2022sandbox", "title": "A Study of Application Sandbox Policies in Linux", "authors": "Trevor Dunlap; William Enck; Bradley Reaves", "venue": "27th ACM SACMAT", "year": 2022, "doi": "10.1145/3532105.3535016", "verified_via": "Crossref registry and ACM DOI record"},
        {"key": "lin2022bugs", "title": "Upstream bug management in Linux distributions", "authors": "Jiahuei Lin; Haoxiang Zhang; Bram Adams; Ahmed E. Hassan", "venue": "Empirical Software Engineering 27(6), article 134", "year": 2022, "doi": "10.1007/s10664-022-10173-y", "verified_via": "Springer publisher record and Crossref"},
        {"key": "lin2023vulnerabilities", "title": "Vulnerability management in Linux distributions", "authors": "Jiahuei Lin; Haoxiang Zhang; Bram Adams; Ahmed E. Hassan", "venue": "Empirical Software Engineering 28(2), article 47", "year": 2023, "doi": "10.1007/s10664-022-10267-7", "verified_via": "Springer publisher record and Crossref"},
        {"key": "peng2026patch", "title": "Toward Efficient Package Maintenance: An Empirical Study of Patch Sharing across Four Linux Distributions", "authors": "Jian Peng; Jiaxin Zhu; Yuwei Zhang; Wei Chen; Guoquan Wu; Wei Wang; Jun Wei", "venue": "48th IEEE/ACM ICSE Research Track", "year": 2026, "doi": None, "verified_via": "official ICSE 2026 conference record; no DOI identified at cutoff"},
        {"key": "hu2026kernel", "title": "SoK: Take a Deep Step into Linux Kernel Hardening Effectiveness from the Offensive-Defensive Perspective", "authors": "Yinhao Hu; Pengyu Ding; Zhenpeng Lin; Dongliang Mu; Yuan Li", "venue": "NDSS 2026", "year": 2026, "doi": "10.14722/ndss.2026.241725", "verified_via": "official NDSS paper page and Crossref"},
        {"key": "li2024patchporting", "title": "An Investigation of Patch Porting Practices of the Linux Kernel Ecosystem", "authors": "Xingyu Li; Zheng Zhang; Zhiyun Qian; Trent Jaeger; Chengyu Song", "venue": "MSR 2024, pp. 63–74", "year": 2024, "doi": "10.1145/3643991.3644902", "verified_via": "Consensus full record, Crossref, and ACM DOI metadata"},
        {"key": "lamb2022reproducible", "title": "Reproducible Builds: Increasing the Integrity of Software Supply Chains", "authors": "Chris Lamb; Stefano Zacchiroli", "venue": "IEEE Software 39(2), pp. 62–70", "year": 2022, "doi": "10.1109/MS.2021.3073045", "verified_via": "Consensus full record and Crossref/IEEE metadata"},
        {"key": "bajaj2024unreproducible", "title": "Unreproducible builds: time to fix, causes, and correlation with external ecosystem factors", "authors": "Rahul Bajaj; Eduardo Fernandes; Bram Adams; Ahmed E. Hassan", "venue": "Empirical Software Engineering 29(1), article 11", "year": 2024, "doi": "10.1007/s10664-023-10399-4", "verified_via": "Consensus full record, Crossref, and institutional bibliographic record"},
        {"key": "ren2022patching", "title": "Automated Patching for Unreproducible Builds", "authors": "Zhilei Ren; Shiwei Sun; Jifeng Xuan; Xiaochen Li; Zhide Zhou; He Jiang", "venue": "ICSE 2022, pp. 200–211", "year": 2022, "doi": "10.1145/3510003.3510102", "verified_via": "Crossref and ACM DOI metadata"},
        {"key": "benedetti2025packaging", "title": "An Empirical Study on Reproducible Packaging in Open-Source Ecosystems", "authors": "Giacomo Benedetti; Oreofe Solarin; Courtney Miller; Greg Tystahl; William Enck; Christian Kästner; Alexandros Kapravelos; Alessio Merlo; Luca Verderame", "venue": "ICSE 2025, pp. 1052–1063", "year": 2025, "doi": "10.1109/ICSE55347.2025.00136", "verified_via": "Consensus search record and Crossref/IEEE metadata"},
        {"key": "decan2019ecosystems", "title": "An empirical comparison of dependency network evolution in seven software packaging ecosystems", "authors": "Alexandre Decan; Tom Mens; Philippe Grosjean", "venue": "Empirical Software Engineering 24(1), pp. 381–416", "year": 2019, "doi": "10.1007/s10664-017-9589-y", "verified_via": "Crossref/Springer metadata"},
        {"key": "maass2016sandboxing", "title": "A systematic analysis of the science of sandboxing", "authors": "Michael Maass; Adam Sales; Benjamin Chung; Joshua Sunshine", "venue": "PeerJ Computer Science 2:e43", "year": 2016, "doi": "10.7717/peerj-cs.43", "verified_via": "Crossref and publisher DOI record"},
        {"key": "ghavamnia2020confine", "title": "Confine: Automated System Call Policy Generation for Container Attack Surface Reduction", "authors": "Seyedhamed Ghavamnia; Tapti Palit; Azzedine Benameur; Michalis Polychronakis", "venue": "RAID 2020, pp. 443–458", "year": 2020, "doi": None, "verified_via": "official USENIX paper and proceedings record"},
        {"key": "demarinis2020sysfilter", "title": "sysfilter: Automated System Call Filtering for Commodity Software", "authors": "Nicholas DeMarinis; Kent Williams-King; Di Jin; Rodrigo Fonseca; Vasileios P. Kemerlis", "venue": "RAID 2020, pp. 459–474", "year": 2020, "doi": None, "verified_via": "official USENIX paper and proceedings record"},
        {"key": "ghavamnia2020temporal", "title": "Temporal System Call Specialization for Attack Surface Reduction", "authors": "Seyedhamed Ghavamnia; Tapti Palit; Shachee Mishra; Michalis Polychronakis", "venue": "USENIX Security 2020, pp. 1749–1766", "year": 2020, "doi": None, "verified_via": "official USENIX paper and proceedings record"},
        {"key": "alhindi2025seccomp", "title": "Playing in the Sandbox: A Study on the Usability of Seccomp", "authors": "Maysara Alhindi; Joseph Hallett", "venue": "SOUPS 2025, pp. 225–240", "year": 2025, "doi": None, "verified_via": "official USENIX paper and proceedings record"},
        {"key": "yin2011configuration", "title": "An Empirical Study on Configuration Errors in Commercial and Open Source Systems", "authors": "Zuoning Yin; Xiao Ma; Jing Zheng; Yuanyuan Zhou; Lakshmi N. Bairavasundaram; Shankar Pasupathy", "venue": "SOSP 2011, pp. 159–172", "year": 2011, "doi": "10.1145/2043556.2043572", "verified_via": "Crossref and ACM DOI metadata"},
        {"key": "xu2013misconfigurations", "title": "Do Not Blame Users for Misconfigurations", "authors": "Tianyin Xu; Jiaqi Zhang; Peng Huang; Jing Zheng; Tianwei Sheng; Ding Yuan; Yuanyuan Zhou; Shankar Pasupathy", "venue": "SOSP 2013, pp. 244–259", "year": 2013, "doi": "10.1145/2517349.2522727", "verified_via": "Crossref and ACM DOI metadata"},
        {"key": "xu2015knobs", "title": "Hey, You Have Given Me Too Many Knobs!: Understanding and Dealing with Over-Designed Configuration in System Software", "authors": "Tianyin Xu; Long Jin; Xuepeng Fan; Yuanyuan Zhou; Shankar Pasupathy; Rukma Talwadker", "venue": "ESEC/FSE 2015, pp. 307–319", "year": 2015, "doi": "10.1145/2786805.2786852", "verified_via": "Crossref and ACM DOI metadata"},
        {"key": "rabkin2011configuration", "title": "Static Extraction of Program Configuration Options", "authors": "Ariel Rabkin; Randy Katz", "venue": "ICSE 2011, pp. 131–140", "year": 2011, "doi": "10.1145/1985793.1985812", "verified_via": "Crossref and ACM DOI metadata"},
    ]
    result = {
        "cutoff": "2026-08-10", "records": records,
        "academic_record_count": len(records),
        "official_documentation": [
            "https://systemd.io/",
            "https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html",
            "https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html",
            "https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html",
            "https://www.debian.org/doc/debian-policy/ch-opersys.html",
            "https://www.debian.org/vote/2014/vote_003",
            "https://docs.fedoraproject.org/en-US/packaging-guidelines/Systemd/",
            "https://fedoraproject.org/wiki/Changes/SystemdSecurityHardening",
            "https://wiki.archlinux.org/title/Arch_package_guidelines",
            "https://documentation.ubuntu.com/server/explanation/software/changing-package-files/",
        ],
        "search_scope": ["Linux distributions as downstream software ecosystems", "patch propagation and upstream/downstream maintenance", "application sandbox and seccomp least privilege", "configuration errors, extraction, and provenance", "reproducible builds and packaging", "systemd service integration and hardening"],
        "research_discovery_services": ["Consensus", "Crossref", "publisher/conference primary records"],
        "bounded_novelty_statement": "No directly equivalent empirical study was identified within the recorded sources and search scope; no unqualified first-study claim is made.",
    }
    atomic_json(MANIFESTS / "literature_verification.json", result)
    return result


def copy_figures() -> dict[str, str]:
    destination = MANUSCRIPT / "figures"
    destination.mkdir(parents=True, exist_ok=True)
    hashes: dict[str, str] = {}
    for stem in (
        "upe_provenance_flow",
        "attrition_flow",
        "adoption_heatmap",
        "pairwise_divergence",
        "divergence_magnitude",
        "divergence_source",
        "upstream_package_transformations",
    ):
        for extension in ("svg", "pdf", "png"):
            source = FULL / "figures" / f"{stem}.{extension}"
            target = destination / source.name
            shutil.copy2(source, target)
            hashes[str(target.relative_to(ROOT))] = sha256_file(target)
    return hashes


def _ensure_tectonic() -> dict[str, Any]:
    TOOLING.mkdir(parents=True, exist_ok=True)
    acquisition = download(TECTONIC_URL, TECTONIC_ARCHIVE, TECTONIC_ARCHIVE_SHA256)
    if not TECTONIC_BINARY.exists():
        temporary = TECTONIC_BINARY.with_suffix(".tmp")
        with tarfile.open(TECTONIC_ARCHIVE, "r:gz") as archive:
            member = archive.getmember("tectonic")
            source = archive.extractfile(member)
            _assert(source is not None and member.isfile(), "pinned Tectonic archive has no regular tectonic binary")
            with temporary.open("wb") as stream:
                shutil.copyfileobj(source, stream)
        temporary.chmod(0o755)
        os.replace(temporary, TECTONIC_BINARY)
    version = subprocess.run(
        [str(TECTONIC_BINARY), "--version"], text=True, capture_output=True, check=False
    )
    _assert(version.returncode == 0, "pinned Tectonic executable is not runnable")
    _assert(f"Tectonic {TECTONIC_VERSION}" in version.stdout, "unexpected Tectonic version")
    return {
        "name": "Tectonic",
        "version": TECTONIC_VERSION,
        "version_output": version.stdout.strip(),
        "release_url": TECTONIC_URL,
        "archive_path": str(TECTONIC_ARCHIVE.relative_to(ROOT)),
        "archive_sha256": sha256_file(TECTONIC_ARCHIVE),
        "binary_path": str(TECTONIC_BINARY.relative_to(ROOT)),
        "binary_sha256": sha256_file(TECTONIC_BINARY),
        "cached": acquisition["cached"],
    }


def _tool_cache_fingerprint() -> dict[str, Any]:
    cache = TOOLING / "cache"
    rows = [
        (str(path.relative_to(cache)), path.stat().st_size, sha256_file(path))
        for path in sorted(cache.rglob("*"))
        if path.is_file()
    ]
    material = json.dumps(rows, separators=(",", ":"), ensure_ascii=False).encode()
    return {
        "path": str(cache.relative_to(ROOT)),
        "file_count": len(rows),
        "combined_sha256": hashlib.sha256(material).hexdigest(),
    }


def compile_manuscript() -> dict[str, Any]:
    tool = _ensure_tectonic()
    command = [str(TECTONIC_BINARY), "--keep-logs", "--color", "never", "manuscript.tex"]
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
    environment["XDG_CACHE_HOME"] = str(TOOLING / "cache")
    pdf = MANUSCRIPT / "manuscript.pdf"
    intermediates = [
        MANUSCRIPT / f"manuscript.{extension}"
        for extension in ("aux", "bbl", "blg", "out", "xdv")
    ]
    for intermediate in intermediates:
        intermediate.unlink(missing_ok=True)
    pdf.unlink(missing_ok=True)
    first = subprocess.run(
        command, cwd=MANUSCRIPT, env=environment, text=True, capture_output=True, check=False
    )
    first_pdf_sha256 = sha256_file(pdf) if first.returncode == 0 and pdf.exists() else None
    second = subprocess.run(
        command, cwd=MANUSCRIPT, env=environment, text=True, capture_output=True, check=False
    ) if first_pdf_sha256 else None
    second_pdf_sha256 = sha256_file(pdf) if second and second.returncode == 0 and pdf.exists() else None
    passed = bool(first.returncode == 0 and second and second.returncode == 0 and first_pdf_sha256 == second_pdf_sha256)
    result = {
        "status": "PASS" if passed else "FAIL", "command": command,
        "returncode": first.returncode,
        "determinism_returncode": second.returncode if second else None,
        "stdout_tail": first.stdout[-4000:], "stderr_tail": first.stderr[-4000:],
        "tool": tool,
        "tool_cache": _tool_cache_fingerprint(),
        "source_date_epoch": SOURCE_DATE_EPOCH,
        "pdf_path": str(pdf.relative_to(ROOT)) if pdf.exists() else None,
        "pdf_sha256": sha256_file(pdf) if pdf.exists() else None,
        "pdf_bytes": pdf.stat().st_size if pdf.exists() else None,
        "pdf_determinism": {
            "first_sha256": first_pdf_sha256,
            "second_sha256": second_pdf_sha256,
            "byte_equivalent": first_pdf_sha256 is not None and first_pdf_sha256 == second_pdf_sha256,
        },
    }
    for intermediate in intermediates:
        intermediate.unlink(missing_ok=True)
    atomic_json(ANALYSIS / "manuscript_compile_status.json", result)
    _assert(passed and pdf.exists(), "manuscript compilation or PDF determinism check failed")
    return result


def _update_reproducibility_manifest(compilation: dict[str, Any]) -> None:
    from .finalize import _source_tree_manifest

    source_files, source_tree_hash = _source_tree_manifest()
    atomic_json(
        MANIFESTS / "source_tree_manifest.json",
        {"files": source_files, "source_tree_sha256": source_tree_hash},
    )
    manifest_path = MANIFESTS / "reproducibility_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["source_tree_sha256"] = source_tree_hash
    revision_manifest = MANIFESTS / "revision_analysis_manifest.json"
    manifest["revision_analysis"] = json.loads(revision_manifest.read_text(encoding="utf-8"))
    premium_validation = MANIFESTS / "premium_figure_validation.json"
    manifest["premium_figure_validation"] = json.loads(premium_validation.read_text(encoding="utf-8"))
    manifest["premium_figure_sources"] = {
        str(path.relative_to(ROOT)): sha256_file(path)
        for path in sorted((FULL / "figures/source").glob("*.html"))
    }
    manifest["correction_and_recovery_hashes"] = {
        str(path.relative_to(ROOT)): sha256_file(path)
        for path in (
            MANIFESTS / "software_corrections.json",
            MANIFESTS / "source_manifest_recovery.json",
            MANIFESTS / "package_manifest_recovery.json",
        )
    }
    manifest["manuscript_build"] = {
        "status": compilation["status"],
        "command": compilation["command"],
        "source_date_epoch": compilation["source_date_epoch"],
        "tool": compilation["tool"],
        "tool_cache": compilation["tool_cache"],
        "pdf_path": compilation["pdf_path"],
        "pdf_sha256": compilation["pdf_sha256"],
        "pdf_bytes": compilation["pdf_bytes"],
        "pdf_determinism": compilation["pdf_determinism"],
    }
    atomic_json(manifest_path, manifest)


def quality_gates(numeric: dict[str, Any], figures: dict[str, str], compilation: dict[str, Any]) -> dict[str, Any]:
    data_quality = json.loads((ANALYSIS / "data_quality_audit.json").read_text())
    reproducibility = json.loads((MANIFESTS / "reproducibility_manifest.json").read_text())
    analysis_determinism = json.loads((MANIFESTS / "analysis_determinism.json").read_text())
    revision_determinism = json.loads((MANIFESTS / "revision_analysis_manifest.json").read_text())
    literature = json.loads((MANIFESTS / "literature_verification.json").read_text())
    premium_figures = json.loads((MANIFESTS / "premium_figure_validation.json").read_text())
    bibliography = (MANUSCRIPT / "references.bib").read_text(encoding="utf-8")
    manuscript = (MANUSCRIPT / "manuscript.tex").read_text(encoding="utf-8")
    gates = {
        "Evidence Gate": numeric["all_pass"] and all(row["key"] in bibliography for row in literature["records"]),
        "Design Gate": data_quality["all_pass"] and "RQ3d" not in manuscript and "C2D" not in manuscript,
        "Analysis Gate": analysis_determinism["byte_equivalent"] and "upstream-project cluster" in manuscript,
        "Interpretation Gate": "Fedora is more secure than Debian" not in manuscript
        and any(
            phrase in manuscript
            for phrase in ("overall operating-system security", "overall distribution security")
        ),
        "Reproducibility Gate": all(reproducibility[key] for key in ("normalized_determinism_pass", "analysis_determinism_pass", "policy_sensitivity_pass")) and revision_determinism["byte_equivalent_repeated_write"],
        "Consistency Gate": numeric["all_pass"],
        "Presentation Gate": (
            len(figures) == 21
            and len(list((FULL / "figures/source").glob("*.html"))) == 7
            and premium_figures["all_pass"]
            and premium_figures["visual_encoding_audit"]["unexplained_focal_outlines"] == 0
            and premium_figures["connector_audit"]["overlaps"] == 0
            and premium_figures["connector_audit"]["behind_non_endpoint_nodes"] == 0
            and "\\bibliography{references}" in manuscript
            and compilation["status"] == "PASS"
            and bool(compilation["pdf_sha256"])
        ),
    }
    result = {"gates": gates, "all_pass": all(gates.values())}
    atomic_json(ANALYSIS / "quality_gates.json", result)
    _assert(result["all_pass"], f"quality gates failed: {[key for key, value in gates.items() if not value]}")
    return result


def run() -> dict[str, Any]:
    generate_result_macros()
    figures = copy_figures()
    compilation = compile_manuscript()
    _update_reproducibility_manifest(compilation)
    literature_manifest()
    numeric = numeric_audit()
    gates = quality_gates(numeric, figures, compilation)
    output_hashes = {
        str(path.relative_to(ROOT)): sha256_file(path)
        for path in [ROOT / "STUDY_REPORT.md", ROOT / "REVISION_REPORT.md", MANUSCRIPT / "manuscript.tex", MANUSCRIPT / "references.bib", MANUSCRIPT / "results.tex", MANUSCRIPT / "manuscript.pdf", ANALYSIS / "manuscript_compile_status.json"]
    }
    output_hashes.update(figures)
    atomic_json(MANIFESTS / "publication_output_hashes.json", output_hashes)
    return gates


if __name__ == "__main__":
    run()
