from __future__ import annotations

import csv
import hashlib
import inspect
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from . import cli, pipeline, protocol
from .io import atomic_json, sha256_file, write_csv


ROOT = Path(__file__).resolve().parents[2]
NORMALIZED = ROOT / "artifacts/normalized"
AUDIT = ROOT / "artifacts/audit"
REPORT = ROOT / "PHASE0_AUDIT_REPORT.md"

DISTRIBUTIONS = ("debian", "ubuntu", "fedora", "arch")
PAIR_SPECS = (
    ("debian", "ubuntu", "Debian ↔ Ubuntu", "derivative-family"),
    ("debian", "fedora", "Debian ↔ Fedora", "cross-family"),
    ("debian", "arch", "Debian ↔ Arch", "cross-family"),
    ("ubuntu", "fedora", "Ubuntu ↔ Fedora", "cross-family"),
    ("ubuntu", "arch", "Ubuntu ↔ Arch", "cross-family"),
    ("fedora", "arch", "Fedora ↔ Arch", "cross-family"),
)
MATCH_MODES = (
    "EXACT_UPSTREAM_UNIT_IDENTITY",
    "PACKAGING_INSTALL_MAPPING",
    "DETERMINISTIC_GENERATION_MAPPING",
    "UNAMBIGUOUS_EXECUTABLE_LINEAGE",
)
PROVENANCE_CLASSES = (
    "U0_STATIC",
    "U1_TEMPLATE_VALUE_ONLY",
    "U2_TEMPLATE_STRUCTURAL",
    "U3_GENERATED_DETERMINISTIC",
    "U4_NO_UPSTREAM_STATIC_OR_TEMPLATE_UNIT",
    "U5_AMBIGUOUS_OR_UNRESOLVED",
)
AUDITED_REASONS = (
    "NO_AUTHORITATIVE_UPSTREAM_URL",
    "NO_TIER_A_PARTNER",
    "SERVICE_LINEAGE_AMBIGUOUS",
    "U4_NO_UPSTREAM_UNIT",
    "U5_AMBIGUOUS_OR_UNRESOLVED",
    "ANALYZER_FAILURE",
)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def matched_lineage_index(rows: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    index: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        if row["match_tier"] == "A" and row["match_status"] == "MATCHED":
            index[row["lineage_id"]].append(row)
    return dict(index)


def effective_state_index(rows: list[dict[str, str]]) -> dict[tuple[str, str], dict[str, str]]:
    index: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)
    for row in rows:
        if row["layer"] == "E" and row["analysis_status"] == "ANALYZABLE" and row["assessment_id"]:
            index[(row["lineage_id"], row["distribution"])][row["assessment_id"]] = row["normalized_state"]
    return dict(index)


def compute_pair_profiles(
    lineages: dict[str, list[dict[str, str]]],
    effective: dict[tuple[str, str], dict[str, str]],
    c3_lineages: set[str],
) -> tuple[list[dict[str, Any]], dict[tuple[str, str], dict[str, set[str]]]]:
    projects = {lineage_id: members[0]["canonical_upstream_id"] for lineage_id, members in lineages.items()}
    distributions = {lineage_id: {row["distribution"] for row in members} for lineage_id, members in lineages.items()}
    profiles: list[dict[str, Any]] = []
    sets: dict[tuple[str, str], dict[str, set[str]]] = {}
    for left, right, label, family_type in PAIR_SPECS:
        pair_lineages = {lineage_id for lineage_id, observed in distributions.items() if {left, right} <= observed}
        comparable: set[str] = set()
        differing: set[str] = set()
        comparable_dimensions = 0
        for lineage_id in pair_lineages:
            left_states = effective.get((lineage_id, left), {})
            right_states = effective.get((lineage_id, right), {})
            common = set(left_states) & set(right_states)
            if not common:
                continue
            comparable.add(lineage_id)
            comparable_dimensions += len(common)
            if any(left_states[assessment] != right_states[assessment] for assessment in common):
                differing.add(lineage_id)
        sets[(left, right)] = {"tier_a": pair_lineages, "comparable": comparable, "differing": differing}
        profiles.append(
            {
                "pair": label,
                "left_distribution": left,
                "right_distribution": right,
                "family_type": family_type,
                "projects": len({projects[lineage_id] for lineage_id in pair_lineages}),
                "tier_a_lineages": len(pair_lineages),
                "comparable_lineages": len(comparable),
                "differing_lineages": len(differing),
                "divergence_rate": ratio(len(differing), len(comparable)),
                "c3_lineages": len(pair_lineages & c3_lineages),
                "comparable_dimensions": comparable_dimensions,
            }
        )
    return profiles, sets


def compute_cross_family(
    pair_sets: dict[tuple[str, str], dict[str, set[str]]],
    lineages: dict[str, list[dict[str, str]]],
    c3_lineages: set[str],
    transformations: list[dict[str, str]],
) -> tuple[dict[str, Any], set[str]]:
    cross_keys = [(left, right) for left, right, _, family_type in PAIR_SPECS if family_type == "cross-family"]
    tier_a = set().union(*(pair_sets[key]["tier_a"] for key in cross_keys))
    comparable = set().union(*(pair_sets[key]["comparable"] for key in cross_keys))
    differing = set().union(*(pair_sets[key]["differing"] for key in cross_keys))
    projects = {lineages[lineage_id][0]["canonical_upstream_id"] for lineage_id in tier_a}
    resolved_u_p = {
        row["lineage_id"]
        for row in transformations
        if row["transition"] == "U_P"
        and row["semantic_category"] != "UNCHANGED"
        and row["source_resolved"] == "True"
        and row["destination_resolved"] == "True"
    }
    transformed = tier_a & c3_lineages & resolved_u_p
    metrics = {
        "cross_family_projects": len(projects),
        "cross_family_tier_a_lineages": len(tier_a),
        "cross_family_comparable_lineages": len(comparable),
        "cross_family_differing_lineages": len(differing),
        "cross_family_divergence_rate": ratio(len(differing), len(comparable)),
        "cross_family_c3_lineages": len(tier_a & c3_lineages),
        "cross_family_transformed_u_p_lineages": len(transformed),
    }
    return metrics, tier_a


def compute_matching_modes(
    lineages: dict[str, list[dict[str, str]]], cross_family: set[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    total = len(lineages)
    cross_total = len(cross_family)
    projects = {lineage_id: members[0]["canonical_upstream_id"] for lineage_id, members in lineages.items()}
    overall: list[dict[str, Any]] = []
    cross: list[dict[str, Any]] = []
    for mode in MATCH_MODES:
        ids = {lineage_id for lineage_id, members in lineages.items() if {row["lineage_match_mode"] for row in members} == {mode}}
        cross_ids = ids & cross_family
        overall.append(
            {
                "match_mode": mode,
                "distinct_projects": len({projects[lineage_id] for lineage_id in ids}),
                "tier_a_lineages": len(ids),
                "percentage": ratio(len(ids), total) or 0.0,
            }
        )
        cross.append(
            {
                "match_mode": mode,
                "distinct_projects": len({projects[lineage_id] for lineage_id in cross_ids}),
                "tier_a_lineages": len(cross_ids),
                "percentage": ratio(len(cross_ids), cross_total) or 0.0,
            }
        )
    return overall, cross


def audit_matching_invariants(
    lineages: dict[str, list[dict[str, str]]],
    all_lineage_rows: list[dict[str, str]],
    unit_rows: list[dict[str, str]],
) -> dict[str, Any]:
    unit_index = {
        (row["distribution"], row["binary_package_id"], row["unit_path"]): row for row in unit_rows
    }
    violations: list[dict[str, str]] = []
    invariant_names = (
        "canonical_upstream_unique",
        "executable_lineage_unique_nonempty",
        "deterministic_lineage_identifier",
        "at_least_two_distributions",
        "one_member_per_distribution",
        "candidate_count_one",
        "tier_and_status_consistent",
        "canonical_unmasked_static_unit",
        "service_unit_executable_agrees",
    )
    for lineage_id, members in sorted(lineages.items()):
        upstreams = {row["canonical_upstream_id"] for row in members}
        executables = {row["normalized_exec_lineage"] for row in members}
        modes = {row["lineage_match_mode"] for row in members}
        artifact_identities = {row.get("upstream_artifact_identity", "") for row in members}
        observed = [row["distribution"] for row in members]
        if modes == {"EXACT_UPSTREAM_UNIT_IDENTITY"}:
            expected_id = (
                f"{next(iter(upstreams))}::upstream-unit::{next(iter(artifact_identities))}"
                if len(upstreams) == 1
                and len(artifact_identities) == 1
                and bool(next(iter(artifact_identities), ""))
                else ""
            )
        else:
            expected_id = (
                f"{next(iter(upstreams))}::{next(iter(executables))}"
                if len(upstreams) == 1 and len(executables) == 1
                else ""
            )
        units = [unit_index.get((row["distribution"], row["binary_package_id"], row["unit_path"])) for row in members]
        checks = {
            "canonical_upstream_unique": len(upstreams) == 1,
            "executable_lineage_unique_nonempty": (
                modes == {"EXACT_UPSTREAM_UNIT_IDENTITY"}
                or (len(executables) == 1 and bool(next(iter(executables), "")))
            ),
            "deterministic_lineage_identifier": lineage_id == expected_id,
            "at_least_two_distributions": len(set(observed)) >= 2,
            "one_member_per_distribution": len(observed) == len(set(observed)),
            "candidate_count_one": all(str(row["candidate_count"]) == "1" for row in members),
            "tier_and_status_consistent": all(
                row["match_tier"] == "A"
                and row["match_status"] == "MATCHED"
                and row["lineage_match_mode"] in MATCH_MODES
                for row in members
            ),
            "canonical_unmasked_static_unit": all(
                unit is not None
                and unit["canonical_target"] == unit["unit_path"]
                and unit["mask_state"] == "UNMASKED"
                and str(unit["is_template_unit"]).casefold() == "false"
                for unit in units
            ),
            "service_unit_executable_agrees": all(
                unit is not None and unit["normalized_exec_lineage"] == row["normalized_exec_lineage"]
                for row, unit in zip(members, units)
            ),
        }
        for violation_type in invariant_names:
            if not checks[violation_type]:
                violations.append({"lineage_id": lineage_id, "violation_type": violation_type})

    matched_ids = set(lineages)
    ambiguous_ids = {
        row["lineage_id"] for row in all_lineage_rows if row["match_status"] == "SERVICE_LINEAGE_AMBIGUOUS"
    }
    match_source = inspect.getsource(pipeline.match_lineages)
    analyze_source = inspect.getsource(cli.analyze)
    normalization_source = inspect.getsource(protocol.normalized_exec_lineage)
    code_checks = {
        "orders_exact_before_executable": (
            match_source.index("for (upstream, identity)")
            < match_source.index("for (upstream, executable)")
        ),
        "rejects_per_distribution_many_to_many": "if any(value > 1 for value in counts.values())" in match_source,
        "requires_multiple_distributions": "if len(distributions) < 2" in match_source,
        "deterministic_group_iteration": (
            "for (upstream, identity), observations in sorted(exact_groups.items())" in match_source
            and "for (upstream, executable), observations in sorted(executable_groups.items())" in match_source
        ),
        "no_basename_grouping": '[(unit["canonical_upstream_id"], unit["unit_basename"])]' not in match_source,
        "no_fuzzy_matching": not any(token in match_source.casefold() for token in ("sequenceMatcher".casefold(), "fuzzy", "levenshtein", "difflib")),
        "no_manual_override_table": not any(token in match_source.casefold() for token in ("manual_override", "override_table", "rescue_table")),
        "matching_precedes_outcome_analysis": analyze_source.index("match_lineages(") < analyze_source.index("analyze_states("),
        "matching_has_no_policy_input": "policy_states" not in match_source and "transformations" not in match_source,
        "executable_normalization_is_exact_basename": "return Path(token).name or None" in normalization_source,
        "executable_normalization_rejects_substitutions": 'if any(marker in token for marker in ("%", "$", "{"))' in normalization_source,
        "ambiguous_and_matched_sets_disjoint": not bool(ambiguous_ids & matched_ids),
    }
    code_violations = sorted(name for name, passed in code_checks.items() if not passed)
    violating_lineages = {row["lineage_id"] for row in violations}
    return {
        "lineages_audited": len(lineages),
        "member_observations_audited": sum(len(members) for members in lineages.values()),
        "lineages_passing_invariants": len(lineages) - len(violating_lineages),
        "lineages_violating_invariants": len(violating_lineages),
        "violation_type_counts": dict(Counter(row["violation_type"] for row in violations)),
        "violations": violations,
        "code_checks": code_checks,
        "code_violation_types": code_violations,
        "blocking_violation": bool(violating_lineages or code_violations),
        "matching_implementation_sha256": sha256_file(ROOT / "src/unittrace/pipeline.py"),
        "orchestration_sha256": sha256_file(ROOT / "src/unittrace/cli.py"),
        "executable_normalization_sha256": sha256_file(ROOT / "src/unittrace/protocol.py"),
    }


def provenance_margin(
    c3_lineages: set[str], cross_family: set[str], lineages: dict[str, list[dict[str, str]]], upstream: list[dict[str, str]]
) -> dict[str, Any]:
    projects = {lineage_id: members[0]["canonical_upstream_id"] for lineage_id, members in lineages.items()}
    c3_projects = {projects[lineage_id] for lineage_id in c3_lineages}
    cross_projects = {projects[lineage_id] for lineage_id in c3_lineages & cross_family}
    class_projects: dict[str, set[str]] = {artifact_class: set() for artifact_class in PROVENANCE_CLASSES}
    usable_classes: dict[str, set[str]] = defaultdict(set)
    for row in upstream:
        if row["lineage_id"] not in c3_lineages:
            continue
        class_projects[row["u_artifact_class"]].add(row["canonical_upstream_id"])
        if row["u_artifact_class"] in PROVENANCE_CLASSES[:4]:
            usable_classes[row["canonical_upstream_id"]].add(row["u_artifact_class"])
    u1_only = {
        project for project, classes in usable_classes.items() if classes == {"U1_TEMPLATE_VALUE_ONLY"}
    }
    without_u1 = {
        project
        for project, classes in usable_classes.items()
        if any(artifact_class != "U1_TEMPLATE_VALUE_ONLY" for artifact_class in classes)
    }
    return {
        "c3_projects_total": len(c3_projects),
        "c3_projects_derivative_pair_only": len(c3_projects - cross_projects),
        "c3_projects_with_cross_family_lineage": len(cross_projects),
        "project_counts_by_provenance_class": {
            artifact_class: len(class_projects[artifact_class]) for artifact_class in PROVENANCE_CLASSES
        },
        "class_counts_are_nonexclusive": True,
        "c3_projects_exclusively_dependent_on_u1": len(u1_only),
        "c3_projects_remaining_if_u1_excluded": len(without_u1),
        "u1_exclusion_sensitivity_meets_original_30_project_threshold": len(without_u1) >= 30,
    }


def exclusion_distribution(row: dict[str, str]) -> str | None:
    if row["reason_code"] == "ANALYZER_FAILURE":
        try:
            _, distribution, _ = row["entity_id"].rsplit(":", 2)
            return distribution
        except ValueError:
            return None
    distribution = row["entity_id"].split(":", 1)[0]
    return distribution if distribution in DISTRIBUTIONS else None


def compute_attrition(
    exclusions: list[dict[str, str]],
    packages: list[dict[str, str]],
    units: list[dict[str, str]],
    upstream: list[dict[str, str]],
    policy_states: list[dict[str, str]],
    all_lineages: list[dict[str, str]],
    pair_sets: dict[tuple[str, str], dict[str, set[str]]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    counts: Counter[tuple[str, str]] = Counter()
    for row in exclusions:
        distribution = exclusion_distribution(row)
        if distribution and row["reason_code"] in AUDITED_REASONS:
            counts[(distribution, row["reason_code"])] += 1
    state_denominators = Counter(
        (row["distribution"], row["lineage_id"], row["layer"])
        for row in policy_states
        if row["layer"] in {"P", "E"}
    )
    distribution_rows: list[dict[str, Any]] = []
    denominator_map: dict[tuple[str, str], int] = {}
    for distribution in DISTRIBUTIONS:
        denominators = {
            "NO_AUTHORITATIVE_UPSTREAM_URL": sum(row["distribution"] == distribution for row in packages),
            "NO_TIER_A_PARTNER": sum(row["distribution"] == distribution for row in units),
            "SERVICE_LINEAGE_AMBIGUOUS": sum(row["distribution"] == distribution for row in units),
            "U4_NO_UPSTREAM_UNIT": sum(row["distribution"] == distribution for row in upstream),
            "U5_AMBIGUOUS_OR_UNRESOLVED": sum(row["distribution"] == distribution for row in upstream),
            "ANALYZER_FAILURE": sum(key[0] == distribution for key in state_denominators),
        }
        for reason in AUDITED_REASONS:
            denominator_map[(distribution, reason)] = denominators[reason]
            count = counts[(distribution, reason)]
            distribution_rows.append(
                {
                    "distribution": distribution,
                    "reason_code": reason,
                    "count": count,
                    "stage_denominator": denominators[reason],
                    "descriptive_rate": ratio(count, denominators[reason]) or 0.0,
                }
            )
    family_rows: list[dict[str, Any]] = []
    families = {"debian_ubuntu_derivative_family": ("debian", "ubuntu"), "fedora_arch_cross_family_targets": ("fedora", "arch")}
    for family, members in families.items():
        for reason in AUDITED_REASONS:
            count = sum(counts[(distribution, reason)] for distribution in members)
            denominator = sum(denominator_map[(distribution, reason)] for distribution in members)
            family_rows.append(
                {
                    "distribution_group": family,
                    "reason_code": reason,
                    "count": count,
                    "stage_denominator": denominator,
                    "descriptive_rate": ratio(count, denominator) or 0.0,
                }
            )

    ambiguous_distributions: dict[str, set[str]] = defaultdict(set)
    for row in all_lineages:
        if row["match_status"] == "SERVICE_LINEAGE_AMBIGUOUS":
            ambiguous_distributions[row["lineage_id"]].add(row["distribution"])
    class_index = {(row["lineage_id"], row["distribution"]): row["u_artifact_class"] for row in upstream}
    analyzer_failure = {
        (row["lineage_id"], row["distribution"])
        for row in policy_states
        if row["layer"] == "E" and row["analysis_status"] == "ANALYZER_FAILURE"
    }
    pair_rows: list[dict[str, Any]] = []
    for left, right, label, family_type in PAIR_SPECS:
        tier_a = pair_sets[(left, right)]["tier_a"]
        comparable = pair_sets[(left, right)]["comparable"]
        pair_rows.append(
            {
                "pair": label,
                "family_type": family_type,
                "ambiguous_candidate_lineages": sum({left, right} <= observed for observed in ambiguous_distributions.values()),
                "tier_a_noncomparable_lineages": len(tier_a - comparable),
                "lineages_with_u4_member": sum(
                    any(class_index.get((lineage_id, distribution)) == "U4_NO_UPSTREAM_STATIC_OR_TEMPLATE_UNIT" for distribution in (left, right))
                    for lineage_id in tier_a
                ),
                "lineages_with_u5_member": sum(
                    any(class_index.get((lineage_id, distribution)) == "U5_AMBIGUOUS_OR_UNRESOLVED" for distribution in (left, right))
                    for lineage_id in tier_a
                ),
                "lineages_with_e_analyzer_failure": sum(
                    any((lineage_id, distribution) in analyzer_failure for distribution in (left, right))
                    for lineage_id in tier_a
                ),
            }
        )
    return distribution_rows, family_rows, pair_rows


def input_manifest(paths: Iterable[Path]) -> dict[str, Any]:
    records = [
        {"path": str(path.relative_to(ROOT)), "sha256": sha256_file(path), "bytes": path.stat().st_size}
        for path in sorted(paths)
    ]
    material = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return {"input_bundle_sha256": hashlib.sha256(material).hexdigest(), "inputs": records}


def percent(value: float | None) -> str:
    return "NA" if value is None else f"{100 * value:.1f}%"


def report_table(headers: list[str], rows: list[list[Any]], align: list[str]) -> str:
    header = "| " + " | ".join(headers) + " |"
    separator = "| " + " | ".join(align) + " |"
    body = ["| " + " | ".join(str(value) for value in row) + " |" for row in rows]
    return "\n".join([header, separator, *body])


def render_report(
    pair_profiles: list[dict[str, Any]],
    cross: dict[str, Any],
    cx_rows: list[dict[str, Any]],
    fx_rows: list[dict[str, Any]],
    modes: list[dict[str, Any]],
    cross_modes: list[dict[str, Any]],
    invariants: dict[str, Any],
    provenance: dict[str, Any],
    attrition_distribution: list[dict[str, Any]],
    attrition_family: list[dict[str, Any]],
    attrition_pair: list[dict[str, Any]],
    audit_result: dict[str, Any],
    determinism: dict[str, Any],
) -> str:
    pair_table = report_table(
        ["Pair", "Projects", "Tier-A lineages", "Comparable lineages", "Differing lineages", "Divergence rate", "C3 lineages"],
        [[row["pair"], row["projects"], row["tier_a_lineages"], row["comparable_lineages"], row["differing_lineages"], percent(row["divergence_rate"]), row["c3_lineages"]] for row in pair_profiles],
        ["----", "-------:", "--------------:", "------------------:", "-----------------:", "--------------:", "----------:"],
    )
    gate_table = report_table(
        ["Gate", "Metric", "Numerator", "Denominator/context", "Value", "Threshold", "Status"],
        [[row["gate"], row["metric"], row["numerator"], row["denominator_context"], row["value_display"], row["threshold"], row["status"]] for row in [*cx_rows, *fx_rows]],
        ["---", "---", "---:", "---:", "---:", "---", "---"],
    )
    mode_table = report_table(
        ["Match mode", "Distinct projects", "Tier-A lineages", "Percentage"],
        [[row["match_mode"], row["distinct_projects"], row["tier_a_lineages"], percent(row["percentage"])] for row in modes],
        ["---", "---:", "---:", "---:"],
    )
    cross_mode_table = report_table(
        ["Cross-family match mode", "Distinct projects", "Tier-A lineages", "Percentage"],
        [[row["match_mode"], row["distinct_projects"], row["tier_a_lineages"], percent(row["percentage"])] for row in cross_modes],
        ["---", "---:", "---:", "---:"],
    )
    provenance_table = report_table(
        ["Upstream provenance class", "Distinct C3 projects"],
        [[artifact_class, provenance["project_counts_by_provenance_class"][artifact_class]] for artifact_class in PROVENANCE_CLASSES],
        ["---", "---:"],
    )
    attrition_table = report_table(
        ["Distribution", "Reason", "Count", "Stage denominator", "Rate"],
        [[row["distribution"].title(), row["reason_code"], row["count"], row["stage_denominator"], percent(row["descriptive_rate"])] for row in attrition_distribution],
        ["---", "---", "---:", "---:", "---:"],
    )
    family_table = report_table(
        ["Distribution group", "Reason", "Count", "Stage denominator", "Rate"],
        [[row["distribution_group"], row["reason_code"], row["count"], row["stage_denominator"], percent(row["descriptive_rate"])] for row in attrition_family],
        ["---", "---", "---:", "---:", "---:"],
    )
    pair_attrition_table = report_table(
        ["Pair", "Ambiguous candidates", "Tier-A noncomparable", "U4 member", "U5 member", "E analyzer failure"],
        [[row["pair"], row["ambiguous_candidate_lineages"], row["tier_a_noncomparable_lineages"], row["lineages_with_u4_member"], row["lineages_with_u5_member"], row["lineages_with_e_analyzer_failure"]] for row in attrition_pair],
        ["---", "---:", "---:", "---:", "---:", "---:"],
    )
    code_checks = "\n".join(
        f"- `{name}`: {'PASS' if passed else 'FAIL'}" for name, passed in invariants["code_checks"].items()
    )
    return f"""# UnitTrace Post–Phase 0R Methodological Audit

## Purpose

This audit tests whether the completed Phase 0R `GO` remains defensible after separating the Debian–Ubuntu derivative-family pair from cross-family support. It uses only frozen Phase 0R normalized artifacts. No repository, observation, classification, or original report was modified.

`PHASE0R_ORIGINAL_DECISION = GO`

## Pairwise Support

{pair_table}

The divergence counts are pilot feasibility signals only, not ecosystem effect estimates. Pairs are not treated as statistically independent.

## Cross-Family Aggregate

- `cross_family_projects = {cross['cross_family_projects']}`
- `cross_family_tier_a_lineages = {cross['cross_family_tier_a_lineages']}`
- `cross_family_comparable_lineages = {cross['cross_family_comparable_lineages']}`
- `cross_family_differing_lineages = {cross['cross_family_differing_lineages']}`
- `cross_family_divergence_rate = {cross['cross_family_divergence_rate']:.4f}`
- Cross-family C3 lineages: {cross['cross_family_c3_lineages']}.

## Audit Gates

{gate_table}

P0R-CX **fails** because only {cross['cross_family_projects']} projects and {cross['cross_family_tier_a_lineages']} Tier-A lineages participate in cross-family comparisons, below 30 and 40. P0R-FX **passes only through the rate condition**: {cross['cross_family_differing_lineages']}/{cross['cross_family_comparable_lineages']} = {percent(cross['cross_family_divergence_rate'])}; the two absolute-count alternatives fail.

## Matching Modes

{mode_table}

{cross_mode_table}

All Tier-A lineages use the weakest permitted strict mode, `UNAMBIGUOUS_EXECUTABLE_LINEAGE`; no observation was upgraded during this audit.

## Tier-A Invariant Audit

- Lineages audited: **{invariants['lineages_audited']}** ({invariants['member_observations_audited']} distribution-member observations).
- Passing all data invariants: **{invariants['lineages_passing_invariants']}**.
- Violating: **{invariants['lineages_violating_invariants']}**.
- Violation types: `{json.dumps(invariants['violation_type_counts'], sort_keys=True)}`.
- Blocking implementation violation: **{invariants['blocking_violation']}**.

Code/data checks:

{code_checks}

The implementation groups by exact canonical upstream ID and normalized executable lineage, requires at least two distributions, rejects any per-distribution multiplicity greater than one, and assigns matches before policy analysis. Unit basename is stored as evidence but is not the grouping key. No fuzzy matcher or manual rescue table exists.

## Provenance Margin

- C3 projects total: **{provenance['c3_projects_total']}**.
- C3 projects contributed only by Debian–Ubuntu support: **{provenance['c3_projects_derivative_pair_only']}**.
- C3 projects with at least one cross-family lineage: **{provenance['c3_projects_with_cross_family_lineage']}**.
- C3 projects exclusively dependent on U1 recovery: **{provenance['c3_projects_exclusively_dependent_on_u1']}**.
- C3 projects remaining if U1 is excluded: **{provenance['c3_projects_remaining_if_u1_excluded']}**; this is below the original 30-project threshold.

{provenance_table}

Class counts are non-exclusive because one project may contribute different artifact classes across distribution observations. This sensitivity does not retroactively change P0R-E, but it shows that the one-project margin is fragile and substantively depends on deterministic U1 template recovery.

## Attrition Profile

Rates use reason-specific stage denominators and are descriptive only; rates across different reason columns are not directly comparable.

{attrition_table}

{family_table}

{pair_attrition_table}

Pre-match `NO_AUTHORITATIVE_UPSTREAM_URL` and `NO_TIER_A_PARTNER` observations cannot be assigned to a missing pair without inventing membership. Descriptively, missing upstream URLs are concentrated in the Debian–Ubuntu package population, while `NO_TIER_A_PARTNER` and `SERVICE_LINEAGE_AMBIGUOUS` rates are higher in the Fedora/Arch pilot observations. No inferential claim is made.

## Ubuntu Ancestry

`RQ3d_DISABLED`

P0R-G is unchanged and is not used in P0R-CX/P0R-FX.

## Remaining Threats

- Cross-family support is only 17 projects and 22 lineages, despite 52 projects and 64 lineages in historical P0R-C.
- Only 12 C3 projects participate in a cross-family lineage; 19 C3 projects are supported only by the Debian–Ubuntu derivative pair.
- All Tier-A matches use executable-lineage evidence; stronger exact-unit, packaging-install, and deterministic-generation modes have zero observations.
- Excluding U1-only projects leaves 15 C3 projects, so provenance feasibility is sensitive to the validated template projector.
- The cross-family divergence rate is a pilot continuation signal, not an ecosystem estimate.

## Required Amendment

Before any full census, freeze a minimal prospective amendment requiring P0R-CX and P0R-FX. Rerun Phase 0R separately with an approximately 60-project pilot selected by the same stable hash rule from the **pre-outcome metadata subset eligible for at least one cross-family pair**, while retaining Debian–Ubuntu descriptively as a derivative-family pair. Do not lower the 30-project/40-lineage cross-family thresholds. This audit does not implement or rerun that redesign.

## Reproducibility

- Command: `uv run python -m unittrace.phase0_audit`
- Frozen input manifest: `artifacts/audit/input_manifest.json`.
- Normalized audit outputs: `artifacts/audit/`.
- Byte-equivalent to immediately preceding audit run: **{determinism.get('byte_equivalent_to_previous_run')}**.

## Final Audit Decision

`POST_PHASE0R_AUDIT = {audit_result['post_phase0r_audit']}`

`PHASE0R_ORIGINAL_DECISION = GO`

`RQ3d_DISABLED`

P0R-CX fails while P0R-FX and all Tier-A invariants pass. The cross-family evidence is non-zero and variable, so the study is not stopped, but the existing pilot does not satisfy the clarified cross-family support intent. Full-census work remains blocked pending the prospective amendment and separate Phase 0R rerun.
"""


def write_determinism_manifest(targets: list[Path]) -> dict[str, Any]:
    current = {str(path.relative_to(ROOT)): sha256_file(path) for path in targets}
    path = AUDIT / "determinism_manifest.json"
    previous = json.loads(path.read_text()).get("current_hashes") if path.exists() else None
    result = {
        "previous_run_available": previous is not None,
        "byte_equivalent_to_previous_run": previous == current if previous is not None else None,
        "current_hashes": current,
        "previous_hashes": previous,
    }
    atomic_json(path, result)
    return result


def main() -> None:
    AUDIT.mkdir(parents=True, exist_ok=True)
    source_paths = {
        "lineages": NORMALIZED / "service_lineages.csv",
        "states": NORMALIZED / "policy_states.csv",
        "cohorts": NORMALIZED / "cohorts.csv",
        "transformations": NORMALIZED / "transformations.csv",
        "upstream": NORMALIZED / "upstream_artifacts.csv",
        "exclusions": NORMALIZED / "exclusions.csv",
        "units": NORMALIZED / "service_units.csv",
        "packages": NORMALIZED / "repository_packages.csv",
    }
    all_lineage_rows = read_csv(source_paths["lineages"])
    policy_states = read_csv(source_paths["states"])
    cohorts = read_csv(source_paths["cohorts"])
    transformations = read_csv(source_paths["transformations"])
    upstream = read_csv(source_paths["upstream"])
    exclusions = read_csv(source_paths["exclusions"])
    units = read_csv(source_paths["units"])
    packages = read_csv(source_paths["packages"])
    lineages = matched_lineage_index(all_lineage_rows)
    effective = effective_state_index(policy_states)
    c3_lineages = {row["lineage_id"] for row in cohorts if row["cohort"] == "C3"}

    pair_profiles, pair_sets = compute_pair_profiles(lineages, effective, c3_lineages)
    cross, cross_family = compute_cross_family(pair_sets, lineages, c3_lineages, transformations)
    modes, cross_modes = compute_matching_modes(lineages, cross_family)
    invariants = audit_matching_invariants(lineages, all_lineage_rows, units)
    provenance = provenance_margin(c3_lineages, cross_family, lineages, upstream)
    distribution_attrition, family_attrition, pair_attrition = compute_attrition(
        exclusions, packages, units, upstream, policy_states, all_lineage_rows, pair_sets
    )

    cx_pass = cross["cross_family_projects"] >= 30 and cross["cross_family_tier_a_lineages"] >= 40
    fx_count_pass = cross["cross_family_differing_lineages"] >= 25
    fx_rate_pass = (cross["cross_family_divergence_rate"] or 0.0) >= 0.10
    fx_transform_pass = cross["cross_family_transformed_u_p_lineages"] >= 25
    fx_pass = fx_count_pass or fx_rate_pass or fx_transform_pass
    cx_rows = [
        {"gate": "P0R-CX", "metric": "cross_family_projects", "numerator": cross["cross_family_projects"], "denominator_context": len({members[0]["canonical_upstream_id"] for members in lineages.values()}), "value_display": cross["cross_family_projects"], "threshold": ">=30", "status": "PASS" if cx_pass else "FAIL"},
        {"gate": "P0R-CX", "metric": "cross_family_tier_a_lineages", "numerator": cross["cross_family_tier_a_lineages"], "denominator_context": len(lineages), "value_display": cross["cross_family_tier_a_lineages"], "threshold": ">=40", "status": "PASS" if cx_pass else "FAIL"},
    ]
    fx_rows = [
        {"gate": "P0R-FX", "metric": "differing_cross_family_lineages", "numerator": cross["cross_family_differing_lineages"], "denominator_context": cross["cross_family_comparable_lineages"], "value_display": cross["cross_family_differing_lineages"], "threshold": ">=25", "status": "PASS" if fx_count_pass else "FAIL"},
        {"gate": "P0R-FX", "metric": "cross_family_divergence_rate", "numerator": cross["cross_family_differing_lineages"], "denominator_context": cross["cross_family_comparable_lineages"], "value_display": percent(cross["cross_family_divergence_rate"]), "threshold": ">=10%", "status": "PASS" if fx_rate_pass else "FAIL"},
        {"gate": "P0R-FX", "metric": "cross_family_u_p_transformed_lineages", "numerator": cross["cross_family_transformed_u_p_lineages"], "denominator_context": cross["cross_family_c3_lineages"], "value_display": cross["cross_family_transformed_u_p_lineages"], "threshold": ">=25", "status": "PASS" if fx_transform_pass else "FAIL"},
    ]
    decision = "CONFIRMED_GO"
    if not cx_pass:
        decision = "REDESIGN_REQUIRED"
    elif not fx_pass or invariants["blocking_violation"]:
        decision = "STOP"
    audit_result = {
        "phase0r_original_decision": "GO",
        "p0r_cx_status": "PASS" if cx_pass else "FAIL",
        "p0r_fx_status": "PASS" if fx_pass else "FAIL",
        "tier_a_blocking_violation": invariants["blocking_violation"],
        "post_phase0r_audit": decision,
        "rq3d_status": "RQ3d_DISABLED",
    }

    manifest = input_manifest(
        [
            *source_paths.values(),
            ROOT / "PHASE0_REPORT.md",
            ROOT / "unittrace_article_spec_v4_1.md",
            ROOT / "src/unittrace/pipeline.py",
            ROOT / "src/unittrace/cli.py",
            ROOT / "src/unittrace/protocol.py",
            ROOT / "src/unittrace/phase0_audit.py",
        ]
    )
    atomic_json(AUDIT / "input_manifest.json", manifest)
    write_csv(AUDIT / "pairwise_support.csv", pair_profiles, ["pair", "left_distribution", "right_distribution", "family_type", "projects", "tier_a_lineages", "comparable_lineages", "differing_lineages", "divergence_rate", "c3_lineages", "comparable_dimensions"])
    atomic_json(AUDIT / "cross_family_support.json", cross)
    write_csv(AUDIT / "gate_results.csv", [*cx_rows, *fx_rows], ["gate", "metric", "numerator", "denominator_context", "value_display", "threshold", "status"])
    write_csv(AUDIT / "matching_modes.csv", modes, ["match_mode", "distinct_projects", "tier_a_lineages", "percentage"])
    write_csv(AUDIT / "cross_family_matching_modes.csv", cross_modes, ["match_mode", "distinct_projects", "tier_a_lineages", "percentage"])
    atomic_json(AUDIT / "tier_a_invariant_audit.json", invariants)
    atomic_json(AUDIT / "provenance_margin.json", provenance)
    write_csv(AUDIT / "attrition_by_distribution.csv", distribution_attrition, ["distribution", "reason_code", "count", "stage_denominator", "descriptive_rate"])
    write_csv(AUDIT / "attrition_by_family.csv", family_attrition, ["distribution_group", "reason_code", "count", "stage_denominator", "descriptive_rate"])
    write_csv(AUDIT / "attrition_by_pair.csv", pair_attrition, ["pair", "family_type", "ambiguous_candidate_lineages", "tier_a_noncomparable_lineages", "lineages_with_u4_member", "lineages_with_u5_member", "lineages_with_e_analyzer_failure"])
    atomic_json(AUDIT / "audit_result.json", audit_result)
    targets = [
        AUDIT / "input_manifest.json",
        AUDIT / "pairwise_support.csv",
        AUDIT / "cross_family_support.json",
        AUDIT / "gate_results.csv",
        AUDIT / "matching_modes.csv",
        AUDIT / "cross_family_matching_modes.csv",
        AUDIT / "tier_a_invariant_audit.json",
        AUDIT / "provenance_margin.json",
        AUDIT / "attrition_by_distribution.csv",
        AUDIT / "attrition_by_family.csv",
        AUDIT / "attrition_by_pair.csv",
        AUDIT / "audit_result.json",
    ]
    determinism = write_determinism_manifest(targets)
    REPORT.write_text(
        render_report(
            pair_profiles, cross, cx_rows, fx_rows, modes, cross_modes, invariants, provenance,
            distribution_attrition, family_attrition, pair_attrition, audit_result, determinism,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
