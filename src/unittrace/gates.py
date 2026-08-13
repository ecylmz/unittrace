from __future__ import annotations

from .model import GateResult, GateStatus


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def calculate_gates(metrics: dict[str, int | bool]) -> list[GateResult]:
    artifact_rate = ratio(int(metrics["artifacts_ok"]), int(metrics["artifacts_total"]))
    analyzer_rate = ratio(int(metrics["states_analyzable"]), int(metrics["states_total"]))
    usable_rate = ratio(int(metrics["c3_usable_lineages"]), int(metrics["c3_candidate_lineages"]))
    difference_rate = ratio(int(metrics["rq2_different_lineages"]), int(metrics["rq2_comparable_lineages"]))
    results: list[GateResult] = []
    a_pass = bool(metrics["all_four_enumerators"]) and artifact_rate is not None and artifact_rate >= 0.95
    results.append(GateResult("P0R-A", "repository_enumerators_root_builders", 4 if metrics["all_four_enumerators"] else 0, 4, 1.0 if metrics["all_four_enumerators"] else 0.0, "4/4", GateStatus.PASS if a_pass else GateStatus.FAIL, "artifacts/normalized/distribution_snapshots.csv"))
    results.append(GateResult("P0R-A", "pilot_artifact_reproducibility", int(metrics["artifacts_ok"]), int(metrics["artifacts_total"]), artifact_rate, ">=0.95", GateStatus.PASS if a_pass else GateStatus.FAIL, "artifacts/raw/package_artifact_manifest.json"))
    b_pass = analyzer_rate is not None and analyzer_rate >= 0.90 and bool(metrics["fixtures_pass"])
    results.append(GateResult("P0R-B", "analyzable_or_classified_states", int(metrics["states_analyzable"]), int(metrics["states_total"]), analyzer_rate, ">=0.90", GateStatus.PASS if b_pass else GateStatus.FAIL, "artifacts/normalized/policy_states.csv"))
    results.append(GateResult("P0R-B", "mandatory_semantic_fixtures", 6 if metrics["fixtures_pass"] else 0, 6, 1.0 if metrics["fixtures_pass"] else 0.0, "6/6", GateStatus.PASS if b_pass else GateStatus.FAIL, "artifacts/normalized/semantic_fixture_results.json"))
    c_pass = int(metrics["tier_a_projects"]) >= 30 and int(metrics["tier_a_lineages"]) >= 40
    results.append(GateResult("P0R-C", "strict_tier_a_projects", int(metrics["tier_a_projects"]), 60, ratio(int(metrics["tier_a_projects"]), 60), ">=30 projects", GateStatus.PASS if c_pass else GateStatus.FAIL, "artifacts/normalized/service_lineages.csv"))
    results.append(GateResult("P0R-C", "strict_tier_a_lineages", int(metrics["tier_a_lineages"]), int(metrics["tier_a_candidate_lineages"]), ratio(int(metrics["tier_a_lineages"]), int(metrics["tier_a_candidate_lineages"])), ">=40 lineages", GateStatus.PASS if c_pass else GateStatus.FAIL, "artifacts/normalized/service_lineages.csv"))
    d_pass = int(metrics["four_way_projects"]) >= 20
    results.append(GateResult("P0R-D", "complete_four_way_support", int(metrics["four_way_projects"]), int(metrics["tier_a_projects"]), ratio(int(metrics["four_way_projects"]), int(metrics["tier_a_projects"])), ">=20 projects preferred", GateStatus.PASS if d_pass else GateStatus.FAIL, "artifacts/normalized/service_lineages.csv"))
    e_pass = int(metrics["c3_projects"]) >= 30 and usable_rate is not None and usable_rate >= 0.50
    results.append(GateResult("P0R-E", "distinct_c3_projects", int(metrics["c3_projects"]), int(metrics["tier_a_projects"]), ratio(int(metrics["c3_projects"]), int(metrics["tier_a_projects"])), ">=30 projects", GateStatus.PASS if e_pass else GateStatus.FAIL, "artifacts/normalized/upstream_artifacts.csv"))
    results.append(GateResult("P0R-E", "usable_dimension_resolved_lineages", int(metrics["c3_usable_lineages"]), int(metrics["c3_candidate_lineages"]), usable_rate, ">=0.50", GateStatus.PASS if e_pass else GateStatus.FAIL, "artifacts/normalized/policy_states.csv"))
    f_pass = int(metrics["rq2_different_lineages"]) >= 25 or (difference_rate is not None and difference_rate >= 0.10) or int(metrics["up_transformed_lineages"]) >= 25
    results.append(GateResult("P0R-F", "empirical_variation", int(metrics["rq2_different_lineages"]), int(metrics["rq2_comparable_lineages"]), difference_rate, ">=25 RQ2 or >=0.10 RQ2 rate or >=25 U->P", GateStatus.PASS if f_pass else GateStatus.FAIL, "artifacts/normalized/transformations.csv"))
    g_pass = int(metrics["ancestor_projects"]) >= 20 and int(metrics["c2d_lineages"]) >= 25
    results.append(GateResult("P0R-G", "exact_ancestor_projects", int(metrics["ancestor_projects"]), int(metrics["ubuntu_projects"]), ratio(int(metrics["ancestor_projects"]), int(metrics["ubuntu_projects"])), ">=20 projects", GateStatus.PASS if g_pass else GateStatus.FAIL, "artifacts/normalized/distribution_derivation.csv"))
    results.append(GateResult("P0R-G", "c2d_comparable_lineages", int(metrics["c2d_lineages"]), int(metrics["ubuntu_lineages"]), ratio(int(metrics["c2d_lineages"]), int(metrics["ubuntu_lineages"])), ">=25 lineages", GateStatus.PASS if g_pass else GateStatus.FAIL, "artifacts/normalized/distribution_derivation.csv"))
    return results


def scientific_decision(results: list[GateResult], blocking_determinism_problem: bool = False) -> tuple[str, str]:
    statuses = {row.gate_id: row.status for row in results}
    rq3d = "RQ3d_ENABLED" if statuses["P0R-G"] == GateStatus.PASS else "RQ3d_DISABLED"
    if not blocking_determinism_problem and all(statuses[gate] == GateStatus.PASS for gate in ("P0R-A", "P0R-B", "P0R-C", "P0R-E", "P0R-F")):
        return "GO", rq3d
    if statuses["P0R-A"] == GateStatus.UNRESOLVED:
        return "REDESIGN", rq3d
    if statuses["P0R-E"] == GateStatus.FAIL or statuses["P0R-F"] == GateStatus.FAIL or statuses["P0R-C"] == GateStatus.FAIL:
        return "STOP", rq3d
    return "REDESIGN", rq3d
