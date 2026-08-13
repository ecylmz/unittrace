from __future__ import annotations

from unittrace.phase0x import (
    calculate_phase0x_gates,
    c3x_membership,
    construct_eligible_population,
    deduplicated_cross_family_sets,
    matching_mode_distribution,
    pair_family_type,
    select_cross_family_pilot,
    u1_sensitivity,
)


def package(project: str, distribution: str, **outcomes: object) -> dict[str, object]:
    return {
        "canonical_upstream_id": project,
        "distribution": distribution,
        "name": "daemon",
        "homepage": project,
        **outcomes,
    }


def test_cross_and_derivative_family_classification() -> None:
    assert pair_family_type("debian", "ubuntu") == "DERIVATIVE_FAMILY"
    assert pair_family_type("ubuntu", "fedora") == "CROSS_FAMILY"
    assert pair_family_type("arch", "fedora") == "CROSS_FAMILY"


def test_metadata_only_eligibility_excludes_derivative_only_and_ignores_outcomes() -> None:
    rows = [
        package("https://example.org/derivative", "debian", exposure=0.1),
        package("https://example.org/derivative", "ubuntu", exposure=9.9),
        package("https://example.org/cross", "debian", exposure=0.0, semantic_category="DIFFERENT"),
        package("https://example.org/cross", "fedora", exposure=10.0, semantic_category="UNCHANGED"),
    ]
    eligible, _ = construct_eligible_population(rows, "phase0x-test")
    assert {row["canonical_upstream_id"] for row in eligible} == {"https://example.org/cross"}
    changed = [{**row, "exposure": -100, "semantic_category": "OTHER"} for row in rows]
    eligible_changed, _ = construct_eligible_population(changed, "phase0x-test")
    assert eligible == eligible_changed


def test_phase0x_selection_is_stable_and_bounded() -> None:
    rows = [package(f"https://example.org/{index}", distribution) for index in range(70) for distribution in ("debian", "fedora")]
    eligible, _ = construct_eligible_population(rows, "unittrace:v4.2:test")
    first = select_cross_family_pilot(eligible, 60)
    second = select_cross_family_pilot(list(reversed(eligible)), 60)
    second.sort(key=lambda row: (row["selection_hash"], row["canonical_upstream_id"]))
    assert len(first) == 60
    assert first == second


def test_c1x_union_is_deduplicated_and_derivative_pair_cannot_leak() -> None:
    pair_sets = {
        ("debian", "fedora"): {"tier_a": {"a", "shared"}, "comparable": {"a", "shared"}, "differing": {"a"}},
        ("debian", "arch"): {"tier_a": {"shared"}, "comparable": {"shared"}, "differing": set()},
        ("ubuntu", "fedora"): {"tier_a": {"u"}, "comparable": {"u"}, "differing": {"u"}},
        ("ubuntu", "arch"): {"tier_a": set(), "comparable": set(), "differing": set()},
        ("fedora", "arch"): {"tier_a": {"fa"}, "comparable": {"fa"}, "differing": set()},
        ("debian", "ubuntu"): {"tier_a": {"derivative-only"}, "comparable": {"derivative-only"}, "differing": {"derivative-only"}},
    }
    union = deduplicated_cross_family_sets(pair_sets)
    assert union["tier_a"] == {"a", "shared", "u", "fa"}
    assert "derivative-only" not in union["tier_a"]


def test_c3x_is_intersection_of_c1x_and_resolved_provenance() -> None:
    assert c3x_membership({"cross-resolved", "cross-unresolved"}, {"cross-resolved", "derivative-resolved"}) == {"cross-resolved"}


def passing_metrics() -> dict[str, object]:
    return {
        "repository_integrity": True,
        "artifact_rate": 0.95,
        "analyzable_rate": 0.90,
        "fixtures_pass": True,
        "cross_family_projects": 30,
        "cross_family_tier_a_lineages": 40,
        "c3x_projects": 30,
        "provenance_retention": 0.50,
        "cross_family_differing_lineages": 4,
        "cross_family_divergence_rate": 0.10,
        "cross_family_transformed_u_p_lineages": 4,
        "artifacts_ok": 95,
        "artifacts_total": 100,
        "states_analyzable": 90,
        "states_total": 100,
        "selected_pilot_size": 60,
        "tier_a_lineages": 40,
        "four_way_projects": 0,
        "four_way_lineages": 0,
        "cross_family_projects": 30,
        "cross_family_c3_candidate_lineages": 40,
        "usable_cross_family_provenance_lineages": 20,
        "cross_family_comparable_lineages": 40,
        "tier_a_blocking_violation": False,
        "determinism_pass": True,
    }


def thresholds() -> dict[str, object]:
    return {
        "artifact_rate": 0.95,
        "analyzable_rate": 0.90,
        "cross_family_projects": 30,
        "cross_family_tier_a_lineages": 40,
        "c3x_projects": 30,
        "provenance_retention": 0.50,
        "differing_lineages": 25,
        "divergence_rate": 0.10,
        "transformed_lineages": 25,
    }


def test_phase0x_gate_boundaries_and_nonblocking_tetrad() -> None:
    rows, decision = calculate_phase0x_gates(passing_metrics(), thresholds())
    assert decision == "CONFIRMED_GO"
    assert next(row for row in rows if row["gate"] == "P0R-D-X")["status"] == "DESCRIPTIVE"


def test_p0r_fx_calculates_all_three_alternatives() -> None:
    rows, decision = calculate_phase0x_gates(passing_metrics(), thresholds())
    fx = [row for row in rows if row["gate"] == "P0R-FX"]
    assert len(fx) == 3
    assert [row["status"] for row in fx] == ["FAIL", "PASS", "FAIL"]
    assert decision == "CONFIRMED_GO"


def test_p0r_cx_and_ex_are_blocking_stop_conditions() -> None:
    metrics = passing_metrics()
    metrics["cross_family_projects"] = 29
    _, decision = calculate_phase0x_gates(metrics, thresholds())
    assert decision == "STOP"
    metrics = passing_metrics()
    metrics["c3x_projects"] = 29
    _, decision = calculate_phase0x_gates(metrics, thresholds())
    assert decision == "STOP"


def test_u1_sensitivity_and_matching_modes_report_zeros() -> None:
    lineage_index = {
        "one": [{"canonical_upstream_id": "p1", "lineage_match_mode": "UNAMBIGUOUS_EXECUTABLE_LINEAGE"}],
        "two": [{"canonical_upstream_id": "p2", "lineage_match_mode": "UNAMBIGUOUS_EXECUTABLE_LINEAGE"}],
    }
    upstream = [
        {"lineage_id": "one", "distribution": "debian", "canonical_upstream_id": "p1", "u_artifact_class": "U1_TEMPLATE_VALUE_ONLY"},
        {"lineage_id": "two", "distribution": "fedora", "canonical_upstream_id": "p2", "u_artifact_class": "U0_STATIC"},
    ]
    states = [
        {"lineage_id": "one", "distribution": "debian", "layer": "U", "dimension_provenance_status": "PRESENT_RESOLVED"},
        {"lineage_id": "two", "distribution": "fedora", "layer": "U", "dimension_provenance_status": "ABSENT_RESOLVED"},
    ]
    sensitivity = u1_sensitivity({"one", "two"}, lineage_index, upstream, states)
    assert sensitivity == {"c3x_projects_exclusively_dependent_on_U1": 1, "c3x_projects_if_U1_only_projects_excluded": 1}
    modes = matching_mode_distribution(lineage_index, {"one", "two"}, "C1X")
    assert len(modes) == 4
    assert next(row for row in modes if row["match_mode"] == "EXACT_UPSTREAM_UNIT_IDENTITY")["lineages"] == 0


def test_rq3d_is_frozen_disabled() -> None:
    import json
    from pathlib import Path

    config = json.loads(Path("config/phase0x.json").read_text())
    assert config["rq3d_status"] == "RQ3d_DISABLED"
