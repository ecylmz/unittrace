from unittrace.gates import calculate_gates, scientific_decision


def passing_metrics() -> dict[str, int | bool]:
    return {
        "all_four_enumerators": True,
        "artifacts_ok": 190,
        "artifacts_total": 200,
        "states_analyzable": 180,
        "states_total": 200,
        "fixtures_pass": True,
        "tier_a_projects": 30,
        "tier_a_lineages": 40,
        "tier_a_candidate_lineages": 45,
        "four_way_projects": 20,
        "c3_projects": 30,
        "c3_usable_lineages": 20,
        "c3_candidate_lineages": 40,
        "rq2_different_lineages": 25,
        "rq2_comparable_lineages": 40,
        "up_transformed_lineages": 0,
        "ancestor_projects": 20,
        "c2d_lineages": 25,
        "ubuntu_projects": 30,
        "ubuntu_lineages": 40,
    }


def test_gate_boundaries_and_decision() -> None:
    results = calculate_gates(passing_metrics())
    assert all(row.status == "PASS" for row in results)
    assert scientific_decision(results) == ("GO", "RQ3d_ENABLED")


def test_nonblocking_ancestry() -> None:
    metrics = passing_metrics()
    metrics["c2d_lineages"] = 24
    results = calculate_gates(metrics)
    assert scientific_decision(results) == ("GO", "RQ3d_DISABLED")
