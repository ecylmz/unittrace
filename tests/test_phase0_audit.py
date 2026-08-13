from unittrace.phase0_audit import compute_pair_profiles, effective_state_index, matched_lineage_index


def lineage(distribution: str) -> dict[str, str]:
    return {
        "lineage_id": "https://example.org/project::daemon",
        "canonical_upstream_id": "https://example.org/project",
        "distribution": distribution,
        "match_tier": "A",
        "match_status": "MATCHED",
    }


def state(distribution: str, value: str) -> dict[str, str]:
    return {
        "lineage_id": "https://example.org/project::daemon",
        "distribution": distribution,
        "layer": "E",
        "assessment_id": "PrivateTmp",
        "normalized_state": value,
        "analysis_status": "ANALYZABLE",
    }


def test_pair_profile_uses_common_effective_dimensions() -> None:
    lineages = matched_lineage_index([lineage("debian"), lineage("fedora")])
    effective = effective_state_index([state("debian", "off"), state("fedora", "on")])
    profiles, _ = compute_pair_profiles(lineages, effective, {"https://example.org/project::daemon"})
    debian_fedora = next(row for row in profiles if row["pair"] == "Debian ↔ Fedora")
    assert debian_fedora["projects"] == 1
    assert debian_fedora["tier_a_lineages"] == 1
    assert debian_fedora["comparable_lineages"] == 1
    assert debian_fedora["differing_lineages"] == 1
    assert debian_fedora["divergence_rate"] == 1.0
    assert debian_fedora["c3_lineages"] == 1
