from unittrace.pipeline import _overlay_tree, layer_transformations, match_lineages, root_manifest_hash


def unit(distribution: str, path: str) -> dict[str, object]:
    return {
        "distribution": distribution,
        "binary_package_id": "example",
        "canonical_upstream_id": "https://example.org/project",
        "unit_path": path,
        "unit_basename": path.rsplit("/", 1)[-1],
        "canonical_target": path,
        "is_template_unit": False,
        "mask_state": "UNMASKED",
        "normalized_exec_lineage": "exampled",
        "unit_hash": "downstream-hash",
    }


def test_executable_lineage_matches_renamed_units(tmp_path) -> None:
    rows = match_lineages(
        [unit("debian", "usr/lib/systemd/system/example.service"), unit("fedora", "usr/lib/systemd/system/exampled.service")],
        tmp_path,
    )
    assert len(rows) == 2
    assert {row["match_status"] for row in rows} == {"MATCHED"}
    assert {row["lineage_match_mode"] for row in rows} == {"UNAMBIGUOUS_EXECUTABLE_LINEAGE"}


def test_competing_executable_candidates_are_ambiguous(tmp_path) -> None:
    rows = match_lineages(
        [
            unit("debian", "usr/lib/systemd/system/one.service"),
            unit("debian", "usr/lib/systemd/system/two.service"),
            unit("fedora", "usr/lib/systemd/system/exampled.service"),
        ],
        tmp_path,
    )
    assert {row["match_status"] for row in rows} == {"SERVICE_LINEAGE_AMBIGUOUS"}


def exact_inventory(distribution: str, source_name: str, source_version: str) -> dict[str, object]:
    return {
        "distribution": distribution,
        "source_name": source_name,
        "source_version": source_version,
        "inventory_status": "SUCCESS",
        "source_root": f"/frozen/{distribution}/{source_name}",
        "service_artifacts": [
            {
                "path": f"example-1.0/contrib/systemd/example.service",
                "sha256": "exact-upstream-hash",
            }
        ],
    }


def exact_package(distribution: str) -> dict[str, str]:
    return {
        "distribution": distribution,
        "name": "example",
        "source_name": "example-source",
        "source_version": "1.0",
    }


def test_exact_upstream_identity_precedes_executable_fallback(tmp_path) -> None:
    debian = unit("debian", "usr/lib/systemd/system/example.service")
    fedora = unit("fedora", "usr/lib/systemd/system/renamed.service")
    debian["unit_hash"] = fedora["unit_hash"] = "exact-upstream-hash"
    debian["normalized_exec_lineage"] = "debian-daemon-name"
    fedora["normalized_exec_lineage"] = "fedora-daemon-name"
    rows = match_lineages(
        [debian, fedora],
        tmp_path,
        [
            exact_inventory("debian", "example-source", "1.0"),
            exact_inventory("fedora", "example-source", "1.0"),
        ],
        [exact_package("debian"), exact_package("fedora")],
    )
    assert len(rows) == 2
    assert {row["match_status"] for row in rows} == {"MATCHED"}
    assert {row["lineage_match_mode"] for row in rows} == {"EXACT_UPSTREAM_UNIT_IDENTITY"}
    assert {row["upstream_artifact_identity"] for row in rows} == {
        "contrib/systemd/example.service"
    }


def test_competing_exact_candidates_do_not_fall_back_to_executable(tmp_path) -> None:
    debian_one = unit("debian", "usr/lib/systemd/system/example.service")
    debian_two = unit("debian", "lib/systemd/system/example.service")
    fedora = unit("fedora", "usr/lib/systemd/system/example.service")
    for row in (debian_one, debian_two, fedora):
        row["unit_hash"] = "exact-upstream-hash"
    rows = match_lineages(
        [debian_one, debian_two, fedora],
        tmp_path,
        [
            exact_inventory("debian", "example-source", "1.0"),
            exact_inventory("fedora", "example-source", "1.0"),
        ],
        [exact_package("debian"), exact_package("fedora")],
    )
    assert len(rows) == 3
    assert {row["match_status"] for row in rows} == {"SERVICE_LINEAGE_AMBIGUOUS"}
    assert {row["lineage_match_mode"] for row in rows} == {"EXACT_UPSTREAM_UNIT_IDENTITY"}


def test_p_e_transformations_classify_add_remove_and_modify(tmp_path) -> None:
    def state(layer, assessment, set_state, exposure, normalized):
        return {
            "lineage_id": "p::daemon",
            "distribution": "fedora",
            "layer": layer,
            "assessment_id": assessment,
            "analysis_status": "ANALYZABLE",
            "set_state": set_state,
            "exposure": exposure,
            "normalized_state": normalized,
        }

    states = [
        state("P", "Added", False, 1.0, "a"),
        state("E", "Added", True, 0.0, "b"),
        state("P", "Removed", True, 0.0, "a"),
        state("E", "Removed", False, 1.0, "b"),
        state("P", "Modified", True, 1.0, "a"),
        state("E", "Modified", True, 0.5, "b"),
        state("P", "Same", True, 0.0, "a"),
        state("E", "Same", True, 0.0, "a"),
    ]
    rows = layer_transformations(states, tmp_path, "P", "E")
    categories = {row["assessment_id"]: row["provenance_category"] for row in rows}
    assert categories == {
        "Added": "ADDED",
        "Modified": "MODIFIED",
        "Removed": "REMOVED",
        "Same": "INHERITED_SAME",
    }


def test_root_manifest_represents_executable_only_file(tmp_path) -> None:
    path = tmp_path / "helper"
    path.write_bytes(b"verified by enclosing package")
    path.chmod(0o111)
    first = root_manifest_hash(tmp_path)
    assert len(first) == 64
    path.chmod(0o511)
    assert root_manifest_hash(tmp_path) != first


def test_overlay_tree_replaces_existing_symlink(tmp_path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir(); destination.mkdir()
    (source / "alias.service").symlink_to("new.service")
    (destination / "alias.service").symlink_to("old.service")
    _overlay_tree(source, destination)
    assert (destination / "alias.service").readlink().as_posix() == "new.service"
