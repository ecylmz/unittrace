from __future__ import annotations

import csv
import json
import os
import shutil
import stat
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import rpmfile

from .io import atomic_json, download, sha256_file, write_csv
from .protocol import is_system_service_path, normalized_exec_lineage
from .systemd import evaluate_unit, make_minimal_root, parse_service_assignments


def _safe_target(root: Path, member_name: str) -> Path:
    target = root / member_name.lstrip("./")
    if root.resolve() not in (target.parent.resolve(), *target.parent.resolve().parents):
        raise ValueError(f"archive path escapes root: {member_name}")
    return target


def extract_package(artifact: Path, distribution: str, root: Path) -> None:
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    if distribution in {"debian", "ubuntu"}:
        subprocess.run(["dpkg-deb", "-x", str(artifact), str(root)], check=True, capture_output=True)
    elif distribution == "arch":
        subprocess.run(["tar", "--zstd", "-xf", str(artifact), "-C", str(root)], check=True, capture_output=True)
    elif distribution == "fedora":
        with rpmfile.open(artifact) as archive:
            for member in archive.getmembers():
                name = member.name.lstrip("./")
                if not (name.startswith(("usr/lib/systemd/", "etc/systemd/", "lib/systemd/")) or name == "usr/lib/os-release"):
                    continue
                target = _safe_target(root, name)
                target.parent.mkdir(parents=True, exist_ok=True)
                mode = getattr(member, "mode", 0)
                if bool(getattr(member, "isdir", False)):
                    target.mkdir(exist_ok=True)
                elif bool(getattr(member, "issymlink", False)):
                    stream = archive.extractfile(member)
                    linkname = stream.read().decode() if stream is not None else ""
                    target.unlink(missing_ok=True)
                    target.symlink_to(linkname)
                else:
                    stream = archive.extractfile(member)
                    if stream is not None:
                        target.write_bytes(stream.read())
                        target.chmod(mode if mode else 0o644)
    else:
        raise ValueError(f"unsupported distribution: {distribution}")
    make_minimal_root(root)


def _unit_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for prefix in ("usr/lib/systemd/system", "lib/systemd/system", "etc/systemd/system"):
        directory = root / prefix
        if directory.exists():
            files.extend(path for path in directory.rglob("*.service") if path.is_file() or path.is_symlink())
    return sorted(set(files))


def _relative(root: Path, path: Path) -> str:
    return str(path.relative_to(root))


def extract_pilot_packages(records: list[dict[str, Any]], artifacts: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    manifest: list[dict[str, Any]] = []
    units: list[dict[str, Any]] = []
    for record in records:
        output = dict(record)
        if record.get("fetch_status") != "SUCCESS":
            manifest.append(output)
            continue
        artifact = Path(record["local_path"])
        root = artifacts / "roots/packages" / record["distribution"] / f"{record['name']}-{record['version'].replace('/', '_')}"
        complete = root / ".unittrace-extracted.json"
        try:
            if not complete.exists() or json.loads(complete.read_text()).get("artifact_sha256") != record["observed_sha256"]:
                extract_package(artifact, record["distribution"], root)
                atomic_json(complete, {"artifact_sha256": record["observed_sha256"]})
            found = _unit_files(root)
            for path in found:
                relative = _relative(root, path)
                is_mask = path.is_symlink() and os.path.realpath(path) == "/dev/null"
                canonical_target = relative
                if path.is_symlink() and not is_mask:
                    link = os.readlink(path)
                    canonical_target = str((path.parent / link).resolve(strict=False).relative_to(root.resolve())) if not os.path.isabs(link) else link.lstrip("/")
                text = "" if path.is_symlink() else path.read_text(encoding="utf-8", errors="replace")
                assignments = parse_service_assignments(text)
                exec_start = assignments.get("ExecStart", [""])[-1] if assignments.get("ExecStart") else ""
                units.append({
                    "distribution": record["distribution"],
                    "binary_package_id": record["name"],
                    "package_version": record["version"],
                    "canonical_upstream_id": record["canonical_upstream_id"],
                    "unit_path": relative,
                    "unit_basename": path.name,
                    "canonical_target": canonical_target,
                    "unit_hash": sha256_file(path) if not path.is_symlink() else "",
                    "is_template_unit": path.name.endswith("@.service"),
                    "package_owned": True,
                    "mask_state": "MASKED_EFFECTIVE_UNIT" if is_mask else "UNMASKED",
                    "exec_start": exec_start,
                    "normalized_exec_lineage": normalized_exec_lineage(exec_start) or "",
                    "root": str(root),
                })
            output["extract_status"] = "SUCCESS"
            output["root"] = str(root)
            output["root_manifest_hash"] = root_manifest_hash(root)
            output["service_count"] = len(found)
        except Exception as error:
            output["extract_status"] = "FAILURE"
            output["failure"] = str(error)
        manifest.append(output)
        atomic_json(artifacts / "checkpoints/package_extract.json", manifest)
    atomic_json(artifacts / "raw/package_artifact_manifest.json", manifest)
    write_csv(artifacts / "normalized/service_units.csv", units, ["distribution", "binary_package_id", "package_version", "canonical_upstream_id", "unit_path", "unit_basename", "canonical_target", "unit_hash", "is_template_unit", "package_owned", "mask_state", "exec_start", "normalized_exec_lineage", "root"])
    return manifest, units


def root_manifest_hash(root: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.name != ".unittrace-extracted.json"):
        relative = str(path.relative_to(root))
        digest.update(relative.encode() + b"\0")
        if path.is_symlink():
            digest.update(b"L" + os.readlink(path).encode())
        elif path.is_file():
            metadata = path.stat()
            digest.update(b"F" + str(stat.S_IMODE(metadata.st_mode)).encode() + b":" + str(metadata.st_size).encode() + b":")
            try:
                digest.update(bytes.fromhex(sha256_file(path)))
            except PermissionError:
                # Some verified package archives intentionally ship executable-only
                # helpers.  They are not systemd inputs, but their path/mode/size
                # must remain represented in the deterministic root manifest.
                digest.update(b"UNREADABLE_VERIFIED_PACKAGE_MEMBER")
        elif path.is_dir():
            digest.update(b"D")
    return digest.hexdigest()


def _unit_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return row["distribution"], row["binary_package_id"], row["unit_path"]


def _boolean(value: Any) -> bool:
    return value if isinstance(value, bool) else str(value).casefold() == "true"


def _normalized_upstream_service_path(inventory: dict[str, Any], artifact: dict[str, Any]) -> str:
    """Normalize an exact-revision source path without reducing it to a basename.

    Pristine archives normally add one version-bearing root directory.  It is
    removed only when every service artifact in that inventory shares it.
    Terminal ``.service.in`` is normalized to the installed ``.service`` form.
    """
    service_artifacts = inventory.get("service_artifacts", [])
    first_components = {
        Path(item["path"]).parts[0]
        for item in service_artifacts
        if Path(item["path"]).parts
    }
    parts = Path(artifact["path"]).parts
    if len(first_components) == 1 and len(parts) > 1:
        parts = parts[1:]
    normalized = "/".join(parts)
    if normalized.endswith(".service.in"):
        normalized = normalized.removesuffix(".in")
    return normalized


def _exact_upstream_identities(
    units: list[dict[str, Any]],
    inventories: list[dict[str, Any]],
    packages: list[dict[str, Any]],
) -> dict[tuple[str, str, str], dict[str, str]]:
    inventory_index = {
        (row["distribution"], row["source_name"], row["source_version"]): row
        for row in inventories
    }
    package_index = {(row["distribution"], row["name"]): row for row in packages}
    identities: dict[tuple[str, str, str], dict[str, str]] = {}
    for unit in units:
        package = package_index.get((unit["distribution"], unit["binary_package_id"]))
        if package is None:
            continue
        source_version = package["source_version"]
        if unit["distribution"] in {"debian", "ubuntu"}:
            source_version = source_version.split(":", 1)[-1]
        inventory = inventory_index.get(
            (unit["distribution"], package["source_name"], source_version)
        )
        if inventory is None or inventory.get("inventory_status") != "SUCCESS":
            continue
        exact = [
            item
            for item in inventory.get("service_artifacts", [])
            if item.get("sha256") and item["sha256"] == unit.get("unit_hash")
        ]
        if len(exact) != 1:
            continue
        artifact = exact[0]
        identities[_unit_key(unit)] = {
            "identity": _normalized_upstream_service_path(inventory, artifact),
            "evidence_path": str(Path(inventory["source_root"]) / artifact["path"]),
            "source_revision": package["source_version"],
            "artifact_hash": artifact["sha256"],
        }
    return identities


def _lineage_row(
    unit: dict[str, Any],
    *,
    lineage_id: str,
    mode: str,
    status: str,
    candidate_count: int,
    distribution_count: int,
    evidence: dict[str, str] | None = None,
) -> dict[str, Any]:
    exact = evidence or {}
    return {
        "lineage_id": lineage_id,
        "canonical_upstream_id": unit["canonical_upstream_id"],
        "distribution": unit["distribution"],
        "binary_package_id": unit["binary_package_id"],
        "unit_path": unit["unit_path"],
        "unit_basename": unit["unit_basename"],
        "match_tier": "A" if status == "MATCHED" else "UNRESOLVED",
        "lineage_match_mode": mode,
        "match_status": status,
        "match_evidence_uri_or_path": exact.get("evidence_path", unit["unit_path"]),
        "normalized_exec_lineage": unit.get("normalized_exec_lineage", ""),
        "candidate_count": candidate_count,
        "distribution_count": distribution_count,
        "upstream_source_revision": exact.get("source_revision", ""),
        "upstream_artifact_identity": exact.get("identity", ""),
        "upstream_artifact_hash": exact.get("artifact_hash", ""),
        "ambiguity_count_before_acceptance": candidate_count,
    }


def match_lineages(
    units: list[dict[str, Any]],
    artifacts: Path,
    inventories: list[dict[str, Any]] | None = None,
    packages: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Apply REV-A01 exact-artifact matching, then strict executable fallback.

    The optional provenance inputs contain source/package metadata only.  Policy
    states and outcomes are intentionally absent from this interface.
    """
    canonical_units = [
        row
        for row in units
        if row["mask_state"] == "UNMASKED"
        and row["canonical_target"] == row["unit_path"]
        and not _boolean(row["is_template_unit"])
    ]
    exact = _exact_upstream_identities(canonical_units, inventories or [], packages or [])
    exact_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for unit in canonical_units:
        evidence = exact.get(_unit_key(unit))
        if evidence:
            exact_groups[(unit["canonical_upstream_id"], evidence["identity"])].append(unit)

    lineages: list[dict[str, Any]] = []
    reserved: set[tuple[str, str, str]] = set()
    blocked_by_stronger: set[tuple[str, str, str]] = set()
    accepted_exact_groups = 0
    ambiguous_exact_groups = 0
    for (upstream, identity), observations in sorted(exact_groups.items()):
        distributions = {row["distribution"] for row in observations}
        if len(distributions) < 2:
            continue
        counts = Counter(row["distribution"] for row in observations)
        lineage_id = f"{upstream}::upstream-unit::{identity}"
        if any(value > 1 for value in counts.values()):
            ambiguous_exact_groups += 1
            for unit in observations:
                key = _unit_key(unit)
                blocked_by_stronger.add(key)
                lineages.append(
                    _lineage_row(
                        unit,
                        lineage_id=lineage_id,
                        mode="EXACT_UPSTREAM_UNIT_IDENTITY",
                        status="SERVICE_LINEAGE_AMBIGUOUS",
                        candidate_count=counts[unit["distribution"]],
                        distribution_count=len(distributions),
                        evidence=exact[key],
                    )
                )
            continue
        accepted_exact_groups += 1
        for unit in observations:
            key = _unit_key(unit)
            reserved.add(key)
            lineages.append(
                _lineage_row(
                    unit,
                    lineage_id=lineage_id,
                    mode="EXACT_UPSTREAM_UNIT_IDENTITY",
                    status="MATCHED",
                    candidate_count=1,
                    distribution_count=len(distributions),
                    evidence=exact[key],
                )
            )

    executable_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for unit in canonical_units:
        key = _unit_key(unit)
        if key in reserved or key in blocked_by_stronger:
            continue
        if unit["normalized_exec_lineage"]:
            executable_groups[(unit["canonical_upstream_id"], unit["normalized_exec_lineage"])].append(unit)
    for (upstream, executable), observations in sorted(executable_groups.items()):
        distributions = {row["distribution"] for row in observations}
        if len(distributions) < 2:
            continue
        counts = Counter(row["distribution"] for row in observations)
        status = "SERVICE_LINEAGE_AMBIGUOUS" if any(value > 1 for value in counts.values()) else "MATCHED"
        for unit in observations:
            lineages.append(
                _lineage_row(
                    unit,
                    lineage_id=f"{upstream}::{executable}",
                    mode="UNAMBIGUOUS_EXECUTABLE_LINEAGE",
                    status=status,
                    candidate_count=counts[unit["distribution"]],
                    distribution_count=len(distributions),
                )
            )

    lineages.sort(
        key=lambda row: (
            row["lineage_id"],
            row["distribution"],
            row["binary_package_id"],
            row["unit_path"],
        )
    )
    fields = [
        "lineage_id",
        "canonical_upstream_id",
        "distribution",
        "binary_package_id",
        "unit_path",
        "unit_basename",
        "match_tier",
        "lineage_match_mode",
        "match_status",
        "match_evidence_uri_or_path",
        "normalized_exec_lineage",
        "candidate_count",
        "distribution_count",
        "upstream_source_revision",
        "upstream_artifact_identity",
        "upstream_artifact_hash",
        "ambiguity_count_before_acceptance",
    ]
    write_csv(artifacts / "normalized/service_lineages.csv", lineages, fields)
    atomic_json(
        artifacts / "normalized/matching_mode_availability.json",
        {
            "amendment": "REV-A01",
            "outcome_fields_consumed": [],
            "exact_identity_candidates": len(exact),
            "accepted_exact_groups": accepted_exact_groups,
            "ambiguous_exact_groups": ambiguous_exact_groups,
            "modes": {
                "EXACT_UPSTREAM_UNIT_IDENTITY": "OPERATIONALIZED_REV_A01",
                "PACKAGING_INSTALL_MAPPING": "NOT_OPERATIONALIZED_FROZEN_EVIDENCE_MODEL_UNAVAILABLE",
                "DETERMINISTIC_GENERATION_MAPPING": "NOT_OPERATIONALIZED_FROZEN_EVIDENCE_MODEL_UNAVAILABLE",
                "UNAMBIGUOUS_EXECUTABLE_LINEAGE": "OPERATIONALIZED_V4_2_FALLBACK",
            },
        },
    )
    return lineages


def analyze_states(lineages: list[dict[str, Any]], units: list[dict[str, Any]], evaluator: Path, policy: Path, artifacts: Path) -> list[dict[str, Any]]:
    unit_index = {(row["distribution"], row["binary_package_id"], row["unit_path"]): row for row in units}
    states: list[dict[str, Any]] = []
    schema: dict[str, dict[str, Any]] = {}
    effective_roots: dict[str, dict[str, Any]] = {}
    for lineage in lineages:
        if lineage["match_status"] != "MATCHED":
            continue
        unit = unit_index[(lineage["distribution"], lineage["binary_package_id"], lineage["unit_path"])]
        for layer in ("P", "E"):
            evaluation_root = Path(unit["root"]) if layer == "P" else build_effective_root(unit, artifacts)
            if layer == "E" and str(evaluation_root) not in effective_roots:
                marker = json.loads((evaluation_root / ".unittrace-effective.json").read_text())
                effective_roots[str(evaluation_root)] = {"distribution": unit["distribution"], "binary_package_id": unit["binary_package_id"], "package_version": unit["package_version"], "root": str(evaluation_root), "root_manifest_hash": root_manifest_hash(evaluation_root), **marker}
            status, rows, detail = evaluate_unit(evaluator, policy, evaluation_root, unit["unit_basename"])
            raw_path = artifacts / "raw/evaluator" / lineage["distribution"] / layer / (lineage["lineage_id"].replace("/", "_").replace(":", "_") + ".json")
            atomic_json(raw_path, {"status": status, "detail": detail, "rows": rows})
            if status != "ANALYZABLE":
                states.append({"lineage_id": lineage["lineage_id"], "distribution": lineage["distribution"], "layer": layer, "assessment_id": "", "normalized_state": "", "set_state": "", "description_normalized": detail, "exposure": "", "analysis_status": status, "dimension_provenance_status": "NOT_APPLICABLE", "resolution_evidence": str(raw_path)})
                continue
            for assessment in rows:
                assessment_id = assessment.get("json_field") or assessment.get("name")
                schema[assessment_id] = {key: assessment.get(key) for key in ("json_field", "name")}
                states.append({
                    "lineage_id": lineage["lineage_id"], "distribution": lineage["distribution"], "layer": layer,
                    "assessment_id": assessment_id, "normalized_state": json.dumps({"set": assessment.get("set"), "exposure": assessment.get("exposure"), "description": assessment.get("description")}, sort_keys=True),
                    "set_state": assessment.get("set"), "description_normalized": assessment.get("description"), "exposure": assessment.get("exposure"),
                    "analysis_status": status, "dimension_provenance_status": "NOT_APPLICABLE", "resolution_evidence": str(raw_path),
                })
    atomic_json(artifacts / "security_assessment_schema.json", {"assessment_count": len(schema), "assessments": [schema[key] for key in sorted(schema)]})
    atomic_json(artifacts / "raw/effective_root_manifest.json", [effective_roots[key] for key in sorted(effective_roots)])
    write_csv(artifacts / "normalized/policy_states.csv", states, ["lineage_id", "distribution", "layer", "assessment_id", "normalized_state", "set_state", "description_normalized", "exposure", "analysis_status", "dimension_provenance_status", "resolution_evidence"])
    return states


def prepare_distribution_bases(repository_packages: list[dict[str, Any]], artifacts: Path) -> dict[str, Path]:
    bases: dict[str, Path] = {}
    records: list[dict[str, Any]] = []
    for distribution in ("debian", "ubuntu", "fedora", "arch"):
        candidates = [row for row in repository_packages if row["distribution"] == distribution and row["name"] == "systemd"]
        if len(candidates) != 1:
            raise RuntimeError(f"{distribution}: expected one frozen systemd package, found {len(candidates)}")
        package = candidates[0]
        extension = ".deb" if distribution in {"debian", "ubuntu"} else (".rpm" if distribution == "fedora" else ".pkg.tar.zst")
        artifact = artifacts / "raw/packages/base" / distribution / f"systemd-{package['version']}{extension}"
        fetched = download(package["artifact_url"], artifact, package["artifact_sha256"] or None)
        root = artifacts / "roots/base" / distribution
        marker = root / ".unittrace-base.json"
        if not marker.exists() or json.loads(marker.read_text()).get("artifact_sha256") != fetched["sha256"]:
            extract_package(artifact, distribution, root)
            atomic_json(marker, {"artifact_sha256": fetched["sha256"]})
        bases[distribution] = root
        records.append({**package, "local_path": str(artifact), "observed_sha256": fetched["sha256"], "root": str(root), "root_manifest_hash": root_manifest_hash(root)})
    atomic_json(artifacts / "raw/base_package_manifest.json", records)
    return bases


def build_effective_root(unit: dict[str, Any], artifacts: Path) -> Path:
    distribution = unit["distribution"]
    package_root = Path(unit["root"])
    root = artifacts / "roots/effective" / distribution / f"{unit['binary_package_id']}-{unit['package_version'].replace('/', '_')}"
    marker = root / ".unittrace-effective.json"
    package_hash = root_manifest_hash(package_root)
    base = artifacts / "roots/base" / distribution
    base_hash = root_manifest_hash(base)
    expected = {"package_root_hash": package_hash, "base_root_hash": base_hash}
    if marker.exists() and json.loads(marker.read_text()) == expected:
        return root
    if root.exists():
        shutil.rmtree(root)
    make_minimal_root(root)
    for source_root in (base, package_root):
        for relative in ("usr/lib/systemd", "lib/systemd", "etc/systemd"):
            source = source_root / relative
            if source.exists():
                _overlay_tree(source, root / relative)
    atomic_json(marker, expected)
    return root


def _overlay_tree(source: Path, destination: Path) -> None:
    """Apply a package tree over a base tree with deterministic replacement.

    ``shutil.copytree(..., dirs_exist_ok=True)`` does not replace existing
    symlinks.  Package overlay semantics require the later tree to win for every
    path, including aliases and masks.
    """
    destination.mkdir(parents=True, exist_ok=True)
    for item in sorted(source.rglob("*"), key=lambda path: (len(path.relative_to(source).parts), str(path.relative_to(source)))):
        target = destination / item.relative_to(source)
        if item.is_dir() and not item.is_symlink():
            if target.is_symlink() or (target.exists() and not target.is_dir()):
                target.unlink()
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink() or target.exists():
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            else:
                target.unlink()
        if item.is_symlink():
            target.symlink_to(os.readlink(item))
        elif item.is_file():
            shutil.copy2(item, target)


def cross_distribution_transformations(states: list[dict[str, Any]], artifacts: Path) -> list[dict[str, Any]]:
    effective = [row for row in states if row["layer"] == "E" and row["analysis_status"] == "ANALYZABLE"]
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in effective:
        by_key[(row["lineage_id"], row["assessment_id"])].append(row)
    transformations: list[dict[str, Any]] = []
    for (lineage_id, assessment_id), observations in by_key.items():
        observations.sort(key=lambda row: row["distribution"])
        for left_index, left in enumerate(observations):
            for right in observations[left_index + 1:]:
                changed = left["normalized_state"] != right["normalized_state"]
                transformations.append({
                    "lineage_id": lineage_id, "distribution": f"{left['distribution']}--{right['distribution']}",
                    "transition": "E_CROSS_DISTRIBUTION", "assessment_id": assessment_id,
                    "semantic_category": "DIFFERENT" if changed else "UNCHANGED", "provenance_category": "NOT_APPLICABLE",
                    "exposure_delta": "", "source_resolved": True, "destination_resolved": True,
                })
    write_csv(artifacts / "normalized/transformations.csv", transformations, ["lineage_id", "distribution", "transition", "assessment_id", "semantic_category", "provenance_category", "exposure_delta", "source_resolved", "destination_resolved"])
    return transformations


def layer_transformations(
    states: list[dict[str, Any]], artifacts: Path, source_layer: str, destination_layer: str
) -> list[dict[str, Any]]:
    """Compare two evaluated layers without approximating systemd merge semantics.

    Both inputs are the normalized outputs of the pinned evaluator.  This is used
    for P→E; U→P remains provenance-aware and is produced by ``evaluate_upstream``.
    """
    if (source_layer, destination_layer) != ("P", "E"):
        raise ValueError("only the preregistered P→E transition is supported")
    analyzable = {
        (row["lineage_id"], row["distribution"], row["layer"], row["assessment_id"]): row
        for row in states
        if row["layer"] in {source_layer, destination_layer}
        and row["analysis_status"] == "ANALYZABLE"
        and row["assessment_id"]
    }
    observations = sorted({(key[0], key[1], key[3]) for key in analyzable})
    rows: list[dict[str, Any]] = []
    for lineage_id, distribution, assessment_id in observations:
        source = analyzable.get((lineage_id, distribution, source_layer, assessment_id))
        destination = analyzable.get((lineage_id, distribution, destination_layer, assessment_id))
        if source is None or destination is None:
            continue
        changed = source["normalized_state"] != destination["normalized_state"]
        source_exposure = float(source["exposure"] or 0)
        destination_exposure = float(destination["exposure"] or 0)
        source_set = str(source["set_state"]).casefold() == "true"
        destination_set = str(destination["set_state"]).casefold() == "true"
        if not changed:
            provenance = "INHERITED_SAME"
            semantic = "UNCHANGED"
        elif not source_set and destination_set:
            provenance = "ADDED"
            semantic = "TIGHTENED_UNDER_FIXED_POLICY" if destination_exposure < source_exposure else "CHANGED_EQUAL_EXPOSURE"
        elif source_set and not destination_set:
            provenance = "REMOVED"
            semantic = "RELAXED_UNDER_FIXED_POLICY" if destination_exposure > source_exposure else "CHANGED_EQUAL_EXPOSURE"
        else:
            provenance = "MODIFIED"
            semantic = (
                "TIGHTENED_UNDER_FIXED_POLICY"
                if destination_exposure < source_exposure
                else "RELAXED_UNDER_FIXED_POLICY"
                if destination_exposure > source_exposure
                else "CHANGED_EQUAL_EXPOSURE"
            )
        rows.append(
            {
                "lineage_id": lineage_id,
                "distribution": distribution,
                "transition": "P_E",
                "assessment_id": assessment_id,
                "semantic_category": semantic,
                "provenance_category": provenance,
                "exposure_delta": destination_exposure - source_exposure,
                "source_resolved": True,
                "destination_resolved": True,
            }
        )
    return rows
