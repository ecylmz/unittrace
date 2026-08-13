from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any
import re
import tarfile

from .io import write_csv
from .model import DerivationMode


CHANGELOG_VERSION = re.compile(r"^[^\s].*\(([^)]+)\)\s+[^;]+;")


def exact_debian_parent_from_changelog(changelog: str, focal_version: str) -> str | None:
    versions = [match.group(1).split(":", 1)[-1] for line in changelog.splitlines() if (match := CHANGELOG_VERSION.match(line))]
    focal = focal_version.split(":", 1)[-1]
    try:
        index = versions.index(focal)
    except ValueError:
        return None
    for version in versions[index + 1:]:
        lowered = version.casefold()
        if "ubuntu" not in lowered and "build" not in lowered:
            return version
    return None


def _ubuntu_changelogs(source_records: list[dict[str, Any]]) -> dict[tuple[str, str], str]:
    result: dict[tuple[str, str], str] = {}
    for record in source_records:
        if record["distribution"] != "ubuntu" or record.get("status") != "SUCCESS":
            continue
        for item in record.get("files", []):
            if ".debian.tar" not in item["filename"]:
                continue
            try:
                with tarfile.open(item["path"], "r:*") as archive:
                    member = next((entry for entry in archive.getmembers() if entry.name.rstrip("/").endswith("debian/changelog")), None)
                    if member is not None and (stream := archive.extractfile(member)) is not None:
                        result[(record["source_name"], record["source_version"])] = stream.read().decode("utf-8", errors="replace")
            except tarfile.TarError:
                pass
    return result


def resolve_ubuntu_ancestry(lineages: list[dict[str, Any]], packages: list[dict[str, Any]], states: list[dict[str, Any]], source_records: list[dict[str, Any]], artifacts: Path) -> list[dict[str, Any]]:
    package_index = {(row["distribution"], row["name"]): row for row in packages}
    lineage_index: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for lineage in lineages:
        if lineage["match_status"] == "MATCHED":
            lineage_index[lineage["lineage_id"]][lineage["distribution"]] = lineage
    p_dimensions: dict[tuple[str, str], int] = defaultdict(int)
    for state in states:
        if state["layer"] == "P" and state["analysis_status"] == "ANALYZABLE":
            p_dimensions[(state["lineage_id"], state["distribution"])] += 1
    changelogs = _ubuntu_changelogs(source_records)
    rows: list[dict[str, Any]] = []
    for lineage_id, members in sorted(lineage_index.items()):
        ubuntu = members.get("ubuntu")
        if ubuntu is None:
            continue
        ubuntu_package = package_index[("ubuntu", ubuntu["binary_package_id"])]
        debian = members.get("debian")
        mode = DerivationMode.DERIVATION_UNRESOLVED
        parent_version = ""
        evidence = "official frozen Ubuntu/Debian package metadata"
        comparable = 0
        parent_artifact_hash = ""
        changelog = changelogs.get((ubuntu_package["source_name"], ubuntu_package["source_version"].split(":", 1)[-1]))
        parent_from_changelog = exact_debian_parent_from_changelog(changelog, ubuntu_package["source_version"]) if changelog else None
        if debian is not None:
            debian_package = package_index[("debian", debian["binary_package_id"])]
            ubuntu_source_version = ubuntu_package["source_version"].split(":", 1)[-1]
            debian_source_version = debian_package["source_version"].split(":", 1)[-1]
            if "ubuntu" not in ubuntu_source_version.casefold() and ubuntu_source_version == debian_source_version and ubuntu_package["source_name"] == debian_package["source_name"]:
                mode = DerivationMode.SYNC
                parent_version = debian_package["source_version"]
                comparable = min(p_dimensions[(lineage_id, "ubuntu")], p_dimensions[(lineage_id, "debian")])
                parent_artifact_hash = debian_package["artifact_sha256"]
                evidence = "exact source package name/version equality in frozen official Debian and Ubuntu metadata; Ubuntu version has no Ubuntu delta suffix"
            elif "ubuntu" in ubuntu_source_version.casefold() and parent_from_changelog:
                mode = DerivationMode.MERGE_WITH_DELTA
                parent_version = parent_from_changelog
                if parent_version == debian_source_version and ubuntu_package["source_name"] == debian_package["source_name"]:
                    comparable = min(p_dimensions[(lineage_id, "ubuntu")], p_dimensions[(lineage_id, "debian")])
                    parent_artifact_hash = debian_package["artifact_sha256"]
                evidence = "exact prior non-Ubuntu Debian version parsed from the authoritative focal Ubuntu source package debian/changelog"
        elif "ubuntu" in ubuntu_package["source_version"].casefold() and parent_from_changelog:
            mode = DerivationMode.MERGE_WITH_DELTA
            parent_version = parent_from_changelog
            evidence = "exact prior non-Ubuntu Debian version parsed from the authoritative focal Ubuntu source package debian/changelog"
        rows.append({
            "child_distribution_id": "ubuntu", "child_source_package_id": ubuntu_package["source_name"], "child_package_version": ubuntu_package["source_version"],
            "parent_distribution_id": "debian", "parent_source_package_id": ubuntu_package["source_name"] if mode in {DerivationMode.SYNC, DerivationMode.MERGE_WITH_DELTA} else "",
            "parent_package_version": parent_version, "derivation_mode": mode.value, "parent_artifact_hash": parent_artifact_hash, "child_artifact_hash": ubuntu_package["artifact_sha256"],
            "derivation_evidence_uri_or_path": evidence, "resolution_status": "RESOLVED" if mode in {DerivationMode.SYNC, DerivationMode.MERGE_WITH_DELTA} else "DEBIAN_ANCESTOR_UNRESOLVED",
            "lineage_id": lineage_id, "canonical_upstream_id": ubuntu["canonical_upstream_id"], "comparable_dimension_count": comparable,
        })
    write_csv(artifacts / "normalized/distribution_derivation.csv", rows, ["child_distribution_id", "child_source_package_id", "child_package_version", "parent_distribution_id", "parent_source_package_id", "parent_package_version", "derivation_mode", "parent_artifact_hash", "child_artifact_hash", "derivation_evidence_uri_or_path", "resolution_status", "lineage_id", "canonical_upstream_id", "comparable_dimension_count"])
    return rows
