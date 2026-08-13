from __future__ import annotations

import json
import lzma
import hashlib
import shutil
import subprocess
import tarfile
import sqlite3
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit, urlunsplit

import rpmfile
import zstandard

from .io import atomic_json, download, sha256_file, write_csv
from .model import DimensionStatus, UArtifactClass
from .repositories import _release_hash, deb822_paragraphs
from .systemd import SUBSTITUTION, evaluate_unit, make_minimal_root, parse_service_assignments, project_service_template, template_dimension_statuses


def _source_version(version: str) -> str:
    return version.split(":", 1)[-1]


def fetch_deb_sources(
    config: dict[str, Any],
    pilot_packages: list[dict[str, Any]],
    artifacts: Path,
    frozen_repository_artifacts: Path | None = None,
) -> list[dict[str, Any]]:
    source_records: list[dict[str, Any]] = []
    wanted_by_distribution: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for package in pilot_packages:
        if package["distribution"] in {"debian", "ubuntu"}:
            wanted_by_distribution[package["distribution"]].add((package["source_name"], _source_version(package["source_version"])))
    for distribution in ("debian", "ubuntu"):
        distro_config = config["repositories"][distribution]
        repository_artifacts = frozen_repository_artifacts or artifacts
        raw_repo = repository_artifacts / "raw/repositories" / distribution
        release_text = (raw_repo / "Release").read_text(encoding="utf-8")
        base = distro_config["base_url"].rstrip("/")
        suite = distro_config["suite"]
        paragraphs: dict[tuple[str, str], dict[str, str]] = {}
        for component in distro_config["components"]:
            relative = f"{component}/source/Sources.xz"
            expected = _release_hash(release_text, relative)
            if expected is None:
                continue
            index_path = raw_repo / relative
            if frozen_repository_artifacts is None:
                download(f"{base}/dists/{suite}/{relative}", index_path, expected[0])
            elif not index_path.exists() or sha256_file(index_path) != expected[0]:
                raise RuntimeError(f"{distribution}: frozen source index failed verification: {relative}")
            text = lzma.decompress(index_path.read_bytes()).decode("utf-8", errors="replace")
            for paragraph in deb822_paragraphs(text):
                key = (paragraph.get("Package", ""), _source_version(paragraph.get("Version", "")))
                if key in wanted_by_distribution[distribution]:
                    paragraphs[key] = paragraph
        for source_name, version in sorted(wanted_by_distribution[distribution]):
            paragraph = paragraphs.get((source_name, version))
            record: dict[str, Any] = {"distribution": distribution, "source_name": source_name, "source_version": version, "source_kind": "deb_orig"}
            if paragraph is None:
                record.update({"status": "SOURCE_FETCH_FAILURE", "detail": "exact source version absent from frozen Sources indexes", "files": []})
                source_records.append(record)
                continue
            directory = paragraph.get("Directory", "")
            files: list[dict[str, Any]] = []
            checksums = {}
            for line in paragraph.get("Checksums-Sha256", "").splitlines():
                parts = line.split()
                if len(parts) == 3:
                    checksums[parts[2]] = (parts[0], int(parts[1]))
            status = "SUCCESS"
            detail = ""
            for filename, (digest, _) in checksums.items():
                target = artifacts / "raw/sources" / distribution / source_name / version.replace("/", "_") / filename
                try:
                    fetched = download(f"{base}/{directory}/{filename}", target, digest)
                    files.append({"filename": filename, "path": str(target), "sha256": fetched["sha256"], "bytes": fetched["bytes"]})
                except Exception as error:
                    status = "SOURCE_FETCH_FAILURE"
                    detail = str(error)
            record.update({"status": status, "detail": detail, "directory": directory, "files": files, "homepage": paragraph.get("Homepage", "")})
            source_records.append(record)
            atomic_json(artifacts / "checkpoints/source_fetch.json", source_records)
    atomic_json(artifacts / "raw/source_artifact_manifest.json", source_records)
    return source_records


def fetch_fedora_sources(
    config: dict[str, Any],
    pilot_packages: list[dict[str, Any]],
    artifacts: Path,
    frozen_repository_artifacts: Path | None = None,
) -> list[dict[str, Any]]:
    wanted = {row["source_version"] for row in pilot_packages if row["distribution"] == "fedora"}
    records: list[dict[str, Any]] = []
    source_bases = [
        "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Everything/source/tree",
        "https://download.fedoraproject.org/pub/fedora/linux/updates/44/Everything/source/tree",
    ]
    available: dict[str, tuple[str, str]] = {}
    namespace = {"repo": "http://linux.duke.edu/metadata/repo"}
    for index, base in enumerate(source_bases):
        repository_artifacts = frozen_repository_artifacts or artifacts
        repo_dir = repository_artifacts / "raw/repositories/fedora" / f"source-{index}"
        repomd = repo_dir / "repomd.xml"
        if frozen_repository_artifacts is None:
            download(f"{base}/repodata/repomd.xml", repomd)
        elif not repomd.exists():
            raise RuntimeError(f"fedora: frozen source repomd missing: {repomd}")
        root = ET.parse(repomd).getroot()
        href = digest = ""
        for data in root.findall("repo:data", namespace):
            if data.attrib.get("type") == "primary_db":
                href = data.find("repo:location", namespace).attrib["href"]
                digest = data.find("repo:checksum", namespace).text or ""
        compressed = repo_dir / Path(href).name
        if frozen_repository_artifacts is None:
            download(f"{base}/{href}", compressed, digest)
        elif not compressed.exists() or sha256_file(compressed) != digest:
            raise RuntimeError(f"fedora: frozen source primary metadata failed verification: {compressed}")
        database = repo_dir / "primary.sqlite"
        if not database.exists():
            temporary = database.with_suffix(".tmp")
            with compressed.open("rb") as source, temporary.open("wb") as target:
                zstandard.ZstdDecompressor().copy_stream(source, target)
            temporary.replace(database)
        connection = sqlite3.connect(database)
        connection.row_factory = sqlite3.Row
        for row in connection.execute("select * from packages"):
            mapping = dict(row)
            filename = Path(mapping.get("location_href") or "").name
            if filename in wanted:
                available[filename] = (f"{base}/{mapping['location_href']}", mapping.get("pkgId") or "")
        connection.close()
    package_lookup = {row["source_version"]: row for row in pilot_packages if row["distribution"] == "fedora"}
    for filename in sorted(wanted):
        package = package_lookup[filename]
        record: dict[str, Any] = {"distribution": "fedora", "source_name": package["source_name"], "source_version": filename, "source_kind": "fedora_srpm"}
        located = available.get(filename)
        if located is None:
            record.update({"status": "SOURCE_FETCH_FAILURE", "detail": "exact SRPM absent from frozen source repository metadata", "files": []})
        else:
            url, digest = located
            target = artifacts / "raw/sources/fedora" / package["source_name"] / filename
            try:
                fetched = download(url, target, digest or None)
                record.update({"status": "SUCCESS", "detail": "", "files": [{"filename": filename, "path": str(target), "sha256": fetched["sha256"], "bytes": fetched["bytes"]}]})
            except Exception as error:
                record.update({"status": "SOURCE_FETCH_FAILURE", "detail": str(error), "files": []})
        records.append(record)
        atomic_json(artifacts / "checkpoints/fedora_source_fetch.json", records)
    return records


def _srcinfo_value(text: str, key: str) -> str | None:
    prefix = key + " ="
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped.split("=", 1)[1].strip()
    return None


def _srcinfo_values(text: str, key: str) -> list[str]:
    prefix = key + " ="
    return [line.strip().split("=", 1)[1].strip() for line in text.splitlines() if line.strip().startswith(prefix)]


def _arch_version(srcinfo: str) -> str:
    version = _srcinfo_value(srcinfo, "pkgver") or ""
    release = _srcinfo_value(srcinfo, "pkgrel") or ""
    epoch = _srcinfo_value(srcinfo, "epoch")
    result = f"{version}-{release}"
    return f"{epoch}:{result}" if epoch else result


def _arch_packaging_commit(repository: Path, version: str) -> tuple[str, str] | None:
    commits = subprocess.run(
        ["git", "-C", str(repository), "log", "--all", "--before=2026-08-10T00:00:00Z", "--format=%H", "--", ".SRCINFO"],
        text=True, capture_output=True, check=True,
    ).stdout.splitlines()
    for commit in commits:
        result = subprocess.run(["git", "-C", str(repository), "show", f"{commit}:.SRCINFO"], text=True, capture_output=True)
        if result.returncode == 0 and _arch_version(result.stdout) == version:
            return commit, result.stdout
    return None


def _resolve_vcs_archive(source_url: str) -> tuple[str, str, str]:
    value = source_url.removeprefix("git+")
    split = urlsplit(value)
    query = parse_qs(split.fragment)
    ref_kind = next((key for key in ("commit", "tag", "branch") if key in query), None)
    ref = (query[ref_kind][0] if ref_kind else "HEAD").split("?", 1)[0]
    repository_url = urlunsplit((split.scheme, split.netloc, split.path, "", ""))
    patterns = [ref]
    if ref_kind == "tag":
        patterns = [f"refs/tags/{ref}^{{}}", f"refs/tags/{ref}"]
    elif ref_kind == "branch":
        patterns = [f"refs/heads/{ref}"]
    commit = ""
    for pattern in patterns:
        output = subprocess.run(["git", "ls-remote", repository_url, pattern], text=True, capture_output=True, check=True).stdout.strip()
        if output:
            commit = output.split()[0]
            break
    if not commit:
        raise RuntimeError(f"cannot resolve VCS source {source_url}")
    clean_path = split.path.removesuffix(".git").strip("/")
    if split.netloc.casefold() == "github.com":
        archive_url = f"https://github.com/{clean_path}/archive/{commit}.tar.gz"
    elif "gitlab" in split.netloc.casefold():
        project = clean_path.rsplit("/", 1)[-1]
        archive_url = f"https://{split.netloc}/{clean_path}/-/archive/{commit}/{project}-{commit}.tar.gz"
    else:
        raise RuntimeError(f"unsupported VCS archive host for deterministic retrieval: {split.netloc}")
    return repository_url, commit, archive_url


def fetch_arch_sources(config: dict[str, Any], pilot_packages: list[dict[str, Any]], artifacts: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    packages: dict[str, dict[str, Any]] = {}
    for row in pilot_packages:
        if row["distribution"] == "arch":
            packages.setdefault(row["source_name"], row)
    for source_name, package in sorted(packages.items()):
        packaging_url = f"https://gitlab.archlinux.org/archlinux/packaging/packages/{source_name}.git"
        repository = artifacts / "cache/arch-packaging" / source_name
        record: dict[str, Any] = {"distribution": "arch", "source_name": source_name, "source_version": package["source_version"], "source_kind": "arch_srcinfo"}
        try:
            if not (repository / ".git").exists():
                subprocess.run(["git", "clone", "--filter=blob:none", packaging_url, str(repository)], check=True, capture_output=True)
            else:
                subprocess.run(["git", "-C", str(repository), "fetch", "--all", "--prune"], check=True, capture_output=True)
            resolved = _arch_packaging_commit(repository, package["source_version"])
            if resolved is None:
                raise RuntimeError("no .SRCINFO commit exactly matches frozen package version before freeze timestamp")
            packaging_commit, srcinfo = resolved
            sources = _srcinfo_values(srcinfo, "source") + _srcinfo_values(srcinfo, "source_x86_64")
            sha256s = _srcinfo_values(srcinfo, "sha256sums") + _srcinfo_values(srcinfo, "sha256sums_x86_64")
            b2sums = _srcinfo_values(srcinfo, "b2sums") + _srcinfo_values(srcinfo, "b2sums_x86_64")
            files: list[dict[str, Any]] = []
            for index, source_item in enumerate(sources):
                source_url = source_item.split("::", 1)[-1]
                if source_url.startswith("git+"):
                    repository_url, upstream_commit, archive_url = _resolve_vcs_archive(source_url)
                    destination = artifacts / "raw/sources/arch" / source_name / f"upstream-{index}-{upstream_commit}.tar.gz"
                    fetched = download(archive_url, destination)
                    files.append({"filename": destination.name, "path": str(destination), "sha256": fetched["sha256"], "bytes": fetched["bytes"], "upstream_repository": repository_url, "upstream_commit": upstream_commit, "source_url": source_url})
                    continue
                if not source_url.startswith(("https://", "http://")):
                    continue
                bare_url = source_url.split("#", 1)[0]
                if bare_url.endswith((".sig", ".asc")):
                    continue
                filename = source_item.split("::", 1)[0] if "::" in source_item else Path(urlsplit(bare_url).path).name
                destination = artifacts / "raw/sources/arch" / source_name / filename
                expected = sha256s[index] if index < len(sha256s) and sha256s[index] != "SKIP" else None
                fetched = download(bare_url, destination, expected)
                if index < len(b2sums) and b2sums[index] != "SKIP":
                    observed_b2 = hashlib.blake2b(destination.read_bytes()).hexdigest()
                    if observed_b2 != b2sums[index]:
                        raise ValueError(f"BLAKE2 mismatch for {bare_url}")
                files.append({"filename": filename, "path": str(destination), "sha256": fetched["sha256"], "bytes": fetched["bytes"], "source_url": source_url})
            if not files:
                raise RuntimeError("no deterministic upstream source archive retrieved from exact .SRCINFO")
            record.update({"status": "SUCCESS", "detail": "", "packaging_repository": packaging_url, "packaging_commit": packaging_commit, "srcinfo_sha256": hashlib.sha256(srcinfo.encode()).hexdigest(), "files": files})
        except Exception as error:
            record.update({"status": "SOURCE_FETCH_FAILURE", "detail": str(error), "files": []})
        records.append(record)
        atomic_json(artifacts / "checkpoints/arch_source_fetch.json", records)
    return records


def extract_pristine_sources(source_records: list[dict[str, Any]], artifacts: Path) -> list[dict[str, Any]]:
    inventories: list[dict[str, Any]] = []
    for record in source_records:
        inventory = dict(record)
        orig_files = [
            item for item in record.get("files", [])
            if ".orig.tar" in item["filename"] and not item["filename"].endswith((".asc", ".sig"))
        ]
        if record.get("source_kind") == "fedora_srpm" and record.get("status") == "SUCCESS":
            srpm = Path(record["files"][0]["path"])
            staging = artifacts / "cache/srpm" / record["source_name"] / record["source_version"]
            staging.mkdir(parents=True, exist_ok=True)
            with rpmfile.open(srpm) as archive:
                for member in archive.getmembers():
                    if bool(getattr(member, "isdir", False)) or bool(getattr(member, "issymlink", False)):
                        continue
                    target = staging / Path(member.name).name
                    stream = archive.extractfile(member)
                    if stream is not None and not target.exists():
                        target.write_bytes(stream.read())
            orig_files = [
                {"filename": path.name, "path": str(path), "sha256": sha256_file(path), "bytes": path.stat().st_size}
                for path in staging.iterdir() if path.is_file() and tarfile.is_tarfile(path)
            ]
        elif record.get("source_kind") == "arch_srcinfo" and record.get("status") == "SUCCESS":
            orig_files = [item for item in record.get("files", []) if tarfile.is_tarfile(item["path"])]
        if record.get("status") != "SUCCESS" or not orig_files:
            inventory.update({"inventory_status": "UPSTREAM_UNRESOLVED", "source_root": "", "service_artifacts": []})
            inventories.append(inventory)
            continue
        root = artifacts / "roots/sources" / record["distribution"] / record["source_name"] / record["source_version"].replace("/", "_")
        complete = root / ".unittrace-source.json"
        try:
            hashes = {item["filename"]: item["sha256"] for item in orig_files}
            if not complete.exists() or json.loads(complete.read_text()).get("hashes") != hashes:
                if root.exists():
                    shutil.rmtree(root)
                root.mkdir(parents=True)
                for item in orig_files:
                    subprocess.run(["tar", "--no-same-owner", "-xf", item["path"], "-C", str(root)], check=True, capture_output=True)
                atomic_json(complete, {"hashes": hashes})
            services = []
            for path in root.rglob("*"):
                if not path.is_file() or path.name == ".unittrace-source.json":
                    continue
                if path.name.endswith(".service") or ".service.in" in path.name or path.name.endswith(".service.in"):
                    services.append({"path": str(path.relative_to(root)), "sha256": sha256_file(path)})
            inventory.update({"inventory_status": "SUCCESS", "source_root": str(root), "service_artifacts": sorted(services, key=lambda row: row["path"])})
        except Exception as error:
            inventory.update({"inventory_status": "UPSTREAM_UNRESOLVED", "source_root": str(root), "service_artifacts": [], "detail": str(error)})
        inventories.append(inventory)
    atomic_json(artifacts / "normalized/source_inventories.json", inventories)
    return inventories


def resolve_upstream_artifacts(lineages: list[dict[str, Any]], inventories: list[dict[str, Any]], artifacts: Path) -> list[dict[str, Any]]:
    inventory_index = {(row["distribution"], row["source_name"], row["source_version"]): row for row in inventories}
    package_rows = list(__import__("csv").DictReader((artifacts / "normalized/pilot_packages.csv").open(encoding="utf-8")))
    package_index = {(row["distribution"], row["name"]): row for row in package_rows}
    rows: list[dict[str, Any]] = []
    for lineage in lineages:
        if lineage["match_status"] != "MATCHED":
            continue
        package = package_index[(lineage["distribution"], lineage["binary_package_id"])]
        common = {
            "lineage_id": lineage["lineage_id"], "canonical_upstream_id": lineage["canonical_upstream_id"],
            "distribution": lineage["distribution"], "binary_package_id": lineage["binary_package_id"],
            "source_package_id": package["source_name"], "source_version": package["source_version"],
        }
        inventory_version = package["source_version"] if lineage["distribution"] in {"fedora", "arch"} else _source_version(package["source_version"])
        inventory = inventory_index.get((lineage["distribution"], package["source_name"], inventory_version))
        if inventory is None or inventory.get("inventory_status") != "SUCCESS":
            rows.append({**common, "u_artifact_class": UArtifactClass.U5_AMBIGUOUS_OR_UNRESOLVED.value, "u_source_path": "", "u_source_revision": package["source_version"], "u_artifact_hash": "", "u_structural_placeholder_count": 0, "generation_rule_id": "", "generation_status": "NOT_ATTEMPTED", "resolution_detail": "pristine source unavailable"})
            continue
        candidates = inventory["service_artifacts"]
        basename = lineage["unit_basename"]
        exact = [item for item in candidates if Path(item["path"]).name in {basename, basename + ".in"} or Path(item["path"]).name.removesuffix(".in") == basename]
        if not exact:
            if not candidates:
                rows.append({**common, "u_artifact_class": UArtifactClass.U4_NO_UPSTREAM_STATIC_OR_TEMPLATE_UNIT.value, "u_source_path": "", "u_source_revision": package["source_version"], "u_artifact_hash": "", "u_structural_placeholder_count": 0, "generation_rule_id": "", "generation_status": "NOT_APPLICABLE", "resolution_detail": "complete pristine orig-tar inventory contained no service unit or template"})
            else:
                executable = lineage["normalized_exec_lineage"]
                source_root = Path(inventory["source_root"])
                exec_candidates = [item for item in candidates if executable and executable in (source_root / item["path"]).read_text(encoding="utf-8", errors="replace")]
                if len(exec_candidates) == 1:
                    exact = exec_candidates
                else:
                    rows.append({**common, "u_artifact_class": UArtifactClass.U5_AMBIGUOUS_OR_UNRESOLVED.value, "u_source_path": "", "u_source_revision": package["source_version"], "u_artifact_hash": "", "u_structural_placeholder_count": 0, "generation_rule_id": "", "generation_status": "NOT_ATTEMPTED", "resolution_detail": f"no unique upstream artifact; candidates={len(candidates)}, executable_candidates={len(exec_candidates)}"})
        if exact:
            if len(exact) != 1:
                rows.append({**common, "u_artifact_class": UArtifactClass.U5_AMBIGUOUS_OR_UNRESOLVED.value, "u_source_path": "", "u_source_revision": package["source_version"], "u_artifact_hash": "", "u_structural_placeholder_count": 0, "generation_rule_id": "", "generation_status": "NOT_ATTEMPTED", "resolution_detail": f"ambiguous exact artifacts={len(exact)}"})
                continue
            item = exact[0]
            path = Path(inventory["source_root"]) / item["path"]
            text = path.read_text(encoding="utf-8", errors="replace")
            is_template = path.name.endswith(".in") or ".service.in" in path.name or bool(SUBSTITUTION.search(text))
            projection = project_service_template(text) if is_template else None
            artifact_class = projection.artifact_class if projection else UArtifactClass.U0_STATIC
            rows.append({**common, "u_artifact_class": artifact_class.value, "u_source_path": str(path), "u_source_revision": package["source_version"], "u_artifact_hash": item["sha256"], "u_structural_placeholder_count": projection.structural_placeholder_count if projection else 0, "generation_rule_id": "", "generation_status": "NOT_APPLICABLE", "resolution_detail": "exact basename or unique executable source mapping"})
    write_csv(artifacts / "normalized/upstream_artifacts.csv", rows, ["lineage_id", "canonical_upstream_id", "distribution", "binary_package_id", "source_package_id", "source_version", "u_artifact_class", "u_source_path", "u_source_revision", "u_artifact_hash", "u_structural_placeholder_count", "generation_rule_id", "generation_status", "resolution_detail"])
    return rows


def evaluate_upstream(upstream_rows: list[dict[str, Any]], states: list[dict[str, Any]], evaluator: Path, policy: Path, artifacts: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    schema = json.loads((artifacts / "security_assessment_schema.json").read_text())
    assessment_ids = {row["json_field"] for row in schema["assessments"] if row.get("json_field")}
    p_index = {(row["lineage_id"], row["distribution"], row["assessment_id"]): row for row in states if row["layer"] == "P" and row["analysis_status"] == "ANALYZABLE"}
    transformations: list[dict[str, Any]] = []
    for upstream in upstream_rows:
        artifact_class = upstream["u_artifact_class"]
        if artifact_class not in {UArtifactClass.U0_STATIC.value, UArtifactClass.U1_TEMPLATE_VALUE_ONLY.value, UArtifactClass.U2_TEMPLATE_STRUCTURAL.value}:
            continue
        source = Path(upstream["u_source_path"])
        text = source.read_text(encoding="utf-8", errors="replace")
        if artifact_class == UArtifactClass.U0_STATIC.value:
            projected_text = text
            statuses = {assessment_id: DimensionStatus.ABSENT_RESOLVED for assessment_id in assessment_ids}
        else:
            projection = project_service_template(text)
            projected_text = projection.projected_text
            statuses = template_dimension_statuses(projection, assessment_ids)
            if "ExecStart" not in parse_service_assignments(projected_text):
                projected_text = projected_text.replace("[Service]", "[Service]\nExecStart=/usr/bin/true", 1)
        root = artifacts / "roots/upstream" / upstream["distribution"] / upstream["lineage_id"].replace("/", "_").replace(":", "_")
        if root.exists():
            shutil.rmtree(root)
        make_minimal_root(root)
        unit_name = "unittrace-u.service"
        (root / "usr/lib/systemd/system" / unit_name).write_text(projected_text, encoding="utf-8")
        status, assessments, detail = evaluate_unit(evaluator, policy, root, unit_name)
        raw_path = artifacts / "raw/evaluator" / upstream["distribution"] / "U" / (upstream["lineage_id"].replace("/", "_").replace(":", "_") + ".json")
        atomic_json(raw_path, {"status": status, "detail": detail, "rows": assessments})
        if status != "ANALYZABLE":
            continue
        for assessment in assessments:
            assessment_id = assessment.get("json_field") or assessment.get("name")
            dimension_status = statuses.get(assessment_id, DimensionStatus.ABSENCE_UNRESOLVED)
            if artifact_class == UArtifactClass.U0_STATIC.value and assessment.get("set"):
                dimension_status = DimensionStatus.PRESENT_RESOLVED
            normalized = json.dumps({"set": assessment.get("set"), "exposure": assessment.get("exposure"), "description": assessment.get("description")}, sort_keys=True)
            u_state = {
                "lineage_id": upstream["lineage_id"], "distribution": upstream["distribution"], "layer": "U", "assessment_id": assessment_id,
                "normalized_state": normalized, "set_state": assessment.get("set"), "description_normalized": assessment.get("description"), "exposure": assessment.get("exposure"),
                "analysis_status": "ANALYZABLE", "dimension_provenance_status": dimension_status.value, "resolution_evidence": str(raw_path),
            }
            states.append(u_state)
            if dimension_status not in {DimensionStatus.PRESENT_RESOLVED, DimensionStatus.ABSENT_RESOLVED}:
                continue
            p_state = p_index.get((upstream["lineage_id"], upstream["distribution"], assessment_id))
            if p_state is None:
                continue
            changed = normalized != p_state["normalized_state"]
            u_exposure = float(assessment.get("exposure") or 0)
            p_exposure = float(p_state["exposure"] or 0)
            u_set = bool(assessment.get("set"))
            p_set = str(p_state["set_state"]).casefold() == "true"
            if not changed:
                provenance_category = "INHERITED_SAME"
            elif not u_set and p_set:
                provenance_category = "ADDED"
            elif u_set and not p_set:
                provenance_category = "REMOVED"
            else:
                provenance_category = "MODIFIED"
            transformations.append({
                "lineage_id": upstream["lineage_id"], "distribution": upstream["distribution"], "transition": "U_P", "assessment_id": assessment_id,
                "semantic_category": "CHANGED_EQUAL_EXPOSURE" if changed and u_exposure == p_exposure else ("TIGHTENED_UNDER_FIXED_POLICY" if changed and p_exposure < u_exposure else ("RELAXED_UNDER_FIXED_POLICY" if changed else "UNCHANGED")),
                "provenance_category": provenance_category, "exposure_delta": p_exposure - u_exposure, "source_resolved": True, "destination_resolved": True,
            })
    write_csv(artifacts / "normalized/policy_states.csv", states, ["lineage_id", "distribution", "layer", "assessment_id", "normalized_state", "set_state", "description_normalized", "exposure", "analysis_status", "dimension_provenance_status", "resolution_evidence"])
    return states, transformations
