from __future__ import annotations

import gzip
import io
import json
import lzma
import sqlite3
import subprocess
import tarfile
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator

import zstandard

from .io import atomic_json, download, sha256_file, write_csv
from .protocol import deterministic_order, is_system_service_path, normalize_upstream_url


def deb822_paragraphs(text: str) -> Iterator[dict[str, str]]:
    paragraph: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines() + [""]:
        if not line:
            if paragraph:
                yield paragraph
            paragraph = {}
            current = None
        elif line[0].isspace() and current:
            paragraph[current] += "\n" + line[1:]
        elif ":" in line:
            current, value = line.split(":", 1)
            paragraph[current] = value.lstrip()


def _release_hash(release: str, relative_path: str, algorithm: str = "SHA256") -> tuple[str, int] | None:
    lines = release.splitlines()
    try:
        start = lines.index(algorithm + ":") + 1
    except ValueError:
        return None
    for line in lines[start:]:
        if not line.startswith(" "):
            break
        parts = line.split()
        if len(parts) == 3 and parts[2] == relative_path:
            return parts[0], int(parts[1])
    return None


def _read_compressed(path: Path) -> str:
    if path.suffix == ".xz":
        return lzma.decompress(path.read_bytes()).decode("utf-8", errors="replace")
    if path.suffix == ".gz":
        return gzip.decompress(path.read_bytes()).decode("utf-8", errors="replace")
    if path.suffix == ".zst":
        return zstandard.ZstdDecompressor().decompress(path.read_bytes()).decode("utf-8", errors="replace")
    return path.read_text(encoding="utf-8", errors="replace")


class DebRepository:
    def __init__(self, name: str, config: dict[str, Any], raw: Path):
        self.name = name
        self.config = config
        self.raw = raw / "repositories" / name

    def freeze_and_enumerate(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        suite = self.config["suite"]
        base = self.config["base_url"].rstrip("/")
        release_path = self.raw / "Release"
        release_record = download(f"{base}/dists/{suite}/Release", release_path)
        release_text = release_path.read_text(encoding="utf-8")
        records = [release_record]
        package_metadata: dict[str, dict[str, str]] = {}
        package_components: dict[str, str] = {}
        for component in self.config["components"]:
            relative = f"{component}/binary-amd64/Packages.xz"
            expected = _release_hash(release_text, relative)
            if not expected:
                continue
            destination = self.raw / relative
            record = download(f"{base}/dists/{suite}/{relative}", destination, expected[0])
            records.append(record)
            for paragraph in deb822_paragraphs(_read_compressed(destination)):
                package = paragraph.get("Package")
                if package:
                    package_metadata[package] = paragraph
                    package_components[package] = component
        relative_contents = "main/Contents-amd64.gz" if self.name == "debian" else "Contents-amd64.gz"
        expected = _release_hash(release_text, relative_contents)
        if expected is None and self.name == "debian":
            relative_contents = "main/Contents-amd64"
            expected = _release_hash(release_text, relative_contents)
        if expected is None:
            raise RuntimeError(f"{self.name}: Contents-amd64 missing from frozen Release")
        contents_path = self.raw / relative_contents
        record = download(f"{base}/dists/{suite}/{relative_contents}", contents_path, expected[0])
        records.append(record)
        service_paths: dict[str, set[str]] = defaultdict(set)
        opener = gzip.open if contents_path.suffix == ".gz" else open
        with opener(contents_path, "rt", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                try:
                    path, package_field = line.rstrip().rsplit(maxsplit=1)
                except ValueError:
                    continue
                if not is_system_service_path(path):
                    continue
                for package_item in package_field.split(","):
                    package = package_item.rsplit("/", 1)[-1]
                    service_paths[package].add(path)
        packages: list[dict[str, Any]] = []
        services: list[dict[str, Any]] = []
        for package in sorted(service_paths):
            metadata = package_metadata.get(package)
            if metadata is None:
                continue
            source_field = metadata.get("Source", package)
            source_name = source_field.split()[0]
            source_version = source_field.partition("(")[2].rstrip(")") or metadata.get("Version", "")
            homepage = metadata.get("Homepage", "")
            canonical = normalize_upstream_url(homepage)
            row = {
                "distribution": self.name,
                "name": package,
                "version": metadata.get("Version", ""),
                "architecture": metadata.get("Architecture", ""),
                "source_name": source_name,
                "source_version": source_version,
                "homepage": homepage,
                "canonical_upstream_id": canonical or "",
                "filename": metadata.get("Filename", ""),
                "artifact_url": f"{base}/{metadata.get('Filename', '')}",
                "artifact_sha256": metadata.get("SHA256", ""),
                "component": package_components.get(package, ""),
            }
            packages.append(row)
            for path in sorted(service_paths[package]):
                services.append({"distribution": self.name, "package": package, "unit_path": path})
        atomic_json(self.raw / "freeze_records.json", records)
        return packages, services


class FedoraRepository:
    NAMESPACE = {"repo": "http://linux.duke.edu/metadata/repo"}

    def __init__(self, config: dict[str, Any], raw: Path):
        self.config = config
        self.raw = raw / "repositories" / "fedora"

    def _metadata_href(self, repomd: Path, kind: str) -> tuple[str, str]:
        root = ET.parse(repomd).getroot()
        for data in root.findall("repo:data", self.NAMESPACE):
            if data.attrib.get("type") == kind:
                location = data.find("repo:location", self.NAMESPACE)
                checksum = data.find("repo:checksum", self.NAMESPACE)
                if location is not None and checksum is not None:
                    return location.attrib["href"], checksum.text or ""
        raise RuntimeError(f"Fedora metadata {kind} not found")

    def freeze_and_enumerate(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        merged: dict[str, dict[str, Any]] = {}
        service_paths: dict[str, set[str]] = defaultdict(set)
        records: list[dict[str, Any]] = []
        for index, base in enumerate(self.config["repositories"]):
            repo_dir = self.raw / str(index)
            repomd = repo_dir / "repomd.xml"
            records.append(download(f"{base}/repodata/repomd.xml", repomd))
            primary_href, primary_hash = self._metadata_href(repomd, "primary_db")
            files_href, files_hash = self._metadata_href(repomd, "filelists_db")
            primary_zst = repo_dir / Path(primary_href).name
            files_zst = repo_dir / Path(files_href).name
            records.append(download(f"{base}/{primary_href}", primary_zst, primary_hash))
            records.append(download(f"{base}/{files_href}", files_zst, files_hash))
            primary_db = repo_dir / "primary.sqlite"
            files_db = repo_dir / "filelists.sqlite"
            for source, target in ((primary_zst, primary_db), (files_zst, files_db)):
                if not target.exists():
                    temporary = target.with_suffix(target.suffix + ".tmp")
                    with source.open("rb") as compressed, temporary.open("wb") as output:
                        zstandard.ZstdDecompressor().copy_stream(compressed, output)
                    temporary.replace(target)
            primary = sqlite3.connect(primary_db)
            files = sqlite3.connect(files_db)
            primary.row_factory = sqlite3.Row
            files.row_factory = sqlite3.Row
            primary_columns = {row[1] for row in primary.execute("pragma table_info(packages)")}
            file_columns = {row[1] for row in files.execute("pragma table_info(packages)")}
            pkg_key = "pkgKey"
            file_rows = files.execute("select * from packages")
            file_by_checksum: dict[str, set[str]] = defaultdict(set)
            for row in file_rows:
                mapping = dict(row)
                checksum = mapping.get("pkgId") or mapping.get("pkgid") or str(mapping.get(pkg_key, ""))
                file_by_checksum[checksum].update(self._files_for_package(files, mapping, file_columns))
            for row in primary.execute("select * from packages"):
                mapping = dict(row)
                checksum = mapping.get("pkgId") or mapping.get("pkgid") or ""
                paths = {path for path in file_by_checksum.get(checksum, set()) if is_system_service_path(path)}
                if not paths:
                    continue
                name = mapping["name"]
                version = f"{mapping.get('epoch') or '0'}:{mapping.get('version')}-{mapping.get('release')}"
                if version.startswith("0:"):
                    version = version[2:]
                href = mapping.get("location_href") or mapping.get("location") or ""
                homepage = mapping.get("url") or ""
                item = {
                    "distribution": "fedora",
                    "name": name,
                    "version": version,
                    "architecture": mapping.get("arch", ""),
                    "source_name": (mapping.get("rpm_sourcerpm") or mapping.get("sourcerpm") or name).rsplit("-", 2)[0],
                    "source_version": mapping.get("rpm_sourcerpm") or mapping.get("sourcerpm") or "",
                    "homepage": homepage,
                    "canonical_upstream_id": normalize_upstream_url(homepage) or "",
                    "filename": href,
                    "artifact_url": f"{base}/{href}",
                    "artifact_sha256": checksum,
                    "component": "updates" if index else "release",
                }
                merged[name] = item
                service_paths[name] = paths
            primary.close()
            files.close()
        packages = [merged[name] for name in sorted(merged)]
        services = [{"distribution": "fedora", "package": name, "unit_path": path} for name in sorted(service_paths) for path in sorted(service_paths[name])]
        atomic_json(self.raw / "freeze_records.json", records)
        return packages, services

    @staticmethod
    def _files_for_package(connection: sqlite3.Connection, package: dict[str, Any], columns: set[str]) -> set[str]:
        if "filelist" in package and package.get("filelist"):
            return set(str(package["filelist"]).split("/"))
        key = package.get("pkgKey")
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        result: set[str] = set()
        for table in ("filelist", "files"):
            if table not in tables:
                continue
            table_columns = {row[1] for row in connection.execute(f"pragma table_info({table})")}
            path_column = next((item for item in ("dirname", "path", "name") if item in table_columns), None)
            name_column = "filenames" if "filenames" in table_columns else None
            if path_column:
                for row in connection.execute(f"select * from {table} where pkgKey=?", (key,)):
                    mapping = dict(zip([description[0] for description in connection.execute(f"select * from {table} limit 0").description or []], row))
                    dirname = str(mapping.get("dirname") or mapping.get("path") or "")
                    filenames = str(mapping.get("filenames") or mapping.get("name") or "")
                    if filenames:
                        for filename in filenames.split("/"):
                            result.add(dirname.rstrip("/") + "/" + filename)
                    elif dirname:
                        result.add(dirname)
        return result


def _tar_sections(path: Path) -> dict[str, dict[str, list[str]]]:
    result: dict[str, dict[str, list[str]]] = {}
    with tarfile.open(path, "r:*") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            stream = archive.extractfile(member)
            if stream is None:
                continue
            section: str | None = None
            parsed: dict[str, list[str]] = defaultdict(list)
            for line in stream.read().decode("utf-8", errors="replace").splitlines():
                if line.startswith("%") and line.endswith("%"):
                    section = line.strip("%")
                elif line and section:
                    parsed[section].append(line)
            result[member.name.split("/", 1)[0]] = dict(parsed)
    return result


class ArchRepository:
    def __init__(self, config: dict[str, Any], raw: Path):
        self.config = config
        self.raw = raw / "repositories" / "arch"

    def freeze_and_enumerate(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        records: list[dict[str, Any]] = []
        merged: dict[str, dict[str, Any]] = {}
        service_paths: dict[str, set[str]] = defaultdict(set)
        base = self.config["base_url"].rstrip("/")
        for repository in self.config["repositories"]:
            db_path = self.raw / f"{repository}.db"
            files_path = self.raw / f"{repository}.files"
            records.append(download(f"{base}/{repository}/os/x86_64/{repository}.db", db_path))
            records.append(download(f"{base}/{repository}/os/x86_64/{repository}.files", files_path))
            descriptions = _tar_sections(db_path)
            file_sections = _tar_sections(files_path)
            for directory, fields in descriptions.items():
                name = fields.get("NAME", [""])[0]
                paths = {path for path in file_sections.get(directory, {}).get("FILES", []) if is_system_service_path(path)}
                if not name or not paths:
                    continue
                homepage = fields.get("URL", [""])[0]
                filename = fields.get("FILENAME", [""])[0]
                item = {
                    "distribution": "arch",
                    "name": name,
                    "version": fields.get("VERSION", [""])[0],
                    "architecture": fields.get("ARCH", [""])[0],
                    "source_name": fields.get("BASE", [name])[0],
                    "source_version": fields.get("VERSION", [""])[0],
                    "homepage": homepage,
                    "canonical_upstream_id": normalize_upstream_url(homepage) or "",
                    "filename": filename,
                    "artifact_url": f"{base}/{repository}/os/x86_64/{filename}",
                    "artifact_sha256": fields.get("SHA256SUM", [""])[0],
                    "component": repository,
                }
                merged[name] = item
                service_paths[name] = paths
        packages = [merged[name] for name in sorted(merged)]
        services = [{"distribution": "arch", "package": name, "unit_path": path} for name in sorted(service_paths) for path in sorted(service_paths[name])]
        atomic_json(self.raw / "freeze_records.json", records)
        return packages, services


def enumerate_all(config: dict[str, Any], artifacts: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    raw = artifacts / "raw"
    all_packages: list[dict[str, Any]] = []
    all_services: list[dict[str, Any]] = []
    adapters = [
        DebRepository("debian", config["repositories"]["debian"], raw),
        DebRepository("ubuntu", config["repositories"]["ubuntu"], raw),
        FedoraRepository(config["repositories"]["fedora"], raw),
        ArchRepository(config["repositories"]["arch"], raw),
    ]
    for adapter in adapters:
        packages, services = adapter.freeze_and_enumerate()
        all_packages.extend(packages)
        all_services.extend(services)
    package_fields = ["distribution", "name", "version", "architecture", "source_name", "source_version", "homepage", "canonical_upstream_id", "filename", "artifact_url", "artifact_sha256", "component"]
    write_csv(artifacts / "normalized/repository_packages.csv", all_packages, package_fields)
    write_csv(artifacts / "normalized/repository_services.csv", all_services, ["distribution", "package", "unit_path"])
    return all_packages, all_services


def select_pilot(packages: list[dict[str, Any]], config: dict[str, Any], artifacts: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pre_exclusions: list[dict[str, Any]] = []
    for package in packages:
        canonical = package["canonical_upstream_id"]
        if not canonical:
            pre_exclusions.append({"entity_type": "package", "entity_id": f"{package['distribution']}:{package['name']}", "stage": "before_selection", "reason_code": "NO_AUTHORITATIVE_UPSTREAM_URL", "technical_detail": package.get("homepage", "")})
            continue
        by_project[canonical].append(package)
    candidates: list[dict[str, Any]] = []
    for canonical, observations in by_project.items():
        distributions = sorted({row["distribution"] for row in observations})
        if len(distributions) < 2:
            continue
        candidates.append({
            "canonical_upstream_id": canonical,
            "selection_hash": deterministic_order(canonical, config["selection_namespace"]),
            "distribution_count": len(distributions),
            "distributions": ";".join(distributions),
            "package_count": len(observations),
        })
    candidates.sort(key=lambda row: (row["selection_hash"], row["canonical_upstream_id"]))
    selected_ids = {row["canonical_upstream_id"] for row in candidates[: int(config["pilot_size"])]}
    selected_packages = [row for row in packages if row["canonical_upstream_id"] in selected_ids]
    write_csv(artifacts / "normalized/pilot_candidates.csv", candidates, ["canonical_upstream_id", "selection_hash", "distribution_count", "distributions", "package_count"])
    write_csv(artifacts / "normalized/pilot_projects.csv", candidates[: int(config["pilot_size"])], ["canonical_upstream_id", "selection_hash", "distribution_count", "distributions", "package_count"])
    write_csv(artifacts / "normalized/exclusions.csv", pre_exclusions, ["entity_type", "entity_id", "stage", "reason_code", "technical_detail"])
    write_csv(artifacts / "normalized/pilot_packages.csv", selected_packages, ["distribution", "name", "version", "architecture", "source_name", "source_version", "homepage", "canonical_upstream_id", "filename", "artifact_url", "artifact_sha256", "component"])
    atomic_json(artifacts / "normalized/sampling_manifest.json", {
        "candidate_population": len(candidates),
        "selected_projects": len(selected_ids),
        "namespace": config["selection_namespace"],
        "rule": "ascending sha256(namespace + NUL + canonical_upstream_id), then canonical_upstream_id",
        "outcome_inspected_before_selection": False,
    })
    return candidates[: int(config["pilot_size"])], selected_packages


def fetch_pilot_packages(packages: list[dict[str, Any]], artifacts: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for package in packages:
        extension = ".deb" if package["distribution"] in {"debian", "ubuntu"} else (".rpm" if package["distribution"] == "fedora" else ".pkg.tar.zst")
        destination = artifacts / "raw/packages" / package["distribution"] / f"{package['name']}-{package['version'].replace('/', '_')}{extension}"
        record = dict(package)
        try:
            fetched = download(package["artifact_url"], destination, package["artifact_sha256"] or None)
            record.update({"local_path": str(destination), "observed_sha256": fetched["sha256"], "retrieved_at_utc": fetched["retrieved_at_utc"], "fetch_status": "SUCCESS", "extract_status": "PENDING"})
        except Exception as error:
            record.update({"local_path": str(destination), "observed_sha256": "", "fetch_status": "FAILURE", "extract_status": "NOT_ATTEMPTED", "failure": str(error)})
        records.append(record)
        atomic_json(artifacts / "checkpoints/package_fetch.json", records)
    atomic_json(artifacts / "raw/package_artifact_manifest.json", records)
    return records
