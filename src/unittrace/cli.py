from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .io import atomic_json, read_json, sha256_file
from .ancestry import resolve_ubuntu_ancestry
from .fixtures import run_semantic_fixtures
from .pipeline import analyze_states, cross_distribution_transformations, extract_pilot_packages, match_lineages, prepare_distribution_bases
from .reporting import derive_metrics, write_cohorts, write_complete_exclusions, write_determinism_manifest, write_distribution_snapshots, write_report
from .repositories import enumerate_all, fetch_pilot_packages, select_pilot
from .sources import evaluate_upstream, extract_pristine_sources, fetch_arch_sources, fetch_deb_sources, fetch_fedora_sources, resolve_upstream_artifacts


ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "artifacts"


def _command(command: list[str]) -> str | None:
    try:
        return subprocess.run(command, text=True, capture_output=True, check=True).stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


def _first_line(command: list[str]) -> str | None:
    value = _command(command)
    return value.splitlines()[0] if value else None


def load_config() -> dict[str, Any]:
    return read_json(ROOT / "config/phase0r.json")


def freeze() -> None:
    config = load_config()
    ARTIFACTS.mkdir(exist_ok=True)
    protocol = ROOT / "unittrace_article_spec_v4_1.md"
    evaluator = Path(config["evaluator"]["path"])
    observed_digest = sha256_file(evaluator)
    if observed_digest != config["evaluator"]["sha256"]:
        raise RuntimeError(f"pinned evaluator mismatch: {observed_digest}")
    memory_kib = None
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemTotal:"):
            memory_kib = int(line.split()[1])
    ldd_output = _command(["ldd", str(evaluator)]) or ""
    library_paths: list[Path] = []
    for line in ldd_output.splitlines():
        tokens = line.replace("=>", " ").split()
        library_paths.extend(Path(token) for token in tokens if token.startswith("/") and Path(token).is_file())
    evaluator_files = [{"path": str(path), "sha256": sha256_file(path)} for path in sorted(set([evaluator, *library_paths]))]
    bundle_material = json.dumps(evaluator_files, sort_keys=True, separators=(",", ":")).encode()
    evaluator_bundle_digest = hashlib.sha256(bundle_material).hexdigest()
    atomic_json(ARTIFACTS / "evaluator_runtime_manifest.json", {"version": config["evaluator"]["version"], "binary_sha256": observed_digest, "bundle_sha256": evaluator_bundle_digest, "files": evaluator_files, "ldd_output": ldd_output})
    environment = {
        "environment_id": config["phase0_run_id"],
        "host_platform": "Proxmox VE (requested infrastructure; host API unavailable inside VM)",
        "host_architecture": None,
        "proxmox_version": None,
        "vm_machine_type": _command(["cat", "/sys/class/dmi/id/product_name"]),
        "vm_cpu_model": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), None),
        "vm_vcpu_count": os.cpu_count(),
        "vm_memory_mb": memory_kib // 1024 if memory_kib else None,
        "vm_storage_controller": "virtio/SCSI details unavailable; guest exposes QEMU HARDDISK /dev/sda",
        "vm_os_release": _command(["sh", "-c", ". /etc/os-release; printf '%s %s' \"$NAME\" \"$VERSION\""]),
        "vm_architecture": platform.machine(),
        "vm_image_digest": None,
        "vm_snapshot_identifier": None,
        "kernel_version": platform.release(),
        "python_version": platform.python_version(),
        "systemd_version": _first_line(["systemd-analyze", "--version"]),
        "evaluator_version": config["evaluator"]["version"],
        "evaluator_digest": observed_digest,
        "evaluator_bundle_digest": evaluator_bundle_digest,
        "security_policy_hash": sha256_file(ROOT / config["evaluator"]["policy"]),
        "virtualization_mode": _command(["systemd-detect-virt"]),
        "filesystem": _command(["df", "-PT", str(ROOT)]),
        "block_devices": _command(["lsblk", "-o", "NAME,TYPE,FSTYPE,SIZE,MOUNTPOINTS,MODEL"]),
        "package_managers": {
            "apt": _first_line(["apt", "--version"]),
            "dpkg": _first_line(["dpkg", "--version"]),
            "rpm": None,
            "dnf": None,
            "pacman": None,
            "adapter_note": "Fedora and Arch use repository-format adapters; native target package managers are not installed or used as comparative evaluators."
        },
        "unavailable_fields_reason": "Proxmox host metadata, VM config, image digest, and snapshot identifier are not exposed to the unprivileged guest and were not guessed."
    }
    atomic_json(ARTIFACTS / "execution_environment.json", environment)
    atomic_json(ARTIFACTS / "protocol_freeze.json", {
        "authoritative_protocol": protocol.name,
        "sha256": sha256_file(protocol),
        "bytes": protocol.stat().st_size,
        "lines": len(protocol.read_text(encoding="utf-8").splitlines()),
        "interpretations": read_json(ROOT / "config/protocol-freeze.json")["frozen_interpretations"],
    })


def enumerate_repositories() -> None:
    config = load_config()
    packages, _ = enumerate_all(config, ARTIFACTS)
    select_pilot(packages, config, ARTIFACTS)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def fetch() -> None:
    fetch_pilot_packages(_read_csv(ARTIFACTS / "normalized/pilot_packages.csv"), ARTIFACTS)


def analyze() -> None:
    config = load_config()
    evaluator = Path(config["evaluator"]["path"])
    policy = ROOT / config["evaluator"]["policy"]
    fixture_results = run_semantic_fixtures(evaluator, policy, ARTIFACTS)
    fetch_manifest = read_json(ARTIFACTS / "raw/package_artifact_manifest.json")
    manifest, units = extract_pilot_packages(fetch_manifest, ARTIFACTS)
    pilot_packages = _read_csv(ARTIFACTS / "normalized/pilot_packages.csv")
    source_records = fetch_deb_sources(config, pilot_packages, ARTIFACTS)
    source_records.extend(fetch_fedora_sources(config, pilot_packages, ARTIFACTS))
    source_records.extend(fetch_arch_sources(config, pilot_packages, ARTIFACTS))
    atomic_json(ARTIFACTS / "raw/source_artifact_manifest.json", source_records)
    inventories = extract_pristine_sources(source_records, ARTIFACTS)
    lineages = match_lineages(units, ARTIFACTS, inventories, pilot_packages)
    prepare_distribution_bases(_read_csv(ARTIFACTS / "normalized/repository_packages.csv"), ARTIFACTS)
    states = analyze_states(lineages, units, evaluator, policy, ARTIFACTS)
    upstream = resolve_upstream_artifacts(lineages, inventories, ARTIFACTS)
    states, upstream_transformations = evaluate_upstream(upstream, states, evaluator, policy, ARTIFACTS)
    transformations = cross_distribution_transformations(states, ARTIFACTS) + upstream_transformations
    from .io import write_csv
    write_csv(ARTIFACTS / "normalized/transformations.csv", transformations, ["lineage_id", "distribution", "transition", "assessment_id", "semantic_category", "provenance_category", "exposure_delta", "source_resolved", "destination_resolved"])
    derivations = resolve_ubuntu_ancestry(lineages, pilot_packages, states, source_records, ARTIFACTS)
    metrics, gates, decision, rq3d = derive_metrics(manifest, lineages, states, upstream, transformations, derivations, bool(fixture_results["all_pass"]), ARTIFACTS)
    write_cohorts(lineages, states, upstream, derivations, ARTIFACTS)
    write_distribution_snapshots(config, ARTIFACTS)
    write_complete_exclusions(manifest, lineages, states, upstream, derivations, ARTIFACTS)
    write_determinism_manifest(ARTIFACTS)
    write_report(metrics, gates, decision, rq3d, manifest, lineages, states, upstream, transformations, derivations, ARTIFACTS, ROOT / "PHASE0_REPORT.md")


def main() -> None:
    parser = argparse.ArgumentParser(description="UnitTrace Phase 0R pipeline")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("freeze", "enumerate", "fetch", "analyze"):
        subparsers.add_parser(name)
    subparsers.add_parser("run")
    arguments = parser.parse_args()
    if arguments.command in {"freeze", "run"}:
        freeze()
    if arguments.command in {"enumerate", "run"}:
        enumerate_repositories()
    if arguments.command in {"fetch", "run"}:
        fetch()
    if arguments.command in {"analyze", "run"}:
        analyze()


if __name__ == "__main__":
    main()
