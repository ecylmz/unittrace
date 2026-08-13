from __future__ import annotations

import csv
import hashlib
import json
import math
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_repository_boundary() -> None:
    forbidden_directories = ("manuscript", "submission_ist", "revision", "release", "reports")
    require(not any((ROOT / name).exists() for name in forbidden_directories), "private working directory is present")
    markdown = [path for path in ROOT.rglob("*.md") if not any(part.startswith(".") for part in path.relative_to(ROOT).parts)]
    require([path.relative_to(ROOT).as_posix() for path in markdown] == ["README.md"], "README.md must be the only public Markdown file")
    raw_suffixes = (".deb", ".rpm", ".iso", ".qcow2", ".vdi", ".vmdk")
    require(not any(path.name.endswith(raw_suffixes) for path in ROOT.rglob("*") if path.is_file()), "third-party binary payload is present")


def verify_checksums() -> int:
    count = 0
    for line in (ROOT / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        path = ROOT / relative
        require(path.is_file(), f"missing tracked file: {relative}")
        require(sha256(path) == expected, f"checksum mismatch: {relative}")
        count += 1
    return count


def verify_scientific_results() -> None:
    analysis = ROOT / "artifacts/full/analysis"
    headline = json.loads((analysis / "headline_results.json").read_text(encoding="utf-8"))
    require((headline["c1x_projects"], headline["c1x_lineages"]) == (375, 649), "C1X mismatch")
    require((headline["c3x_projects"], headline["c3x_lineages"]) == (237, 418), "C3X mismatch")
    require(headline["cross_family_comparable_union_lineages"] == 645, "RQ2 denominator mismatch")
    require(headline["cross_family_differing_union_lineages"] == 164, "RQ2 numerator mismatch")
    require(math.isclose(headline["cross_family_divergence_rate_union_lineages"], 164 / 645), "RQ2 rate mismatch")

    pipeline = json.loads((analysis / "full_census_pipeline_metrics.json").read_text(encoding="utf-8"))
    modes = [row for row in pipeline["matching_modes"] if row["cohort"] == "WHOLE_PILOT"]
    require(sum(int(row["lineages"]) for row in modes) == 713, "accepted matching mismatch")
    require(next(int(row["lineages"]) for row in modes if row["match_mode"] == "EXACT_UPSTREAM_UNIT_IDENTITY") == 137, "exact matching mismatch")
    require(next(int(row["lineages"]) for row in modes if row["match_mode"] == "UNAMBIGUOUS_EXECUTABLE_LINEAGE") == 576, "executable matching mismatch")

    union = next(csv.DictReader((analysis / "rq2_cross_family_union_summary.csv").open(encoding="utf-8", newline="")))
    require(int(union["projects"]) == 373, "RQ2 project count mismatch")
    require((int(union["differing_union_lineages"]), int(union["comparable_union_lineages"])) == (164, 645), "RQ2 union mismatch")
    require(math.isclose(float(union["ci_low"]), 0.1924, abs_tol=0.00005), "RQ2 lower CI mismatch")
    require(math.isclose(float(union["ci_high"]), 0.3282, abs_tol=0.00005), "RQ2 upper CI mismatch")

    sensitivity = list(csv.DictReader((analysis / "matching_mode_outcome_sensitivity.csv").open(encoding="utf-8", newline="")))
    exact = next(row for row in sensitivity if row["matching_mode"] == "EXACT_UPSTREAM_UNIT_IDENTITY")
    executable = next(row for row in sensitivity if row["matching_mode"] == "UNAMBIGUOUS_EXECUTABLE_LINEAGE")
    require((int(exact["numerator"]), int(exact["denominator"])) == (6, 128), "exact-mode RQ2 mismatch")
    require((int(executable["numerator"]), int(executable["denominator"])) == (158, 517), "executable-mode RQ2 mismatch")

    rates = list(csv.DictReader((analysis / "revision_rq3_grouped_change_rates.csv").open(encoding="utf-8", newline="")))
    overall = next(row for row in rates if row["distribution"] == "ALL")
    require((int(overall["changed"]), int(overall["denominator"])) == (302, 39357), "RQ3 grouped mismatch")
    require(math.isclose(float(overall["ci_low"]), 0.0046, abs_tol=0.00005), "RQ3 lower CI mismatch")
    require(math.isclose(float(overall["ci_high"]), 0.0116, abs_tol=0.00005), "RQ3 upper CI mismatch")

    compressed = json.loads((ROOT / "COMPRESSED_FILES.json").read_text(encoding="utf-8"))
    for record in compressed["files"]:
        require(sha256(ROOT / record["compressed_path"]) == record["compressed_sha256"], "compressed dataset mismatch")

    determinism = json.loads((ROOT / "artifacts/full/manifests/determinism_manifest.json").read_text(encoding="utf-8"))
    require(determinism["byte_equivalent_normalized_outputs"], "normalized outputs are not deterministic")
    require(len(determinism["normalized_targets"]) == 27, "normalized output count is not 27")


def main() -> None:
    verify_repository_boundary()
    count = verify_checksums()
    verify_scientific_results()
    print(f"PASS: {count} files, corrected results, and 27 deterministic normalized outputs verified")


if __name__ == "__main__":
    main()
