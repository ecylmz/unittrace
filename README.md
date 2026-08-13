# UnitTrace

UnitTrace measures how systemd service-confinement policy is inherited and changed as software moves from its corresponding upstream source (`U`), through a distribution package evaluated in isolation (`P`), to the effective unit loaded in a clean distribution root (`E`). The frozen x86-64 census covers Debian 13.6, Ubuntu 26.04 LTS, Fedora 44, and the Arch Linux Archive snapshot from 9 August 2026.

## Repository contents

This repository contains the analysis source and tests, frozen configuration, acquisition metadata, normalized U/P/E data, matching and cohort records, derived RQ1–RQ4 results, table data, quantitative figure assets, and determinism manifests. Two large normalized CSV files are stored as deterministic gzip files.

Manuscript sources, journal-submission files, internal revision material, phase reports, and working notes are not part of this repository. Third-party distribution archives, binary packages, source packages, repository mirrors, caches, extracted roots, and virtual-machine images are also excluded. Their identifiers, source locations, snapshot metadata, and integrity hashes are retained in `artifacts/full/acquisition/` so available inputs can be reacquired and checked without redistributing them.

## Install and verify

UnitTrace requires Python 3.12 or later and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --frozen
uv run pytest -q
uv run python scripts/verify_repository.py
```

The test suite expects 49 passing tests. The repository verifier checks the tracked-file boundary, SHA-256 manifest, compressed datasets, corrected headline results, and the 27-output determinism record.

Restore the two compressed normalized datasets before rerunning analysis:

```bash
uv run python scripts/restore_derived_data.py
uv run python scripts/regenerate_outputs.py --analysis
uv run python scripts/regenerate_outputs.py --figures
```

A complete census from raw inputs requires reacquisition of the non-redistributed third-party artifacts. Later downloads must match the recorded hashes before use; unavailable historical inputs cannot be reconstructed from filenames alone.

## Expected results

A successful verification yields:

- 713 accepted lineages: 137 by exact-artifact identity and 576 by executable identity;
- C1X: 375 projects and 649 lineages;
- comparable RQ2 union: 373 projects and 645 lineages;
- RQ2 binary union: 164/645 = 25.43%, with a project-cluster 95% CI of 19.24%–32.82%;
- exact-mode RQ2: 6/128 = 4.69%;
- executable-mode RQ2: 158/517 = 30.56%;
- C3X: 237 projects and 418 lineages; and
- grouped U→P changes: 302/39,357 = 0.77%, with a project-cluster 95% CI of 0.46%–1.16%.

Matching-mode differences are construct sensitivity, not causal effects. Among attributable cases, inherited differences outnumber downstream-introduced differences in four cross-family pairs; Fedora/Arch is the exception. Most final differences remain unattributed.

## Third-party material

The original licenses for third-party software remain with their projects and distributions. UnitTrace publishes acquisition metadata and integrity hashes, not third-party payloads. The included normalized and derived datasets are UnitTrace research outputs.
