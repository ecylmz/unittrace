from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from .io import atomic_json
from .systemd import evaluate_unit, make_minimal_root


def _assessment(rows: list[dict[str, Any]], identifier: str) -> dict[str, Any]:
    return next(row for row in rows if row.get("json_field") == identifier)


def _write_unit(root: Path, name: str = "fixture.service", extra: str = "") -> None:
    make_minimal_root(root)
    (root / "usr/lib/systemd/system" / name).write_text(
        "[Unit]\nDescription=UnitTrace semantic fixture\n[Service]\nExecStart=/usr/bin/true\n" + extra,
        encoding="utf-8",
    )


def run_semantic_fixtures(evaluator: Path, policy: Path, artifacts: Path) -> dict[str, Any]:
    fixture_root = artifacts / "roots/fixtures"
    if fixture_root.exists():
        shutil.rmtree(fixture_root)
    results: dict[str, Any] = {}

    dropin = fixture_root / "dropin"
    _write_unit(dropin, extra="ProtectSystem=full\n")
    directory = dropin / "etc/systemd/system/fixture.service.d"
    directory.mkdir(parents=True)
    (directory / "90-override.conf").write_text("[Service]\nProtectSystem=strict\n", encoding="utf-8")
    status, rows, detail = evaluate_unit(evaluator, policy, dropin, "fixture.service")
    results["drop_in_precedence"] = {"pass": status == "ANALYZABLE" and "strict" in _assessment(rows, "ProtectSystem")["description"], "status": status, "detail": detail, "rows": rows}

    reset = fixture_root / "reset"
    _write_unit(reset, extra="SystemCallFilter=~@clock\n")
    directory = reset / "etc/systemd/system/fixture.service.d"
    directory.mkdir(parents=True)
    (directory / "90-reset.conf").write_text("[Service]\nSystemCallFilter=\nSystemCallFilter=@system-service\n", encoding="utf-8")
    status, rows, detail = evaluate_unit(evaluator, policy, reset, "fixture.service")
    clock = _assessment(rows, "SystemCallFilter_clock") if status == "ANALYZABLE" else {}
    results["directive_reset_semantics"] = {"pass": status == "ANALYZABLE" and bool(clock.get("set")), "status": status, "detail": detail, "rows": rows}

    alias = fixture_root / "alias"
    _write_unit(alias, name="canonical.service", extra="PrivateTmp=yes\n")
    (alias / "usr/lib/systemd/system/alias.service").symlink_to("canonical.service")
    canonical_status, canonical_rows, canonical_detail = evaluate_unit(evaluator, policy, alias, "canonical.service")
    alias_status, alias_rows, alias_detail = evaluate_unit(evaluator, policy, alias, "alias.service")
    results["aliases"] = {"pass": canonical_status == alias_status == "ANALYZABLE" and canonical_rows == alias_rows, "canonical_status": canonical_status, "alias_status": alias_status, "canonical_detail": canonical_detail, "alias_detail": alias_detail, "canonical_rows": canonical_rows, "alias_rows": alias_rows}

    masked = fixture_root / "mask"
    make_minimal_root(masked)
    (masked / "etc/systemd/system/masked.service").symlink_to("/dev/null")
    status, rows, detail = evaluate_unit(evaluator, policy, masked, "masked.service")
    results["masked_units"] = {"pass": status == "ANALYZER_FAILURE" and "masked" in detail.casefold(), "deterministic_classification": "MASKED_EFFECTIVE_UNIT", "status": status, "detail": detail, "rows": rows}

    service_wide = fixture_root / "service-wide"
    _write_unit(service_wide)
    directory = service_wide / "etc/systemd/system/service.d"
    directory.mkdir(parents=True)
    (directory / "50-wide.conf").write_text("[Service]\nPrivateTmp=yes\n", encoding="utf-8")
    status, rows, detail = evaluate_unit(evaluator, policy, service_wide, "fixture.service")
    results["service_wide_dropins"] = {"pass": status == "ANALYZABLE" and _assessment(rows, "PrivateTmp")["set"] is True, "status": status, "detail": detail, "rows": rows}

    effective = fixture_root / "effective"
    _write_unit(effective)
    wide = effective / "etc/systemd/system/service.d"
    specific = effective / "etc/systemd/system/fixture.service.d"
    wide.mkdir(parents=True)
    specific.mkdir(parents=True)
    (wide / "50-wide.conf").write_text("[Service]\nPrivateTmp=no\n", encoding="utf-8")
    (specific / "90-specific.conf").write_text("[Service]\nPrivateTmp=yes\n", encoding="utf-8")
    status, rows, detail = evaluate_unit(evaluator, policy, effective, "fixture.service")
    results["effective_configuration_resolution"] = {"pass": status == "ANALYZABLE" and _assessment(rows, "PrivateTmp")["set"] is True, "status": status, "detail": detail, "rows": rows}

    normalized = {name: {key: value for key, value in result.items() if key != "rows" and not key.endswith("_rows")} for name, result in results.items()}
    normalized["all_pass"] = all(result["pass"] for result in results.values())
    atomic_json(artifacts / "raw/semantic_fixture_output.json", results)
    atomic_json(artifacts / "normalized/semantic_fixture_results.json", normalized)
    return normalized

