from __future__ import annotations

import configparser
import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .model import DimensionStatus, UArtifactClass


SUBSTITUTION = re.compile(r"(?:@[A-Za-z0-9_.-]+@|\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|__[A-Z][A-Z0-9_]*__|(?<![/A-Za-z0-9_])[A-Z][A-Z0-9_]*DIR(?=/))")
STRUCTURAL_LINE = re.compile(r"^\s*(?:@[A-Za-z0-9_.-]+@|\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*)\s*$")


@dataclass(frozen=True)
class TemplateProjection:
    artifact_class: UArtifactClass
    projected_text: str
    structural_placeholder_count: int
    unresolved_directives: tuple[str, ...]


def project_service_template(text: str) -> TemplateProjection:
    in_service = False
    structural = 0
    unresolved: list[str] = []
    projected: list[str] = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_service = stripped.casefold() == "[service]"
            projected.append(raw_line)
            continue
        if in_service and STRUCTURAL_LINE.match(raw_line):
            structural += 1
            continue
        if in_service and "=" in raw_line and SUBSTITUTION.search(raw_line.split("=", 1)[1]):
            unresolved.append(raw_line.split("=", 1)[0].strip())
            continue
        projected.append(raw_line)
    artifact_class = UArtifactClass.U2_TEMPLATE_STRUCTURAL if structural else UArtifactClass.U1_TEMPLATE_VALUE_ONLY
    return TemplateProjection(artifact_class, "\n".join(projected) + "\n", structural, tuple(unresolved))


def parse_service_assignments(text: str) -> dict[str, list[str]]:
    parser = configparser.RawConfigParser(strict=False, interpolation=None, delimiters=("="), comment_prefixes=("#", ";"))
    parser.optionxform = str
    assignments: dict[str, list[str]] = {}
    in_service = False
    continued = ""
    for raw_line in text.splitlines():
        line = continued + raw_line
        if line.endswith("\\"):
            continued = line[:-1]
            continue
        continued = ""
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            in_service = stripped.casefold() == "[service]"
            continue
        if in_service and "=" in line:
            key, value = line.split("=", 1)
            assignments.setdefault(key.strip(), []).append(value.strip())
    return assignments


def apply_dropins(base: dict[str, list[str]], dropins: list[dict[str, list[str]]], list_directives: set[str]) -> dict[str, list[str]]:
    merged = {key: list(values) for key, values in base.items()}
    for dropin in dropins:
        for key, values in dropin.items():
            if key not in list_directives:
                merged[key] = [values[-1]]
                continue
            for value in values:
                if value == "":
                    merged[key] = []
                else:
                    merged.setdefault(key, []).append(value)
    return merged


def evaluate_unit(evaluator: Path, policy: Path, root: Path, unit_name: str) -> tuple[str, list[dict[str, Any]], str]:
    command = [
        str(evaluator), "security", "--offline=yes", "--json=short", "--no-pager",
        f"--root={root}", f"--security-policy={policy}", unit_name,
    ]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        return "ANALYZER_FAILURE", [], result.stderr.strip()
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        return "ANALYZER_FAILURE", [], f"invalid JSON: {error}: {result.stdout[:200]}"
    return "ANALYZABLE", rows, result.stderr.strip()


def make_minimal_root(root: Path) -> None:
    (root / "usr/lib/systemd/system").mkdir(parents=True, exist_ok=True)
    (root / "etc/systemd/system").mkdir(parents=True, exist_ok=True)
    (root / "usr/bin").mkdir(parents=True, exist_ok=True)
    os_release = root / "etc/os-release"
    if not os_release.exists():
        os_release.write_text("ID=unittrace\nVERSION_ID=phase0r\n", encoding="utf-8")
    true_target = root / "usr/bin/true"
    if not true_target.exists():
        shutil.copy2("/usr/bin/true", true_target)


def assessment_for_directive(assessment_ids: set[str], directive: str) -> set[str]:
    direct = {item for item in assessment_ids if item == directive or item.startswith(directive + "_")}
    aliases = {
        "User": {"UserOrDynamicUser"},
        "DynamicUser": {"UserOrDynamicUser"},
        "RootDirectory": {"RootDirectoryOrRootImage"},
        "RootImage": {"RootDirectoryOrRootImage"},
        "IPAddressAllow": {"IPAddressDeny"},
    }
    return direct | (aliases.get(directive, set()) & assessment_ids)


def template_dimension_statuses(projection: TemplateProjection, assessment_ids: set[str]) -> dict[str, DimensionStatus]:
    explicit = parse_service_assignments(projection.projected_text)
    statuses: dict[str, DimensionStatus] = {}
    for assessment_id in assessment_ids:
        statuses[assessment_id] = (
            DimensionStatus.ABSENCE_UNRESOLVED
            if projection.artifact_class == UArtifactClass.U2_TEMPLATE_STRUCTURAL
            else DimensionStatus.ABSENT_RESOLVED
        )
    for directive in explicit:
        for assessment_id in assessment_for_directive(assessment_ids, directive):
            statuses[assessment_id] = DimensionStatus.PRESENT_RESOLVED
    for directive in projection.unresolved_directives:
        for assessment_id in assessment_for_directive(assessment_ids, directive):
            statuses[assessment_id] = DimensionStatus.VALUE_UNRESOLVED
        # systemd-analyze conditions these assessments on the resolved service
        # identity.  A projected-away User=/DynamicUser= value can therefore
        # change their normalized state even when the directives themselves
        # are absent.  Treat the dependent rows as unresolved instead of
        # evaluating them under the synthetic root-user fallback.
        if directive in {"User", "DynamicUser"}:
            for assessment_id in {"RemoveIPC", "SupplementaryGroups"} & assessment_ids:
                statuses[assessment_id] = DimensionStatus.VALUE_UNRESOLVED
    return statuses
