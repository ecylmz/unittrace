from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class UArtifactClass(StrEnum):
    U0_STATIC = "U0_STATIC"
    U1_TEMPLATE_VALUE_ONLY = "U1_TEMPLATE_VALUE_ONLY"
    U2_TEMPLATE_STRUCTURAL = "U2_TEMPLATE_STRUCTURAL"
    U3_GENERATED_DETERMINISTIC = "U3_GENERATED_DETERMINISTIC"
    U4_NO_UPSTREAM_STATIC_OR_TEMPLATE_UNIT = "U4_NO_UPSTREAM_STATIC_OR_TEMPLATE_UNIT"
    U5_AMBIGUOUS_OR_UNRESOLVED = "U5_AMBIGUOUS_OR_UNRESOLVED"


class DimensionStatus(StrEnum):
    PRESENT_RESOLVED = "PRESENT_RESOLVED"
    ABSENT_RESOLVED = "ABSENT_RESOLVED"
    VALUE_UNRESOLVED = "VALUE_UNRESOLVED"
    ABSENCE_UNRESOLVED = "ABSENCE_UNRESOLVED"


class DerivationMode(StrEnum):
    SYNC = "SYNC"
    MERGE_WITH_DELTA = "MERGE_WITH_DELTA"
    DERIVATION_UNRESOLVED = "DERIVATION_UNRESOLVED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class GateStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNRESOLVED = "UNRESOLVED"


EXCLUSION_REASON_CODES = frozenset(
    {
        "PACKAGE_ABSENT",
        "USER_UNIT",
        "THIRD_PARTY_REPOSITORY",
        "LOCAL_ADMIN_OVERRIDE",
        "RUNTIME_GENERATED_UNIT",
        "RUNTIME_ONLY_INSTANCE",
        "AMBIGUOUS_UPSTREAM",
        "SERVICE_LINEAGE_AMBIGUOUS",
        "UPSTREAM_UNRESOLVED",
        "UPSTREAM_BASELINE_UNRESOLVED",
        "U1_VALUE_UNRESOLVED",
        "U2_ABSENCE_UNRESOLVED",
        "U3_GENERATION_FAILURE",
        "U4_NO_UPSTREAM_UNIT",
        "U5_AMBIGUOUS_OR_UNRESOLVED",
        "MASKED_EFFECTIVE_UNIT",
        "ANALYZER_FAILURE",
        "DEBIAN_ANCESTOR_UNRESOLVED",
        "NOT_APPLICABLE",
        "ARTIFACT_FETCH_FAILURE",
        "ARTIFACT_HASH_MISMATCH",
        "ARTIFACT_EXTRACTION_FAILURE",
        "SOURCE_FETCH_FAILURE",
        "PACKAGE_METADATA_INCOMPLETE",
        "NO_SYSTEM_SERVICE",
        "NO_AUTHORITATIVE_UPSTREAM_URL",
        "NO_TIER_A_PARTNER",
        "DUPLICATE_ALIAS",
        "UNSUPPORTED_ARCHIVE_FORMAT",
    }
)


@dataclass(frozen=True)
class GateResult:
    gate_id: str
    metric_name: str
    numerator: int | float | None
    denominator: int | float | None
    value: float | None
    threshold: str
    status: GateStatus
    evidence_artifact: str

    def to_dict(self) -> dict[str, Any]:
        row = asdict(self)
        row["status"] = self.status.value
        return row


def validate_reason_code(reason_code: str) -> str:
    if reason_code not in EXCLUSION_REASON_CODES:
        raise ValueError(f"unknown exclusion reason code: {reason_code}")
    return reason_code

