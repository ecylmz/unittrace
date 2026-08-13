from pathlib import Path

from unittrace.model import DimensionStatus, UArtifactClass
from unittrace.systemd import apply_dropins, parse_service_assignments, project_service_template, template_dimension_statuses


def test_service_parser_repeated_assignments() -> None:
    parsed = parse_service_assignments("[Service]\nCapabilityBoundingSet=CAP_A\nCapabilityBoundingSet=CAP_B\n")
    assert parsed["CapabilityBoundingSet"] == ["CAP_A", "CAP_B"]


def test_value_only_projection() -> None:
    projection = project_service_template("[Service]\nPrivateTmp=yes\nUser=@USER@\n")
    assert projection.artifact_class == UArtifactClass.U1_TEMPLATE_VALUE_ONLY
    assert projection.unresolved_directives == ("User",)
    statuses = template_dimension_statuses(projection, {"PrivateTmp", "UserOrDynamicUser", "ProtectSystem"})
    assert statuses["PrivateTmp"] == DimensionStatus.PRESENT_RESOLVED
    assert statuses["UserOrDynamicUser"] == DimensionStatus.VALUE_UNRESOLVED
    assert statuses["ProtectSystem"] == DimensionStatus.ABSENT_RESOLVED


def test_unresolved_user_masks_context_dependent_assessments() -> None:
    projection = project_service_template("[Service]\nUser=@USER@\nExecStart=/usr/bin/daemon\n")
    statuses = template_dimension_statuses(
        projection,
        {"UserOrDynamicUser", "RemoveIPC", "SupplementaryGroups", "PrivateTmp"},
    )
    assert statuses["UserOrDynamicUser"] == DimensionStatus.VALUE_UNRESOLVED
    assert statuses["RemoveIPC"] == DimensionStatus.VALUE_UNRESOLVED
    assert statuses["SupplementaryGroups"] == DimensionStatus.VALUE_UNRESOLVED
    assert statuses["PrivateTmp"] == DimensionStatus.ABSENT_RESOLVED


def test_structural_template_uncertainty() -> None:
    projection = project_service_template("[Service]\nPrivateTmp=yes\n@HARDENING@\n")
    assert projection.artifact_class == UArtifactClass.U2_TEMPLATE_STRUCTURAL
    statuses = template_dimension_statuses(projection, {"PrivateTmp", "ProtectSystem"})
    assert statuses["PrivateTmp"] == DimensionStatus.PRESENT_RESOLVED
    assert statuses["ProtectSystem"] == DimensionStatus.ABSENCE_UNRESOLVED


def test_equivalent_template_placeholders() -> None:
    projection = project_service_template("[Service]\nExecStart=__INSTALLDIR__/bin/tool\nProtectSystem=strict\n")
    assert projection.artifact_class == UArtifactClass.U1_TEMPLATE_VALUE_ONLY
    assert projection.unresolved_directives == ("ExecStart",)


def test_reset_semantics() -> None:
    base = {"SystemCallFilter": ["@system-service"]}
    dropins = [{"SystemCallFilter": ["", "@basic-io"]}]
    assert apply_dropins(base, dropins, {"SystemCallFilter"})["SystemCallFilter"] == ["@basic-io"]


def test_dropin_precedence() -> None:
    base = {"ProtectSystem": ["full"]}
    dropins = [{"ProtectSystem": ["strict"]}, {"ProtectSystem": ["yes"]}]
    assert apply_dropins(base, dropins, set())["ProtectSystem"] == ["yes"]
