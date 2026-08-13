from unittrace.model import EXCLUSION_REASON_CODES, validate_reason_code
from unittrace.protocol import deterministic_order, is_system_service_path, normalize_upstream_url, normalized_exec_lineage


def test_system_service_path() -> None:
    assert is_system_service_path("usr/lib/systemd/system/example.service")
    assert is_system_service_path("lib/systemd/system/example.service.d/hardening.conf")
    assert not is_system_service_path("usr/lib/systemd/user/example.service")


def test_upstream_normalization() -> None:
    assert normalize_upstream_url("git@github.com:example/project.git") == "https://github.com/example/project"
    assert normalize_upstream_url("https://www.github.com/example/project/issues") == "https://github.com/example/project"


def test_selection_deterministic() -> None:
    assert deterministic_order("https://example.org/a", "ns") == deterministic_order("https://example.org/a", "ns")
    assert deterministic_order("https://example.org/a", "ns") != deterministic_order("https://example.org/b", "ns")


def test_exec_lineage() -> None:
    assert normalized_exec_lineage("-@/usr/sbin/exampled --foreground") == "exampled"
    assert normalized_exec_lineage("${DAEMON} --foreground") is None


def test_exclusion_codes_closed() -> None:
    for reason in EXCLUSION_REASON_CODES:
        assert validate_reason_code(reason) == reason

