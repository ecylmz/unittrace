from pathlib import Path
import shutil

import pytest

from unittrace.fixtures import run_semantic_fixtures


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd evaluator unavailable")
def test_pinned_semantic_fixture_suite(tmp_path) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text("{}\n", encoding="utf-8")
    result = run_semantic_fixtures(Path(shutil.which("systemd-analyze")), policy, tmp_path / "artifacts")
    assert result["all_pass"] is True
    assert all(result[name]["pass"] for name in (
        "drop_in_precedence",
        "directive_reset_semantics",
        "aliases",
        "masked_units",
        "service_wide_dropins",
        "effective_configuration_resolution",
    ))
