from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def public_files() -> list[Path]:
    excluded = {".git", ".venv", ".pytest_cache", "__pycache__"}
    return [path for path in ROOT.rglob("*") if path.is_file() and not any(part in excluded for part in path.relative_to(ROOT).parts)]


def test_readme_is_the_only_markdown_file() -> None:
    markdown = sorted(path.relative_to(ROOT).as_posix() for path in public_files() if path.suffix.casefold() == ".md")
    assert markdown == ["README.md"]


def test_private_working_paths_are_absent() -> None:
    forbidden = {"manuscript", "submission_ist", "revision", "release", "reports"}
    assert not any((ROOT / name).exists() for name in forbidden)
    assert not any(path.name.endswith("_REPORT.md") for path in public_files())


def test_third_party_binary_payloads_are_absent() -> None:
    forbidden_suffixes = (".deb", ".rpm", ".iso", ".qcow2", ".vdi", ".vmdk")
    assert not any(path.name.endswith(forbidden_suffixes) for path in public_files())
