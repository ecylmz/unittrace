from unittrace.ancestry import exact_debian_parent_from_changelog


def test_merge_parent_from_authoritative_changelog() -> None:
    changelog = """pkg (2.0-3ubuntu1) resolute; urgency=medium

  * Merge.

pkg (2.0-3) unstable; urgency=medium

  * Debian release.
"""
    assert exact_debian_parent_from_changelog(changelog, "2.0-3ubuntu1") == "2.0-3"


def test_unresolved_parent_is_not_guessed() -> None:
    changelog = "pkg (2.0-3ubuntu1) resolute; urgency=medium\n"
    assert exact_debian_parent_from_changelog(changelog, "2.0-3ubuntu1") is None

