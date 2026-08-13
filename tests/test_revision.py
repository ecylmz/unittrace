from unittrace.revision import classify_divergence_source, render_u1_with_packaged_substitutions


def test_divergence_source_categories() -> None:
    same = ("a",)
    other = ("b",)
    assert classify_divergence_source(None, same, same, same, same, other) == "UNRESOLVED"
    assert classify_divergence_source(same, other, same, other, same, other) == "UPSTREAM_DIFFERENCE_INHERITED"
    assert classify_divergence_source(same, same, same, other, same, other) == "DOWNSTREAM_INTRODUCED"
    assert classify_divergence_source(same, other, other, other, other, other) == "DOWNSTREAM_CONVERGED"
    assert classify_divergence_source(same, other, other, same, other, same) == "DOWNSTREAM_AMPLIFIED_OR_MODIFIED"
    assert classify_divergence_source(same, same, same, same, same, same) == "NO_FINAL_DIFFERENCE"


def test_u1_render_uses_packaged_values_without_changing_literals() -> None:
    template = "[Service]\nExecStart=@BINDIR@/daemon\nPrivateTmp=yes\n#User=@IGNORED@\n"
    packaged = "[Service]\nExecStart=/usr/bin/daemon --flag\nPrivateTmp=yes\n"
    rendered, missing = render_u1_with_packaged_substitutions(template, packaged)
    assert missing == ()
    assert rendered is not None
    assert "ExecStart=/usr/bin/daemon --flag" in rendered
    assert "PrivateTmp=yes" in rendered
    assert "#User=@IGNORED@" in rendered


def test_u1_render_refuses_missing_substitution() -> None:
    rendered, missing = render_u1_with_packaged_substitutions(
        "[Service]\nExecStart=@BINDIR@/daemon\n", "[Service]\nPrivateTmp=yes\n"
    )
    assert rendered is None
    assert missing == ("ExecStart",)
