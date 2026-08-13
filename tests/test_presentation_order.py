from unittrace.analysis import PRESENTATION_PAIR_ORDER, presentation_order_pair_rows


def test_pair_rows_use_primary_then_derivative_order() -> None:
    rows = [
        {"pair": "Debian ↔ Ubuntu", "value": 0},
        {"pair": "Fedora ↔ Arch", "value": 1},
        {"pair": "Debian ↔ Arch", "value": 2},
        {"pair": "Debian ↔ Fedora", "value": 3},
        {"pair": "Ubuntu ↔ Arch", "value": 4},
        {"pair": "Ubuntu ↔ Fedora", "value": 5},
    ]
    assert [row["pair"] for row in presentation_order_pair_rows(rows)] == list(PRESENTATION_PAIR_ORDER)


def test_pair_order_is_applied_within_robustness_groups() -> None:
    rows = [
        {"analysis": "A", "pair": "Debian ↔ Ubuntu"},
        {"analysis": "A", "pair": "Debian ↔ Fedora"},
        {"analysis": "B", "pair": "Fedora ↔ Arch"},
        {"analysis": "B", "pair": "Debian ↔ Arch"},
    ]
    ordered = presentation_order_pair_rows(rows)
    assert [(row["analysis"], row["pair"]) for row in ordered] == [
        ("A", "Debian ↔ Fedora"),
        ("A", "Debian ↔ Ubuntu"),
        ("B", "Debian ↔ Arch"),
        ("B", "Fedora ↔ Arch"),
    ]
