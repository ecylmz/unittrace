from __future__ import annotations

import matplotlib.pyplot as plt
from matplotlib.colors import to_rgba

from unittrace.premium_figures import (
    CROSS_FAMILY,
    DERIVATIVE_FAMILY,
    LINK,
    MUTED,
    _validate_text,
    adoption_heatmap,
    attrition_flow,
    divergence_magnitude,
    pairwise_divergence,
    transformation_composition,
    upe_flow,
)


def test_upe_flow_scenarios_and_labels_fit_page() -> None:
    figure, stem, title = upe_flow()
    try:
        assert title == "Why final-state comparison is insufficient"
        assert _validate_text(figure, stem)["passed"]
        labels = {text.get_text() for text in figure.axes[0].texts}
        assert {"U", "P", "E", "Upstream", "Package", "Effective"} <= labels
        assert {
            "A. INHERITED DIFFERENCE",
            "B. DOWNSTREAM-INTRODUCED DIFFERENCE",
            "C. DOWNSTREAM CONVERGENCE",
            "Inherited from upstream",
            "Introduced downstream",
            "Converged downstream",
        } <= labels
        assert len(figure.axes[0].collections) == 20  # 18 scenario states + 2 legend states
        arrows = [text.arrow_patch for text in figure.axes[0].texts if getattr(text, "arrow_patch", None)]
        assert len(arrows) == 12
    finally:
        plt.close(figure)


def test_attrition_flow_labels_fit_nodes_and_page() -> None:
    figure, stem, title = attrition_flow()
    try:
        assert title == "Observed population, matching evidence, and analytical cohorts"
        assert figure._unittrace_node_text_audit["passed"]
        assert figure._unittrace_node_text_audit["node_text_elements_checked"] == 37
        assert _validate_text(figure, stem)["passed"]
        labels = {text.get_text() for text in figure.axes[0].texts}
        assert {"CENSUS", "ELIGIBILITY", "CANDIDATES", "ACQUIRED", "TIER-A", "C1X", "RQ2 SUPPORT", "C3X"} <= labels
        assert {"EXACT IDENTITY", "EXECUTABLE IDENTITY", "UNAVAILABLE MODES", "C1D", "C3F", "C2", "C4"} <= labels
    finally:
        plt.close(figure)


def test_descriptive_figures_have_no_unexplained_focal_highlights() -> None:
    adoption, _, _ = adoption_heatmap()
    pairwise, _, _ = pairwise_divergence()
    magnitude, _, _ = divergence_magnitude()
    transformation, _, _ = transformation_composition()
    try:
        assert len(adoption.axes[0].patches) == 0
        pair_colors = [patch.get_facecolor() for patch in pairwise.axes[0].patches]
        assert len(set(pair_colors[:5])) == 1
        assert pair_colors[5] != pair_colors[0]
        assert pair_colors[0] == to_rgba(CROSS_FAMILY)
        assert pair_colors[5] == to_rgba(DERIVATIVE_FAMILY)
        assert len(magnitude.axes[0].patches) == 15  # three stack segments × five pairs; no outline patch
        panel_a_colors = {patch.get_facecolor() for patch in transformation.axes[0].patches}
        assert panel_a_colors == {to_rgba(CROSS_FAMILY)}
        assert {text.get_text() for text in transformation.axes[1].texts} >= {"53", "68", "89", "92"}
        assert all(not axis.get_title() for axis in transformation.axes)
        assert {text.get_text() for text in transformation.texts} == {"A", "B"}
    finally:
        for figure in (adoption, pairwise, magnitude, transformation):
            plt.close(figure)


def test_pairwise_cross_family_labels_stay_inside_bars() -> None:
    figure, _, _ = pairwise_divergence()
    try:
        figure.canvas.draw()
        renderer = figure.canvas.get_renderer()
        axis = figure.axes[0]
        for bar, label in zip(axis.patches[:5], axis.texts[:5]):
            bar_box = bar.get_window_extent(renderer=renderer)
            label_box = label.get_window_extent(renderer=renderer)
            assert label_box.x0 >= bar_box.x0
            assert label_box.x1 <= bar_box.x1
            assert label_box.y0 >= bar_box.y0
            assert label_box.y1 <= bar_box.y1
    finally:
        plt.close(figure)


def test_flow_diagrams_use_neutral_node_treatment() -> None:
    upe, _, _ = upe_flow()
    attrition, _, _ = attrition_flow()
    try:
        upe_edges = {
            tuple(color)
            for collection in upe.axes[0].collections
            for color in collection.get_edgecolors()
        }
        attrition_edges = {patch.get_edgecolor() for axis in attrition.axes for patch in axis.patches}
        assert upe_edges == {to_rgba(LINK)}
        assert attrition_edges == {to_rgba(MUTED)}
    finally:
        plt.close(upe)
        plt.close(attrition)


def test_flow_diagram_spacing_and_analysis_cohort_hierarchy() -> None:
    upe, _, _ = upe_flow()
    attrition, _, _ = attrition_flow()
    try:
        assert upe.axes[0].get_ylim() == (0.0, 110.0)
        connector_endpoints = {
            text.xy for text in attrition.axes[0].texts
            if hasattr(text, "xy") and text.get_text() == ""
        }
        assert (110, 57) not in connector_endpoints
    finally:
        plt.close(upe)
        plt.close(attrition)
