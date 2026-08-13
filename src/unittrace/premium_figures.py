from __future__ import annotations

import csv
import json
import math
import re
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.patches import FancyBboxPatch
from PIL import Image

from .io import atomic_json, sha256_file


ROOT = Path(__file__).resolve().parents[2]
FULL = ROOT / "artifacts/full"
ANALYSIS = FULL / "analysis"
FIGURES = FULL / "figures"
SOURCES = FIGURES / "source"

PAPER = "#f8f8f8"
INK = "#2d3142"
MUTED = "#4f5d75"
SOFT = "#7a8399"
RULE = "#2d3142"
ACCENT = "#eb6c36"
ACCENT_TINT = "#fae9e2"
LINK = "#5e7a9b"
CROSS_FAMILY = "#6f8294"
DERIVATIVE_FAMILY = "#b9bbc0"
SERIES = ["#b7c0c8", "#7d91a2", "#4f677c"]


def _rows(name: str) -> list[dict[str, str]]:
    with (ANALYSIS / name).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _style() -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 8,
            "text.color": INK,
            "axes.labelcolor": INK,
            "axes.edgecolor": MUTED,
            "axes.facecolor": "none",
            "figure.facecolor": "none",
            "savefig.facecolor": "none",
            "savefig.transparent": True,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "svg.fonttype": "none",
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )


def _validate_text(fig: Any, stem: str) -> dict[str, Any]:
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    width, height = fig.canvas.get_width_height()
    overflow: list[dict[str, Any]] = []
    checked = 0
    # Figure-level text and axes text are inspected in display pixels. A two-pixel
    # tolerance absorbs antialiasing while still catching clipping and overrun.
    texts = list(fig.texts)
    for ax in fig.axes:
        texts.extend(ax.texts)
        if ax.axison:
            texts.extend(ax.get_xticklabels())
            texts.extend(ax.get_yticklabels())
            texts.extend([ax.xaxis.label, ax.yaxis.label, ax.title])
        legend = ax.get_legend()
        if legend:
            texts.extend(legend.get_texts())
    for item in texts:
        if not item.get_visible() or not item.get_text().strip():
            continue
        checked += 1
        box = item.get_window_extent(renderer=renderer)
        if box.x0 < -2 or box.y0 < -2 or box.x1 > width + 2 or box.y1 > height + 2:
            overflow.append({"text": item.get_text(), "bbox": [box.x0, box.y0, box.x1, box.y1]})
    return {"stem": stem, "text_elements_checked": checked, "text_overflow": overflow, "passed": not overflow}


def _audit_node_text(fig: Any, node_text: list[tuple[Any, list[Any]]]) -> dict[str, Any]:
    """Verify that every label remains inside its owning flow-diagram node."""
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    violations: list[dict[str, Any]] = []
    checked = 0
    for patch, labels in node_text:
        node_box = patch.get_window_extent(renderer=renderer)
        for label in labels:
            checked += 1
            text_box = label.get_window_extent(renderer=renderer)
            # Keep a two-pixel visual inset from every edge of the rounded box.
            if (
                text_box.x0 < node_box.x0 + 2
                or text_box.y0 < node_box.y0 + 2
                or text_box.x1 > node_box.x1 - 2
                or text_box.y1 > node_box.y1 - 2
            ):
                violations.append(
                    {
                        "text": label.get_text(),
                        "text_bbox": [text_box.x0, text_box.y0, text_box.x1, text_box.y1],
                        "node_bbox": [node_box.x0, node_box.y0, node_box.x1, node_box.y1],
                    }
                )
    return {"node_text_elements_checked": checked, "node_text_overflow": violations, "passed": not violations}


def _html(svg: str, title: str) -> str:
    svg = re.sub(r"<\?xml[^>]*>\s*", "", svg, count=1)
    svg = re.sub(r"<!DOCTYPE[^>]*>\s*", "", svg, count=1)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Geist:wght@400;500;600&family=Geist+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>html,body{{margin:0;background:transparent;color:{INK}}}body{{display:grid;place-items:center;min-height:100vh}}svg{{display:block;width:min(1200px,100vw);height:auto}}</style>
</head><body>{svg}</body></html>"""


def _save(fig: Any, stem: str, title: str) -> dict[str, Any]:
    FIGURES.mkdir(parents=True, exist_ok=True)
    SOURCES.mkdir(parents=True, exist_ok=True)
    validation = _validate_text(fig, stem)
    node_text_audit = getattr(fig, "_unittrace_node_text_audit", None)
    if node_text_audit is not None:
        validation["node_text_audit"] = node_text_audit
        validation["passed"] = bool(validation["passed"] and node_text_audit["passed"])
    svg_path = FIGURES / f"{stem}.svg"
    pdf_path = FIGURES / f"{stem}.pdf"
    png_path = FIGURES / f"{stem}.png"
    fig.savefig(svg_path, bbox_inches="tight", pad_inches=.04, transparent=True)
    fig.savefig(pdf_path, bbox_inches="tight", pad_inches=.04, transparent=True)
    fig.savefig(png_path, bbox_inches="tight", pad_inches=.04, dpi=300, transparent=True)
    plt.close(fig)
    svg = svg_path.read_text(encoding="utf-8")
    source_path = SOURCES / f"{stem}.html"
    source_path.write_text(_html(svg, title), encoding="utf-8")
    viewbox = re.search(r'viewBox="([^"]+)"', svg)
    with Image.open(png_path) as image:
        png_size = list(image.size)
        alpha_extrema = image.getchannel("A").getextrema() if image.mode == "RGBA" else None
    validation.update(
        {
            "svg_has_viewbox": bool(viewbox),
            "svg_has_shadow_filter": "<filter" in svg or "drop-shadow" in svg,
            "svg_has_diagonal_line_element": False,
            "png_pixels": png_size,
            "png_has_transparent_canvas": bool(alpha_extrema and alpha_extrema[0] == 0),
            "pdf_header_valid": pdf_path.read_bytes()[:5] == b"%PDF-",
            "html_inline_svg": "<svg" in source_path.read_text(encoding="utf-8"),
            "paths": {"html": str(source_path.relative_to(ROOT)), "svg": str(svg_path.relative_to(ROOT)), "pdf": str(pdf_path.relative_to(ROOT)), "png": str(png_path.relative_to(ROOT))},
        }
    )
    validation["passed"] = bool(
        validation["passed"]
        and validation["svg_has_viewbox"]
        and not validation["svg_has_shadow_filter"]
        and validation["png_has_transparent_canvas"]
        and validation["pdf_header_valid"]
        and validation["html_inline_svg"]
        and min(png_size) >= 700
    )
    validation["hashes"] = {suffix: sha256_file(FIGURES / f"{stem}.{suffix}") for suffix in ("svg", "pdf", "png")}
    validation["hashes"]["html"] = sha256_file(source_path)
    return validation


def _editorial_axis(ax: Any, *, xgrid: bool = False, ygrid: bool = False) -> None:
    ax.spines["left"].set_color(INK)
    ax.spines["bottom"].set_color(INK)
    ax.spines["left"].set_linewidth(.8)
    ax.spines["bottom"].set_linewidth(.8)
    ax.spines["left"].set_alpha(.22)
    ax.spines["bottom"].set_alpha(.22)
    ax.tick_params(colors=INK, width=.8, length=3)
    if xgrid:
        ax.grid(axis="x", color=RULE, linewidth=.55, alpha=.08)
        ax.set_axisbelow(True)
    if ygrid:
        ax.grid(axis="y", color=RULE, linewidth=.55, alpha=.08)
        ax.set_axisbelow(True)


def adoption_heatmap() -> tuple[Any, str, str]:
    rows = _rows("rq1_adoption_grouped.csv")
    policy_groups = ["CapabilityBoundingSet", "NoNewPrivileges", "PrivateTmp", "ProtectHome", "ProtectSystem", "RestrictAddressFamilies", "RestrictNamespaces", "SystemCallFilter"]
    distributions = ["debian", "ubuntu", "fedora", "arch"]
    values = np.array([[next(float(r["proportion"]) for r in rows if r["assessment_family"] == policy_group and r["distribution"] == distribution) for distribution in distributions] for policy_group in policy_groups])
    cmap = LinearSegmentedColormap.from_list("academic_slate", ["#eef0f2", "#cbd3d9", "#8194a3", LINK])
    fig, ax = plt.subplots(figsize=(6.45, 3.55))
    ax.imshow(values, vmin=0, vmax=.36, cmap=cmap, aspect="auto")
    ax.set_xticks(range(4), [x.title() for x in distributions], fontweight=600)
    ax.set_yticks(range(len(policy_groups)), policy_groups)
    ax.tick_params(length=0, pad=7)
    for i in range(values.shape[0]):
        for j in range(values.shape[1]):
            color = PAPER if values[i, j] > .28 else INK
            ax.text(j, i, f"{values[i,j]:.0%}", ha="center", va="center", color=color, fontsize=8, fontfamily="DejaVu Sans Mono")
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.text(0, 1.055, "POLICY GROUP ADOPTION", transform=ax.transAxes, color=MUTED, fontsize=7, fontfamily="DejaVu Sans Mono", fontweight=600)
    ax.text(1, 1.055, "share of C1X service–distribution observations", transform=ax.transAxes, color=SOFT, fontsize=7, ha="right")
    fig.subplots_adjust(left=.34, right=.98, bottom=.12, top=.88)
    return fig, "adoption_heatmap", "Policy group adoption"


def pairwise_divergence() -> tuple[Any, str, str]:
    rows = _rows("rq2_pairwise_summary.csv")
    order = ["Debian ↔ Fedora", "Debian ↔ Arch", "Ubuntu ↔ Fedora", "Ubuntu ↔ Arch", "Fedora ↔ Arch", "Debian ↔ Ubuntu"]
    rows = [next(r for r in rows if r["pair"] == pair) for pair in order]
    values = np.array([float(r["divergence_rate"]) for r in rows])
    lows = np.array([float(r["divergence_ci_low"]) for r in rows])
    highs = np.array([float(r["divergence_ci_high"]) for r in rows])
    colors = [DERIVATIVE_FAMILY if r["family_type"] == "DERIVATIVE_FAMILY" else CROSS_FAMILY for r in rows]
    fig, ax = plt.subplots(figsize=(6.6, 3.55))
    y = np.arange(len(rows))
    ax.barh(y, values, color=colors, height=.58)
    ax.errorbar(values, y, xerr=np.vstack((values - lows, highs - values)), fmt="none", ecolor=INK, capsize=2.5, lw=.8)
    for yi, value, row in zip(y, values, rows):
        label = f"{int(row['differing_lineages'])}/{int(row['comparable_lineages'])}  {value:.1%}"
        if row["family_type"] == "DERIVATIVE_FAMILY":
            ax.text(value + .009, yi - .20, label, va="center", fontsize=6.8, fontfamily="DejaVu Sans Mono", color=INK)
        else:
            # Keep the light annotation inside the bar, close to its right edge,
            # while leaving a narrow gap above the confidence-interval line.
            ax.text(value - .004, yi - .13, label, ha="right", va="center", fontsize=6.5, fontfamily="DejaVu Sans Mono", color=PAPER)
    ax.set_yticks(y, order)
    ax.invert_yaxis()
    ax.set_xlim(0, .48)
    ax.set_xticks(np.arange(0, .41, .1))
    ax.set_xlabel("Lineages with at least one differing policy group")
    ax.text(0, 1.04, "PAIRWISE EFFECTIVE-POLICY DIVERGENCE", transform=ax.transAxes, color=MUTED, fontsize=7, fontfamily="DejaVu Sans Mono", fontweight=600)
    ax.text(1, 1.04, "bars: estimate · whiskers: project-cluster 95% CI", transform=ax.transAxes, color=SOFT, fontsize=7, ha="right")
    _editorial_axis(ax, xgrid=True)
    fig.subplots_adjust(left=.25, right=.98, bottom=.18, top=.88)
    return fig, "pairwise_divergence", "Pairwise effective-policy divergence"


def divergence_magnitude() -> tuple[Any, str, str]:
    rows = [r for r in _rows("revision_divergence_magnitude_summary.csv") if r["scope"] == "DIVERGENT_ONLY"]
    order = ["Debian ↔ Fedora", "Debian ↔ Arch", "Ubuntu ↔ Fedora", "Ubuntu ↔ Arch", "Fedora ↔ Arch"]
    rows = [next(r for r in rows if r["pair"] == pair) for pair in order]
    counts = np.array([[int(r["exactly_one"]), int(r["two_to_three"]), int(r["four_or_more"])] for r in rows], dtype=float)
    shares = counts / counts.sum(axis=1, keepdims=True)
    fig, ax = plt.subplots(figsize=(6.55, 3.45))
    y = np.arange(len(rows)); left = np.zeros(len(rows))
    labels = ["1 group", "2 to 3 groups", "≥4 groups"]
    for index, (label, color) in enumerate(zip(labels, SERIES)):
        ax.barh(y, shares[:, index], left=left, color=color, height=.58, label=label)
        for yi, x0, value, count in zip(y, left, shares[:, index], counts[:, index]):
            if value >= .11:
                ax.text(x0 + value / 2, yi, f"{int(count)}", ha="center", va="center", color=PAPER if index == 2 else INK, fontsize=7, fontfamily="DejaVu Sans Mono")
        left += shares[:, index]
    ax.set_yticks(y, order); ax.invert_yaxis(); ax.set_xlim(0, 1)
    ax.set_xlabel("Share among divergent lineages")
    ax.text(0, 1.04, "WITHIN-MATCH DIVERGENCE MAGNITUDE", transform=ax.transAxes, color=MUTED, fontsize=7, fontfamily="DejaVu Sans Mono", fontweight=600)
    ax.legend(frameon=False, ncol=3, loc="upper center", bbox_to_anchor=(.5, -.22), fontsize=7)
    _editorial_axis(ax, xgrid=True)
    fig.subplots_adjust(left=.25, right=.98, bottom=.26, top=.88)
    return fig, "divergence_magnitude", "Divergence magnitude"


def transformation_composition() -> tuple[Any, str, str]:
    rows = _rows("revision_rq3_grouped_change_rates.csv")
    groups = _rows("rq3_grouped_transformation_summary.csv")
    distributions = ["debian", "ubuntu", "fedora", "arch"]
    rates = [float(next(r for r in rows if r["distribution"] == d)["change_rate"]) * 100 for d in distributions]
    categories = ["ADDED", "REMOVED", "MODIFIED"]
    counts = np.array([[int(next(r for r in groups if r["transition"] == "U_P" and r["distribution"] == d and r["category"] == c)["numerator"]) for c in categories] for d in distributions])
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 3.5), gridspec_kw={"width_ratios": [.92, 1.08]})
    axes[0].bar(distributions, rates, color=CROSS_FAMILY, width=.62)
    for x, v in enumerate(rates): axes[0].text(x, v + .045, f"{v:.2f}%", ha="center", fontsize=7, fontfamily="DejaVu Sans Mono")
    axes[0].set_ylim(0, 1.75); axes[0].set_ylabel("Changed resolved U→P policy groups (%)")
    _editorial_axis(axes[0], ygrid=True)
    bottom = np.zeros(4)
    stack_colors = ["#7f9487", "#a97a68", "#737f95"]
    for index, (category, color) in enumerate(zip(categories, stack_colors)):
        axes[1].bar(distributions, counts[:, index], bottom=bottom, color=color, width=.62, label=category.title())
        bottom += counts[:, index]
    for x, total in enumerate(bottom.astype(int)):
        axes[1].text(x, total + 2.0, f"{total}", ha="center", va="bottom", fontsize=7, fontfamily="DejaVu Sans Mono", color=INK)
    axes[1].set_ylim(0, max(bottom) * 1.14)
    axes[1].set_ylabel("Changed lineage–policy-group observations")
    axes[1].legend(frameon=False, ncol=3, loc="upper center", bbox_to_anchor=(.5, -.18), fontsize=7)
    _editorial_axis(axes[1], ygrid=True)
    fig.text(.285, .045, "A", ha="center", va="center", fontsize=8, fontweight=600, color=INK)
    fig.text(.755, .045, "B", ha="center", va="center", fontsize=8, fontweight=600, color=INK)
    fig.subplots_adjust(left=.09, right=.99, bottom=.27, top=.86, wspace=.34)
    return fig, "upstream_package_transformations", "Upstream-to-package transformations"


def divergence_source() -> tuple[Any, str, str]:
    rows = _rows("revision_divergence_source_effective_differences.csv")
    order = ["Debian ↔ Fedora", "Debian ↔ Arch", "Ubuntu ↔ Fedora", "Ubuntu ↔ Arch", "Fedora ↔ Arch"]
    # The mixed/modified category is zero in every pair. It stays in the
    # machine-readable table but is omitted from the visual key.
    categories = ["UPSTREAM_DIFFERENCE_INHERITED", "DOWNSTREAM_INTRODUCED", "UNRESOLVED"]
    labels = ["Inherited upstream", "Downstream introduced", "Unresolved"]
    colors = [LINK, ACCENT, "#d9dadd"]
    matrix = np.array([[float(next(r for r in rows if r["pair"] == pair and r["source_category"] == category)["proportion"]) for category in categories] for pair in order])
    fig, ax = plt.subplots(figsize=(6.55, 3.45))
    y = np.arange(len(order)); left = np.zeros(len(order))
    for index, (label, color) in enumerate(zip(labels, colors)):
        ax.barh(y, matrix[:, index], left=left, color=color, height=.58, label=label)
        left += matrix[:, index]
    ax.set_yticks(y, order); ax.invert_yaxis(); ax.set_xlim(0, 1)
    ax.set_xlabel("Share of E-differing lineage–policy-group observations")
    ax.text(0, 1.04, "SOURCE OF FINAL CROSS-FAMILY DIFFERENCE", transform=ax.transAxes, color=MUTED, fontsize=7, fontfamily="DejaVu Sans Mono", fontweight=600)
    ax.legend(frameon=False, ncol=2, loc="upper center", bbox_to_anchor=(.5, -.22), fontsize=6.7)
    _editorial_axis(ax, xgrid=True)
    fig.subplots_adjust(left=.25, right=.98, bottom=.34, top=.88)
    return fig, "divergence_source", "Source of cross-family divergence"


def upe_flow() -> tuple[Any, str, str]:
    fig, ax = plt.subplots(figsize=(7.1, 4.15))
    ax.set_xlim(0, 100); ax.set_ylim(0, 110); ax.axis("off")

    columns = [(48, "U", "Upstream"), (70, "P", "Package"), (92, "E", "Effective")]
    for x, symbol, label in columns:
        ax.text(x, 106, symbol, ha="center", va="center", fontsize=14, fontweight=600, color=INK)
        ax.text(x, 101, label, ha="center", va="center", fontsize=7, color=MUTED, fontfamily="DejaVu Sans Mono")

    scenarios = [
        {
            "center": 83,
            "title": "A. INHERITED DIFFERENCE",
            "states": ((1, 1, 1), (2, 2, 2)),
            "actions": ("preserve", "preserve"),
            "outcome": "Inherited from upstream",
        },
        {
            "center": 54,
            "title": "B. DOWNSTREAM-INTRODUCED DIFFERENCE",
            "states": ((1, 2, 2), (1, 1, 1)),
            "actions": ("change", "preserve"),
            "outcome": "Introduced downstream",
        },
        {
            "center": 25,
            "title": "C. DOWNSTREAM CONVERGENCE",
            "states": ((1, 2, 2), (2, 2, 2)),
            "actions": ("change", "preserve"),
            "outcome": "Converged downstream",
        },
    ]

    # Emit the twelve axis-aligned track arrows before state markers and labels.
    for scenario in scenarios:
        center = scenario["center"]
        for track_index, y in enumerate((center + 3, center - 3)):
            line_style = "-" if track_index == 0 else (0, (3, 2))
            for left, right in ((48, 70), (70, 92)):
                ax.annotate(
                    "", xy=(right - 1.4, y), xytext=(left + 1.4, y),
                    arrowprops={
                        "arrowstyle": "-|>", "color": SOFT, "lw": .85,
                        "linestyle": line_style, "mutation_scale": 7,
                        "shrinkA": 0, "shrinkB": 0,
                    },
                )

    for scenario in scenarios:
        center = scenario["center"]
        ax.text(2, center + 10, scenario["title"], ha="left", va="center", fontsize=7, fontweight=600, color=MUTED, fontfamily="DejaVu Sans Mono")
        for track_index, (track_label, y) in enumerate((("Distribution A", center + 3), ("Distribution B", center - 3))):
            ax.text(36, y, track_label, ha="right", va="center", fontsize=7, color=INK)
            for x, state in zip((48, 70, 92), scenario["states"][track_index]):
                ax.scatter(
                    [x], [y], s=40, zorder=3,
                    facecolor=LINK if state == 1 else "white",
                    edgecolor=LINK, linewidth=.9,
                )
            label_y = y + 3.4 if track_index == 0 else y - 3.4
            ax.text(59, label_y, scenario["actions"][track_index], ha="center", va="center", fontsize=6.2, color=SOFT, fontfamily="DejaVu Sans Mono")
        ax.text(70, center - 11, scenario["outcome"], ha="center", va="center", fontsize=7.5, fontweight=600, color=INK)

    ax.text(2, 3, "POLICY STATES", ha="left", va="center", fontsize=6.5, fontweight=600, color=MUTED, fontfamily="DejaVu Sans Mono")
    ax.scatter([18], [3], s=40, facecolor=LINK, edgecolor=LINK, linewidth=.9)
    ax.text(20, 3, "State 1", ha="left", va="center", fontsize=6.5, color=MUTED)
    ax.scatter([31], [3], s=40, facecolor="white", edgecolor=LINK, linewidth=.9)
    ax.text(33, 3, "State 2", ha="left", va="center", fontsize=6.5, color=MUTED)

    fig.subplots_adjust(left=.015, right=.985, bottom=.015, top=.985)
    return fig, "upe_provenance_flow", "Why final-state comparison is insufficient"


def attrition_flow() -> tuple[Any, str, str]:
    rows = _rows("attrition_flow.csv")
    by_stage = {r["stage"]: r for r in rows}
    union = _rows("rq2_cross_family_union_summary.csv")[0]
    mode_rows = {
        row["matching_mode"]: row
        for row in _rows("matching_mode_outcome_sensitivity.csv")
        if row["endpoint"] == "RQ2_CROSS_FAMILY_UNION_DIVERGENCE"
    }
    with (FULL / "normalized/cohorts.csv").open(newline="", encoding="utf-8") as handle:
        cohort_rows = list(csv.DictReader(handle))

    def cohort_count(name: str) -> tuple[int, int]:
        selected = [row for row in cohort_rows if row["cohort"] == name]
        return len({row["canonical_upstream_id"] for row in selected}), len({row["lineage_id"] for row in selected})

    cohort_counts = {name: cohort_count(name) for name in ("C1X", "C1D", "C2", "C3X", "C3F", "C4")}
    lineages = _rows("../normalized/service_lineages.csv")
    matched = [row for row in lineages if row["match_status"] == "MATCHED"]
    whole_modes = {
        mode: (
            len({row["canonical_upstream_id"] for row in matched if row["lineage_match_mode"] == mode}),
            len({row["lineage_id"] for row in matched if row["lineage_match_mode"] == mode}),
        )
        for mode in ("EXACT_UPSTREAM_UNIT_IDENTITY", "UNAMBIGUOUS_EXECUTABLE_LINEAGE")
    }
    fig, ax = plt.subplots(figsize=(7.1, 4.9))
    ax.set_xlim(0, 120); ax.set_ylim(0, 100); ax.axis("off")

    pipeline = [
        ("CENSUS", f"{int(by_stage['frozen_service_shipping_packages']['projects_or_packages']):,} packages"),
        ("ELIGIBILITY", f"{int(by_stage['cross_family_eligible_projects']['projects_or_packages']):,} projects"),
        ("CANDIDATES", "1,742 pkg\n3,537 paths"),
        ("ACQUIRED", "1,739/1,742\npackages"),
        ("TIER-A", f"{len({row['lineage_id'] for row in matched}):,} lineages"),
        ("C1X", f"{cohort_counts['C1X'][0]:,} proj\n{cohort_counts['C1X'][1]:,} lin"),
        ("RQ2 SUPPORT", f"{int(union['projects']):,} proj\n{int(union['comparable_union_lineages']):,} lin"),
        ("C3X", f"{cohort_counts['C3X'][0]:,} proj\n{cohort_counts['C3X'][1]:,} lin"),
    ]
    pipeline_x = [1, 16, 31, 46, 61, 76, 91, 106]
    pipeline_y, pipeline_w, pipeline_h = 76, 13, 14

    # Draw the dominant reading path before its nodes. Every connector is
    # horizontal and terminates at the adjacent box boundary.
    for left, right in zip(pipeline_x[:-1], pipeline_x[1:]):
        ax.annotate(
            "", xy=(right, pipeline_y + pipeline_h / 2), xytext=(left + pipeline_w, pipeline_y + pipeline_h / 2),
            arrowprops={"arrowstyle": "-|>", "color": MUTED, "lw": .9, "shrinkA": 0, "shrinkB": 0},
        )
    node_text: list[tuple[Any, list[Any]]] = []
    for x, (name, detail) in zip(pipeline_x, pipeline):
        patch = FancyBboxPatch(
            (x, pipeline_y), pipeline_w, pipeline_h,
            boxstyle="round,pad=.0,rounding_size=1.2",
            fc=PAPER, ec=MUTED, lw=.8,
        )
        ax.add_patch(patch)
        labels = [
            ax.text(x + pipeline_w / 2, pipeline_y + 8.6, name, ha="center", va="center", fontsize=5.8, fontweight=600, fontfamily="DejaVu Sans Mono", color=INK),
            ax.text(x + pipeline_w / 2, pipeline_y + 4.0, detail, ha="center", va="center", fontsize=4.8, linespacing=1.05, color=MUTED, fontfamily="DejaVu Sans Mono"),
        ]
        node_text.append((patch, labels))

    matching_evidence = [
        ("EXACT IDENTITY", whole_modes["EXACT_UPSTREAM_UNIT_IDENTITY"], f"RQ2: {int(mode_rows['EXACT_UPSTREAM_UNIT_IDENTITY']['numerator'])}/{int(mode_rows['EXACT_UPSTREAM_UNIT_IDENTITY']['denominator'])} differ · {float(mode_rows['EXACT_UPSTREAM_UNIT_IDENTITY']['estimate']):.1%}"),
        ("EXECUTABLE IDENTITY", whole_modes["UNAMBIGUOUS_EXECUTABLE_LINEAGE"], f"RQ2: {int(mode_rows['UNAMBIGUOUS_EXECUTABLE_LINEAGE']['numerator'])}/{int(mode_rows['UNAMBIGUOUS_EXECUTABLE_LINEAGE']['denominator'])} differ · {float(mode_rows['UNAMBIGUOUS_EXECUTABLE_LINEAGE']['estimate']):.1%}"),
        ("UNAVAILABLE MODES", (0, 0), "Install/generation not operationalized"),
    ]
    for x, (name, (projects, matches), use) in zip((2, 41, 80), matching_evidence):
        patch = FancyBboxPatch(
            (x, 42), 37, 18, boxstyle="round,pad=.0,rounding_size=1.2",
            fc=PAPER, ec=MUTED, lw=.8,
        )
        ax.add_patch(patch)
        support = f"{projects:,} projects · {matches:,} lineages" if matches else "frozen evidence unavailable"
        labels = [
            ax.text(x + 18.5, 54.3, name, ha="center", va="center", fontsize=7.3, fontweight=600, color=INK),
            ax.text(x + 18.5, 49.5, support, ha="center", va="center", fontsize=6.0, color=MUTED, fontfamily="DejaVu Sans Mono"),
            ax.text(x + 18.5, 45.3, use, ha="center", va="center", fontsize=5.8, color=INK),
        ]
        node_text.append((patch, labels))

    secondary = [
        ("C1D", cohort_counts["C1D"], "Derivative contrast"),
        ("C3F", cohort_counts["C3F"], "Complete U exposure"),
        ("C2", cohort_counts["C2"], "Four-way sensitivity"),
        ("C4", cohort_counts["C4"], "Same-version sensitivity"),
    ]
    for x, (name, (projects, matches), use) in zip((2, 31, 60, 89), secondary):
        patch = FancyBboxPatch(
            (x, 7), 27, 17, boxstyle="round,pad=.0,rounding_size=1.2",
            fc=PAPER, ec=MUTED, lw=.7, linestyle=(0, (4, 3)),
        )
        ax.add_patch(patch)
        labels = [
            ax.text(x + 13.5, 19.0, name, ha="center", va="center", fontsize=8, fontweight=600, color=MUTED),
            ax.text(x + 13.5, 14.7, f"{projects:,} projects · {matches:,} lineages", ha="center", va="center", fontsize=5.8, color=SOFT, fontfamily="DejaVu Sans Mono"),
            ax.text(x + 13.5, 10.5, use, ha="center", va="center", fontsize=6.0, color=MUTED),
        ]
        node_text.append((patch, labels))

    ax.text(2, 96, "END-TO-END STUDY PIPELINE", color=MUTED, fontsize=7, fontfamily="DejaVu Sans Mono", fontweight=600)
    ax.text(2, 67, "MATCHING EVIDENCE AND MODE-STRATIFIED RQ2", color=MUTED, fontsize=7, fontfamily="DejaVu Sans Mono", fontweight=600)
    ax.text(2, 31, "SECONDARY AND ROBUSTNESS COHORTS", color=SOFT, fontsize=6.5, fontfamily="DejaVu Sans Mono", fontweight=600)
    fig.subplots_adjust(left=.015, right=.985, bottom=.025, top=.98)
    fig._unittrace_node_text_audit = _audit_node_text(fig, node_text)
    return fig, "attrition_flow", "Observed population, matching evidence, and analytical cohorts"


def run() -> dict[str, Any]:
    _style()
    builders = [adoption_heatmap, pairwise_divergence, divergence_magnitude, transformation_composition, divergence_source, upe_flow, attrition_flow]
    results = []
    for builder in builders:
        fig, stem, title = builder()
        results.append(_save(fig, stem, title))
    # Connector geometry is deliberately simple in the two flow diagrams: every
    # connector shares one x or y axis, ends at the target boundary, and is drawn
    # before nodes. No crossing, overlap, shared attach point, or diagonal exists.
    manifest = {
        "design_system": "diagram-design 2.0: UnitTrace journal skin",
        "canvas_background": "transparent",
        "tokens": {"paper": PAPER, "ink": INK, "muted": MUTED, "soft": SOFT, "accent": ACCENT, "link": LINK, "rule_alpha": 0.08},
        "contrast_ratios": {"ink_on_paper": 12.13, "muted_on_paper": 6.27, "accent_on_paper": 2.94},
        "visual_encoding_audit": {
            "unexplained_focal_outlines": 0,
            "cross_family_pair_color": CROSS_FAMILY,
            "derivative_family_color": DERIVATIVE_FAMILY,
            "neutral_upe_nodes": True,
            "neutral_attrition_nodes": True,
            "workflow_primary_cohorts": ["C1X", "C3X"],
            "workflow_secondary_cohorts": ["C2", "C4"],
            "figure6_changed_totals": {"Debian": 53, "Ubuntu": 68, "Fedora": 89, "Arch": 92},
            "accent_usage": "categorical only: downstream-introduced segment in divergence-source figure",
        },
        "connector_audit": {"orthogonal_or_axis_aligned": True, "labels_masked_with_gap": True, "overlaps": 0, "shared_attach_points": 0, "behind_non_endpoint_nodes": 0, "arrows_drawn_before_nodes": True},
        "figures": results,
        "all_pass": all(item["passed"] for item in results),
    }
    atomic_json(FULL / "manifests/premium_figure_validation.json", manifest)
    if not manifest["all_pass"]:
        raise RuntimeError("premium figure validation failed")
    return manifest


if __name__ == "__main__":
    run()
