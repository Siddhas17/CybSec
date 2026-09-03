"""Matplotlib chart images for the PDF report -- each function takes
already-fetched data (never queries DB itself) and returns an in-memory
BytesIO PNG, never a temp file. Headless Agg backend, same pattern already
proven in this environment by attack_graph/visualization/visualize_graph.py.
"""

from __future__ import annotations

import io

import matplotlib

matplotlib.use("Agg")  # headless (no display server) -- must precede pyplot import

import matplotlib.pyplot as plt

ATTACK_COLOR = "#d64550"
BENIGN_COLOR = "#3b9eff"


def _fig_to_png(fig) -> io.BytesIO:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return buf


def confusion_matrix_heatmap_png(matrix: dict, title: str) -> io.BytesIO:
    tn, fp, fn, tp = (matrix.get(k) or 0 for k in ("tn", "fp", "fn", "tp"))
    data = [[tn, fn], [fp, tp]]
    fig, ax = plt.subplots(figsize=(4, 4))
    im = ax.imshow(data, cmap="Blues")
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["Actual BENIGN", "Actual ATTACK"])
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["Pred BENIGN", "Pred ATTACK"])
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{data[i][j]:,}", ha="center", va="center", color="black")
    ax.set_title(title, fontsize=10)
    fig.colorbar(im, ax=ax, fraction=0.046)
    return _fig_to_png(fig)


def risk_score_distribution_png(buckets: list[dict]) -> io.BytesIO:
    fig, ax = plt.subplots(figsize=(6, 2.8))
    if not buckets:
        ax.text(0.5, 0.5, "No data", ha="center", va="center")
    else:
        labels = [f"{b['range_start']:.1f}" for b in buckets]
        ax.bar(labels, [b["count"] for b in buckets], color=ATTACK_COLOR)
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right", fontsize=7)
    ax.set_xlabel("Risk score")
    ax.set_ylabel("Count")
    ax.set_title("Risk Score Distribution", fontsize=10)
    return _fig_to_png(fig)


def anomaly_score_distribution_png(buckets: list[dict]) -> io.BytesIO:
    fig, ax = plt.subplots(figsize=(6, 2.8))
    if not buckets:
        ax.text(0.5, 0.5, "No data", ha="center", va="center")
    else:
        labels = [f"{b['range_start']:.3f}" for b in buckets]
        ax.bar(labels, [b["count"] for b in buckets], color=BENIGN_COLOR)
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right", fontsize=7)
    ax.set_xlabel("Reconstruction error")
    ax.set_ylabel("Count")
    ax.set_title("Anomaly Score Distribution", fontsize=10)
    return _fig_to_png(fig)


def attack_timeline_png(points: list[dict]) -> io.BytesIO:
    fig, ax = plt.subplots(figsize=(7, 2.8))
    if not points:
        ax.text(0.5, 0.5, "No data", ha="center", va="center")
    else:
        labels = [p["bucket"] for p in points]
        ax.plot(labels, [p["event_count"] for p in points], label="Events", color=BENIGN_COLOR)
        ax.plot(labels, [p["attack_count"] for p in points], label="Attacks", color=ATTACK_COLOR)
        ax.legend(fontsize=7)
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right", fontsize=6)
    ax.set_title("Attack Timeline", fontsize=10)
    return _fig_to_png(fig)


def attacks_by_type_png(rows: list[dict]) -> io.BytesIO:
    rows = rows[:15]
    fig, ax = plt.subplots(figsize=(6, max(2.5, len(rows) * 0.3)))
    if not rows:
        ax.text(0.5, 0.5, "No attack events recorded", ha="center", va="center")
    else:
        labels = [r["attack_type"] for r in rows]
        ax.barh(labels, [r["count"] for r in rows], color=ATTACK_COLOR)
        ax.invert_yaxis()
        ax.tick_params(labelsize=7)
    ax.set_xlabel("Count")
    ax.set_title("Attacks by Type", fontsize=10)
    return _fig_to_png(fig)
