"""Figure styling for the evaluation experiments.

One validated categorical palette, recessive axes, thin marks, one measure per
axis (never a second y-scale), a legend whenever more than one series is drawn.
"""

from __future__ import annotations

import pathlib
from typing import Iterable, Optional, Sequence

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt   # noqa: E402

# validated categorical slots (light surface), assigned in fixed order
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#4a3aa7", "#e87ba4", "#008300",
          "#eda100", "#e34948"]
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
INK_MUTED = "#8a8983"
GOOD, WARN, BAD = "#1baf7a", "#eda100", "#e34948"


def use_style() -> None:
    plt.rcParams.update({
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
        "axes.edgecolor": INK_MUTED,
        "axes.linewidth": 0.8,
        "axes.labelcolor": INK_2,
        "axes.titlecolor": INK,
        "axes.titlesize": 11,
        "axes.titleweight": "medium",
        "axes.labelsize": 9.5,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "axes.axisbelow": True,
        "grid.color": "#e5e4e0",
        "grid.linewidth": 0.7,
        "xtick.color": INK_2,
        "ytick.color": INK_2,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.frameon": False,
        "legend.fontsize": 9,
        "lines.linewidth": 2.0,
        "lines.markersize": 5.5,
        "font.family": "DejaVu Sans",
        "figure.dpi": 130,
    })


def line(ax, x: Sequence[float], y: Sequence[float], slot: int, label: str,
         marker: str = "o", **kw):
    return ax.plot(x, y, color=SERIES[slot % len(SERIES)], marker=marker,
                   markeredgecolor=SURFACE, markeredgewidth=1.0, label=label,
                   **kw)


def bars(ax, x, y, slot: int = 0, label: Optional[str] = None, width=0.7, **kw):
    return ax.bar(x, y, width=width, color=SERIES[slot % len(SERIES)],
                  edgecolor=SURFACE, linewidth=1.2, label=label, **kw)


def annotate_last(ax, x, y, text: str, slot: int = 0, dx=0.0, dy=0.0):
    ax.annotate(text, (x, y), textcoords="offset points", xytext=(6 + dx, dy),
                color=INK_2, fontsize=8.5, va="center")


def save(fig, path: str | pathlib.Path, title: Optional[str] = None) -> str:
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if title:
        fig.suptitle(title, color=INK, fontsize=12, fontweight="medium")
    fig.tight_layout()
    fig.savefig(p, bbox_inches="tight")
    plt.close(fig)
    return str(p)
