"""Report figures (matplotlib)."""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from threatsense.storage.database import Database  # noqa: E402

COLORS = {"majority_class": "#64748b", "zscore_threshold": "#a3a3a3", "logistic_regression": "#38bdf8",
          "random_forest": "#f43f5e", "hist_gradient_boosting": "#f59e0b", "isolation_forest": "#a855f7",
          "hybrid": "#22d3ee"}


def make_figures(db: Database, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"figure.dpi": 130, "axes.spines.top": False, "axes.spines.right": False})
    res = db.query_df("SELECT model, curves_json, metrics_json FROM model_results WHERE split='test'")

    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    for r in res.itertuples():
        if r.model == "majority_class":
            continue
        c = json.loads(r.curves_json)
        m = json.loads(r.metrics_json)
        ax.plot(c["recall"], c["precision"], label=f"{r.model} (AP {m['pr_auc']:.3f})", color=COLORS.get(r.model), lw=2)
    ax.set(xlabel="Recall", ylabel="Precision", title="Precision–recall (test window)", ylim=(0, 1.02))
    ax.legend(fontsize=7, frameon=False)
    fig.tight_layout()
    fig.savefig(out / "pr_curves.png")
    plt.close(fig)

    w = db.query_df("SELECT * FROM windows ORDER BY window_start")
    fig, ax = plt.subplots(figsize=(10, 3.5))
    ax.bar(range(len(w)), w.n_true_attacks, color="#f43f5e55", label="true attack flows")
    ax.plot(range(len(w)), w.n_alerts, color="#22d3ee", lw=1.8, label="alerts")
    ax.set(xlabel="5-minute window (test period)", ylabel="flows", title="Alerts vs. ground truth during replay")
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(out / "alerts_over_time.png")
    plt.close(fig)

    g = db.query_df("SELECT model, grp, recall FROM group_metrics WHERE grouping='category' AND grp != 'benign' "
                    "AND model IN ('random_forest','isolation_forest','hybrid')")
    piv = g.pivot(index="grp", columns="model", values="recall")
    fig, ax = plt.subplots(figsize=(7, 3.8))
    piv.plot.bar(ax=ax, color=[COLORS[c] for c in piv.columns], rot=0)
    ax.set(title="Recall by attack category (exfiltration = unseen in training)", ylabel="recall", xlabel="", ylim=(0, 1.05))
    ax.legend(frameon=False, fontsize=8)
    fig.tight_layout()
    fig.savefig(out / "recall_by_category.png")
    plt.close(fig)
