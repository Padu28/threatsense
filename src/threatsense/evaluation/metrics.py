"""Imbalance-aware evaluation: PR-AUC first, workload metrics, per-category breakdowns."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


def binary_report(y: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, float]:
    y = np.asarray(y).astype(int)
    pred = (np.asarray(scores) >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    two = len(np.unique(y)) > 1
    return {
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y, scores)) if two else float("nan"),
        "roc_auc": float(roc_auc_score(y, scores)) if two else float("nan"),
        "fpr": float(fp / max(fp + tn, 1)),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "alerts_per_10k": float(pred.sum() / max(len(y), 1) * 10_000),
        "false_alerts_per_10k": float(fp / max(len(y), 1) * 10_000),
        "threshold": float(threshold),
    }


def per_group_recall(df: pd.DataFrame, pred: np.ndarray, group: str, target: str = "is_attack") -> pd.DataFrame:
    d = df.assign(_pred=np.asarray(pred).astype(int))
    rows = []
    for g, sub in d.groupby(group):
        pos = sub[sub[target] == 1]
        neg = sub[sub[target] == 0]
        rows.append({
            group: g, "n": len(sub), "n_attack": len(pos),
            "recall": float(pos._pred.mean()) if len(pos) else np.nan,
            "fpr": float(neg._pred.mean()) if len(neg) else np.nan,
        })
    return pd.DataFrame(rows)


def curves(y: np.ndarray, scores: np.ndarray, n: int = 200) -> dict[str, list[float]]:
    p, r, _ = precision_recall_curve(y, scores)
    fpr, tpr, _ = roc_curve(y, scores)
    ip = np.linspace(0, len(p) - 1, min(n, len(p))).astype(int)
    ir = np.linspace(0, len(fpr) - 1, min(n, len(fpr))).astype(int)
    return {"precision": p[ip].tolist(), "recall": r[ip].tolist(), "fpr": fpr[ir].tolist(), "tpr": tpr[ir].tolist()}


def bootstrap_ci(y: np.ndarray, scores: np.ndarray, metric=average_precision_score, n: int = 200,
                 seed: int = 0) -> tuple[float, float]:
    rng = np.random.default_rng(seed)
    y, scores = np.asarray(y), np.asarray(scores)
    vals = []
    for _ in range(n):
        idx = rng.integers(0, len(y), len(y))
        if len(np.unique(y[idx])) < 2:
            continue
        vals.append(metric(y[idx], scores[idx]))
    return float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))
