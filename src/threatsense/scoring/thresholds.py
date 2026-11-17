"""Threshold selection on validation data and alert prioritisation."""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class FrozenThreshold:
    value: float
    val_recall: float
    val_fpr: float
    val_precision: float
    policy: str


def select_threshold(y: np.ndarray, scores: np.ndarray, max_fpr: float = 0.01) -> FrozenThreshold:
    """Maximise recall subject to FPR ≤ ``max_fpr`` on *validation* data.

    The returned threshold is frozen and later applied unchanged to the test window.
    """
    y = np.asarray(y).astype(int)
    scores = np.asarray(scores, dtype=float)
    neg = scores[y == 0]
    if len(neg) == 0:
        raise ValueError("Validation set has no negatives")
    # smallest threshold whose FPR is within budget
    thr = float(np.quantile(neg, 1 - max_fpr, method="higher"))
    thr = np.nextafter(thr, np.inf)
    pred = scores >= thr
    tp = int((pred & (y == 1)).sum())
    fp = int((pred & (y == 0)).sum())
    pos = max(int((y == 1).sum()), 1)
    return FrozenThreshold(
        value=float(thr),
        val_recall=tp / pos,
        val_fpr=fp / len(neg),
        val_precision=tp / max(tp + fp, 1),
        policy=f"max recall s.t. FPR ≤ {max_fpr:.2%} (validation)",
    )


def hybrid_risk(supervised_proba: np.ndarray, anomaly_percentile: np.ndarray, w: float = 0.7) -> np.ndarray:
    """Blend a calibrated supervised probability with an anomaly percentile (both in [0, 1])."""
    return np.clip(w * supervised_proba + (1 - w) * anomaly_percentile, 0, 1)


def priority(risk: np.ndarray, bands: dict[str, float]) -> np.ndarray:
    out = np.full(len(risk), "low", dtype=object)
    for name in ("medium", "high", "critical"):
        out[risk >= bands[name]] = name
    return out
