"""Detectors: trivial baselines, supervised classifiers and unsupervised anomaly models."""
from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from threatsense.common.config import get_settings
from threatsense.preprocessing.pipeline import build_preprocessor

SUPERVISED = {
    "logistic_regression": LogisticRegression,
    "random_forest": RandomForestClassifier,
    "hist_gradient_boosting": HistGradientBoostingClassifier,
}


def _prep():
    s = get_settings()
    return build_preprocessor(s.numeric, s.categorical, s.features["log_transform"])


def train_majority(train: pd.DataFrame) -> Pipeline:
    s = get_settings()
    return Pipeline([("prep", _prep()), ("clf", DummyClassifier(strategy="most_frequent"))]).fit(
        train[s.all_features], train[s.target])


def train_supervised(name: str, train: pd.DataFrame) -> Pipeline:
    s = get_settings()
    params: dict[str, Any] = dict(s.thresholds["supervised"][name])
    est = SUPERVISED[name]
    if "random_state" in est().get_params():
        params["random_state"] = s.thresholds["random_state"]
    pipe = Pipeline([("prep", _prep()), ("clf", est(**params))])
    return pipe.fit(train[s.all_features], train[s.target])


def calibrate(model: Pipeline, valid: pd.DataFrame) -> Any:
    """Sigmoid (Platt) calibration fitted on the validation window, model frozen."""
    s = get_settings()
    try:
        from sklearn.frozen import FrozenEstimator  # sklearn ≥ 1.6

        cal = CalibratedClassifierCV(FrozenEstimator(model), method="sigmoid")
    except ImportError:  # pragma: no cover - older sklearn
        cal = CalibratedClassifierCV(model, method="sigmoid", cv="prefit")
    return cal.fit(valid[s.all_features], valid[s.target])


class AnomalyDetector:
    """Isolation Forest fitted on *benign* training flows (semi-supervised novelty detection).

    ``score`` returns higher = more anomalous; ``percentile`` maps a raw score to its
    rank among benign validation scores (0–1), which is easier to communicate than raw scores.
    """

    def __init__(self) -> None:
        s = get_settings()
        cfg = s.thresholds["isolation_forest"]
        self.pipe = Pipeline([("prep", _prep()), ("iso", IsolationForest(
            n_estimators=cfg["n_estimators"], max_samples=cfg["max_samples"],
            contamination=cfg["contamination"], random_state=s.thresholds["random_state"], n_jobs=-1))])
        self._ref: np.ndarray | None = None

    def fit(self, train: pd.DataFrame) -> AnomalyDetector:
        s = get_settings()
        benign = train[train[s.target] == 0]
        self.pipe.fit(benign[s.all_features])
        return self

    def score(self, df: pd.DataFrame) -> np.ndarray:
        s = get_settings()
        return -self.pipe.score_samples(df[s.all_features])

    def set_reference(self, benign_valid: pd.DataFrame) -> None:
        self._ref = np.sort(self.score(benign_valid))

    def percentile(self, scores: np.ndarray) -> np.ndarray:
        if self._ref is None:
            raise RuntimeError("Call set_reference() first")
        return np.searchsorted(self._ref, scores, side="right") / len(self._ref)


class ZScoreBaseline:
    """Statistical threshold baseline: max robust z-score across volumetric features."""

    COLS = ["flow_bytes_per_s", "flow_packets_per_s", "fwd_packets", "fwd_bytes", "duration_ms",
            "src_flow_count_60s", "src_port_diversity_60s", "syn_flag_count"]

    def fit(self, train: pd.DataFrame) -> ZScoreBaseline:
        s = get_settings()
        b = np.log1p(train[train[s.target] == 0][self.COLS].clip(lower=0))
        self.med = b.median()
        self.mad = (b - self.med).abs().median().replace(0, 1e-6) * 1.4826
        return self

    def score(self, df: pd.DataFrame) -> np.ndarray:
        z = (np.log1p(df[self.COLS].clip(lower=0)) - self.med) / self.mad
        return z.abs().max(axis=1).to_numpy()

    def zscores(self, df: pd.DataFrame) -> pd.DataFrame:
        return (np.log1p(df[self.COLS].clip(lower=0)) - self.med) / self.mad
