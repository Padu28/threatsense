import numpy as np
import pytest

from threatsense.detection.models import AnomalyDetector, ZScoreBaseline, calibrate, train_majority, train_supervised
from threatsense.evaluation.metrics import binary_report, per_group_recall
from threatsense.explainability.explain import benign_reference, substitution_contributions, top_factors
from threatsense.features.engineering import time_split
from threatsense.scoring.thresholds import hybrid_risk, priority, select_threshold


@pytest.fixture(scope="module")
def splits(flows):
    return time_split(flows, 0.6, 0.2)


def test_select_threshold_respects_fpr_budget():
    rng = np.random.default_rng(0)
    y = np.r_[np.zeros(5000), np.ones(500)]
    s = np.r_[rng.normal(0, 1, 5000), rng.normal(3, 1, 500)]
    th = select_threshold(y, s, max_fpr=0.01)
    assert th.val_fpr <= 0.01
    assert th.val_recall > 0.5


def test_priority_bands():
    p = priority(np.array([0.2, 0.55, 0.8, 0.95]), {"medium": 0.5, "high": 0.75, "critical": 0.9})
    assert p.tolist() == ["low", "medium", "high", "critical"]


def test_hybrid_risk_bounds():
    r = hybrid_risk(np.array([0, 1, 0.5]), np.array([1, 1, 0]), 0.7)
    assert np.all((r >= 0) & (r <= 1))
    assert r[1] == pytest.approx(1.0)


def test_majority_baseline_has_zero_recall(splits, settings):
    tr, va, te = splits
    m = train_majority(tr)
    rep = binary_report(te[settings.target], m.predict_proba(te[settings.all_features])[:, -1], 0.5)
    assert rep["recall"] == 0.0


def test_supervised_beats_baselines(splits, settings):
    tr, va, te = splits
    rf = train_supervised("random_forest", tr)
    sc = rf.predict_proba(te[settings.all_features])[:, 1]
    zb = ZScoreBaseline().fit(tr)
    assert binary_report(te[settings.target], sc, 0.5)["pr_auc"] > binary_report(te[settings.target], zb.score(te), 6)["pr_auc"]


def test_isolation_forest_flags_exfiltration(splits, settings):
    tr, va, te = splits
    iso = AnomalyDetector().fit(tr)
    iso.set_reference(va[va[settings.target] == 0])
    pct = iso.percentile(iso.score(te))
    exf = te.category.eq("exfiltration").to_numpy()
    assert pct[exf].mean() > 0.95


def test_calibration_and_explanations(splits, settings):
    tr, va, te = splits
    cal = calibrate(train_supervised("logistic_regression", tr), va)
    p = cal.predict_proba(te[settings.all_features])[:, 1]
    assert np.all((p >= 0) & (p <= 1))
    ref = benign_reference(tr, settings.all_features, settings.categorical, settings.target)
    rows = te[te[settings.target] == 1].head(5)[settings.all_features]
    contrib = substitution_contributions(lambda d: cal.predict_proba(d[settings.all_features])[:, 1], rows, ref,
                                         settings.all_features)
    assert contrib.shape == (5, len(settings.all_features))
    assert len(top_factors(contrib.iloc[0], 3)) == 3


def test_per_group_recall(splits, settings):
    _, _, te = splits
    g = per_group_recall(te, te[settings.target].to_numpy(), "category")
    assert (g[g.n_attack > 0].recall == 1.0).all()
