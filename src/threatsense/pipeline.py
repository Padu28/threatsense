"""End-to-end research pipeline.

load → audit → features → time split → baselines → supervised → calibration →
anomaly detector → hybrid risk → freeze thresholds on validation → evaluate on
test → replay test window as a stream → explain alerts → persist → report.
"""
from __future__ import annotations

import json
from typing import Any

import joblib
import numpy as np
import pandas as pd

from threatsense import __version__
from threatsense.common.config import get_settings
from threatsense.common.logging import get_logger
from threatsense.common.utils import dump_json, to_jsonable
from threatsense.detection.models import AnomalyDetector, ZScoreBaseline, calibrate, train_majority, train_supervised
from threatsense.evaluation.metrics import binary_report, bootstrap_ci, curves, per_group_recall
from threatsense.explainability.explain import benign_reference, describe, substitution_contributions, top_factors
from threatsense.features.engineering import build_features, time_split
from threatsense.ingestion.loaders import load_flows, validate_flows
from threatsense.scoring.thresholds import hybrid_risk, priority, select_threshold
from threatsense.storage.database import Database, utcnow
from threatsense.streaming.replay import ReplaySource, run_stream

log = get_logger("threatsense.pipeline")
MODEL_VERSION = f"ts-{__version__}"


class Scorer:
    """Bundles the frozen artefacts needed to score a flow (persisted with joblib)."""

    def __init__(self, calibrated, anomaly: AnomalyDetector, zbase: ZScoreBaseline, threshold: float,
                 weight: float, bands: dict[str, float], reference: pd.Series, features: list[str]) -> None:
        self.calibrated, self.anomaly, self.zbase = calibrated, anomaly, zbase
        self.threshold, self.weight, self.bands = threshold, weight, bands
        self.reference, self.features = reference, features
        self.version = MODEL_VERSION

    def supervised(self, df: pd.DataFrame) -> np.ndarray:
        return self.calibrated.predict_proba(df[self.features])[:, 1]

    def risk(self, df: pd.DataFrame) -> np.ndarray:
        return hybrid_risk(self.supervised(df), self.anomaly.percentile(self.anomaly.score(df)), self.weight)

    def score_frame(self, df: pd.DataFrame) -> pd.DataFrame:
        sp = self.supervised(df)
        ap = self.anomaly.percentile(self.anomaly.score(df))
        r = hybrid_risk(sp, ap, self.weight)
        return pd.DataFrame({"supervised_proba": sp, "anomaly_pct": ap, "risk": r,
                             "zscore": self.zbase.score(df), "alert": (r >= self.threshold).astype(int),
                             "priority": priority(r, self.bands)}, index=df.index)


def run_pipeline() -> dict[str, Any]:
    s = get_settings()
    th = s.thresholds
    db = Database(s.db_path)
    db.reset()

    # ------------------------------------------------------------ data
    raw = load_flows()
    audit = validate_flows(raw)
    log.info("Loaded %d flows · attack rate %.2f%% · %d duplicates", audit["n_rows"], 100 * audit["attack_rate"],
             audit["duplicate_rows"])
    df = build_features(raw, s.features["context_window_seconds"])
    train, valid, test = time_split(df, s.dataset["split"]["train"], s.dataset["split"]["validation"])
    split_info = {name: {"n": len(d), "attack_rate": float(d[s.target].mean()),
                         "start": str(d.timestamp.min()), "end": str(d.timestamp.max()),
                         "categories": d.category.value_counts().to_dict()}
                  for name, d in [("train", train), ("validation", valid), ("test", test)]}
    log.info("Split: train %d · validation %d · test %d", len(train), len(valid), len(test))

    # ------------------------------------------------------------ models
    max_fpr = th["threshold_policy"]["max_fpr"]
    results: dict[str, dict[str, Any]] = {}
    group_rows: list[pd.DataFrame] = []

    def evaluate(name: str, val_scores: np.ndarray, test_scores: np.ndarray, threshold: float | None = None) -> None:
        thr = threshold if threshold is not None else select_threshold(valid[s.target], val_scores, max_fpr).value
        rep = binary_report(test[s.target], test_scores, thr)
        rep["pr_auc_ci95"] = bootstrap_ci(test[s.target].to_numpy(), test_scores) if rep["recall"] > 0 or rep["pr_auc"] > 0 else None
        results[name] = rep
        pred = test_scores >= thr
        for grouping in ("category", "protocol"):
            g = per_group_recall(test, pred, grouping, s.target)
            g = g.rename(columns={grouping: "grp"}).assign(model=name, grouping=grouping)
            group_rows.append(g)
        db.write_df("model_results", pd.DataFrame([{
            "model": name, "split": "test", "metrics_json": json.dumps(to_jsonable(rep)),
            "curves_json": json.dumps(curves(test[s.target].to_numpy(), test_scores)), "created_at": utcnow()}]))
        log.info("%-22s PR-AUC %.3f · recall %.3f · precision %.3f · FPR %.4f", name, rep["pr_auc"], rep["recall"],
                 rep["precision"], rep["fpr"])

    feats = s.all_features
    maj = train_majority(train)
    evaluate("majority_class", maj.predict_proba(valid[feats])[:, -1], maj.predict_proba(test[feats])[:, -1], 0.5)

    zb = ZScoreBaseline().fit(train)
    evaluate("zscore_threshold", zb.score(valid), zb.score(test))

    sup_models = {}
    for name in ("logistic_regression", "random_forest", "hist_gradient_boosting"):
        m = train_supervised(name, train)
        sup_models[name] = m
        evaluate(name, m.predict_proba(valid[feats])[:, 1], m.predict_proba(test[feats])[:, 1])

    iso = AnomalyDetector().fit(train)
    iso.set_reference(valid[valid[s.target] == 0])
    evaluate("isolation_forest", iso.score(valid), iso.score(test))

    primary = th["hybrid"]["primary_model"]
    cal = calibrate(sup_models[primary], valid)
    w = th["hybrid"]["supervised_weight"]
    risk_val = hybrid_risk(cal.predict_proba(valid[feats])[:, 1], iso.percentile(iso.score(valid)), w)
    frozen = select_threshold(valid[s.target], risk_val, max_fpr)
    ref = benign_reference(train, feats, s.categorical, s.target)
    scorer = Scorer(cal, iso, zb, frozen.value, w, th["priority_bands"], ref, feats)
    risk_test = scorer.risk(test)
    evaluate("hybrid", risk_val, risk_test, frozen.value)
    s.models_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(scorer, s.models_dir / "scorer.joblib")

    gm = pd.concat(group_rows, ignore_index=True)[["model", "grouping", "grp", "n", "n_attack", "recall", "fpr"]]
    gm["grp"] = gm["grp"].astype(str)
    db.write_df("group_metrics", gm)

    # ------------------------------------------------------------ streaming replay of the test window
    scored_frames: list[pd.DataFrame] = []
    alert_frames: list[pd.DataFrame] = []
    window_rows: list[dict[str, Any]] = []

    def handle(start: pd.Timestamp, w_df: pd.DataFrame) -> None:
        sc = scorer.score_frame(w_df)
        merged = w_df.join(sc)
        scored_frames.append(merged)
        al = merged[merged.alert == 1]
        if len(al):
            alert_frames.append(al)
        window_rows.append({"window_start": str(start), "n_flows": len(w_df), "n_alerts": int(sc.alert.sum()),
                            "n_true_attacks": int(w_df[s.target].sum()), "mean_risk": float(sc.risk.mean()),
                            "max_risk": float(sc.risk.max()), "alert_rate": float(sc.alert.mean())})

    n_windows = run_stream(ReplaySource(test, th["streaming"]["window_minutes"]), handle)
    scored = pd.concat(scored_frames)
    alerts = pd.concat(alert_frames) if alert_frames else scored.head(0)
    log.info("Replayed %d windows · %d alerts", n_windows, len(alerts))

    # explanations (vectorised) for every alert
    contrib = substitution_contributions(scorer.supervised, alerts[feats], ref, feats) if len(alerts) else None
    zs = zb.zscores(alerts) if len(alerts) else None
    arow = []
    for idx, r in alerts.iterrows():
        f = top_factors(contrib.loc[idx], 4)
        dev = zs.loc[idx].sort_values(key=np.abs, ascending=False).head(4).round(2).to_dict()
        arow.append({"flow_id": r.flow_id, "ts": str(r.timestamp), "src_ip": r.src_ip, "dst_port": int(r.dst_port),
                     "protocol": r.protocol, "true_category": r.category, "is_attack": int(r[s.target]),
                     "risk": float(r.risk), "priority": r.priority, "supervised_proba": float(r.supervised_proba),
                     "anomaly_pct": float(r.anomaly_pct), "model_version": MODEL_VERSION,
                     "factors_json": json.dumps(f), "deviations_json": json.dumps(dev), "summary": describe(f[:3])})
    db.write_df("alerts", pd.DataFrame(arow))
    db.write_df("windows", pd.DataFrame(window_rows))
    keep = ["flow_id", "timestamp", "src_ip", "dst_port", "protocol", "category", s.target, "risk", "supervised_proba",
            "anomaly_pct", "zscore", "alert", "fwd_bytes", "flow_bytes_per_s", "duration_ms", "src_flow_count_60s",
            "src_port_diversity_60s"]
    sf = scored[keep].rename(columns={"timestamp": "ts", s.target: "is_attack"})
    sf["ts"] = sf["ts"].astype(str)
    db.write_df("scored_flows", sf)

    # validation curve for the threshold lab
    db.write_df("model_results", pd.DataFrame([{
        "model": "hybrid", "split": "validation", "metrics_json": json.dumps(frozen.__dict__),
        "curves_json": json.dumps({"risk": np.round(risk_val, 5).tolist(), "y": valid[s.target].astype(int).tolist()}),
        "created_at": utcnow()}]))

    profile = (train.groupby(["category", "protocol"])[["duration_ms", "fwd_bytes", "flow_packets_per_s"]]
               .median().reset_index().to_dict(orient="records"))
    summary = {
        "version": __version__, "model_version": MODEL_VERSION, "created_at": utcnow(), "audit": audit,
        "splits": split_info, "threshold": frozen.__dict__, "results": results, "n_alerts": len(alerts),
        "n_windows": n_windows, "primary_model": primary, "supervised_weight": w,
        "traffic_profile": profile, "dataset_source": s.dataset["source"],
    }
    db.put_meta("summary", to_jsonable(summary))
    dump_json(to_jsonable(summary), s.reports_dir / "evaluation_summary.json")
    write_report(summary, gm, s.reports_dir / "evaluation_report.md")
    try:
        from threatsense.evaluation.figures import make_figures
        make_figures(db, s.reports_dir / "figures")
    except Exception as exc:
        log.warning("Figures skipped: %s", exc)
    return summary


def write_report(summary: dict[str, Any], gm: pd.DataFrame, path) -> None:
    r = summary["results"]
    lines = [
        "# ThreatSense — Evaluation Report", "",
        f"*Generated {summary['created_at']} · model `{summary['model_version']}` · source: {summary['dataset_source']}*", "",
        "> Synthetic flow capture. Metrics describe behaviour on this capture only and are **not** evidence that the",
        "> detector is fit for production security operations.", "",
        f"**Frozen threshold:** {summary['threshold']['value']:.4f} — {summary['threshold']['policy']} "
        f"(validation recall {summary['threshold']['val_recall']:.3f}, FPR {summary['threshold']['val_fpr']:.4f})", "",
        "## Test-window results", "",
        "| Model | PR-AUC (95% CI) | ROC-AUC | Precision | Recall | F1 | FPR | Alerts / 10k flows | False alerts / 10k |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, m in r.items():
        ci = m.get("pr_auc_ci95")
        ci_s = f" ({ci[0]:.3f}–{ci[1]:.3f})" if ci else ""
        lines.append(f"| {name} | {m['pr_auc']:.3f}{ci_s} | {m['roc_auc']:.3f} | {m['precision']:.3f} | {m['recall']:.3f} | "
                     f"{m['f1']:.3f} | {m['fpr']:.4f} | {m['alerts_per_10k']:.0f} | {m['false_alerts_per_10k']:.0f} |")
    cat = gm[(gm.grouping == "category") & (gm.grp != "benign") & gm.model.isin(["random_forest", "isolation_forest", "hybrid"])]
    piv = cat.pivot_table(index="grp", columns="model", values="recall").round(3)
    lines += ["", "## Recall by attack category (test)", "", _md_table(piv),
              "", "`exfiltration` never appears in training — it measures novel-attack detection.", "",
              "## Limitations",
              "- Synthetic traffic is far more separable than real captures; expect lower scores on CIC-IDS2017/UNSW-NB15.",
              "- Label noise (0.5 %) is injected but real IDS labels have systematic errors.",
              "- Scores are prioritisation aids for analysts, not certainty or proof of malicious intent.",
              "- No real scanning, exploitation, credential collection or live traffic capture is performed."]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _md_table(df: pd.DataFrame) -> str:
    cols = [df.index.name or ""] + [str(c) for c in df.columns]
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for idx, row in df.iterrows():
        out.append("| " + " | ".join([str(idx)] + ["—" if pd.isna(v) else f"{v:.3f}" for v in row]) + " |")
    return "\n".join(out)
