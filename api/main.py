"""ThreatSense REST API (defensive analytics on flow metadata).

Run:  uvicorn api.main:app --reload --port 8001     → docs at http://localhost:8001/docs
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Literal

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import joblib  # noqa: E402
import pandas as pd  # noqa: E402
from fastapi import FastAPI, HTTPException, Query  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from threatsense import __version__  # noqa: E402
from threatsense.common.config import get_settings  # noqa: E402
from threatsense.common.utils import to_jsonable  # noqa: E402
from threatsense.explainability.explain import describe, substitution_contributions, top_factors  # noqa: E402
from threatsense.features.engineering import add_flow_features  # noqa: E402
from threatsense.storage.database import Database, utcnow  # noqa: E402

app = FastAPI(title="ThreatSense API", version=__version__,
              description="Explainable risk scoring for network-flow records. Scores support analyst triage; "
                          "they are not proof of malicious activity.")
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
                   allow_methods=["*"], allow_headers=["*"])

settings = get_settings()
db = Database(settings.db_path)
_cache: dict[str, Any] = {}


def scorer():
    if "scorer" not in _cache:
        p = settings.models_dir / "scorer.joblib"
        if not p.exists():
            raise HTTPException(503, "Scorer not trained. Run `python -m threatsense.cli pipeline`.")
        _cache["scorer"] = joblib.load(p)
    return _cache["scorer"]


class Flow(BaseModel):
    src_ip: str = Field("10.0.1.20", description="Anonymised source identifier")
    dst_port: int = Field(443, ge=0, le=65535)
    protocol: Literal["TCP", "UDP", "ICMP", "OTHER"] = "TCP"
    duration_ms: float = Field(1800.0, ge=0)
    fwd_packets: int = Field(12, ge=0)
    bwd_packets: int = Field(10, ge=0)
    fwd_bytes: float = Field(7200.0, ge=0)
    bwd_bytes: float = Field(9100.0, ge=0)
    syn_flag_count: int = Field(1, ge=0)
    rst_flag_count: int = Field(0, ge=0)
    ack_flag_count: int = Field(18, ge=0)
    src_flow_count_60s: int = Field(2, ge=0, description="Flows from same source in previous 60 s")
    src_port_diversity_60s: int = Field(1, ge=0, description="Distinct destination ports from same source (60 s)")


class ScoreResponse(BaseModel):
    risk: float
    alert: bool
    priority: str
    supervised_probability: float
    anomaly_percentile: float
    threshold: float
    model_version: str
    top_factors: list[dict[str, Any]]
    summary: str
    disclaimer: str = "Risk score for triage only — not a determination of malicious intent."


@app.get("/health", tags=["system"])
def health() -> dict[str, Any]:
    s = db.get_meta("summary", {})
    return {"status": "ok", "version": __version__, "time": utcnow(), "model_version": s.get("model_version"),
            "scorer_ready": (settings.models_dir / "scorer.joblib").exists()}


@app.post("/score", response_model=ScoreResponse, tags=["detection"])
def score(flow: Flow) -> ScoreResponse:
    sc = scorer()
    df = add_flow_features(pd.DataFrame([flow.model_dump()]))
    out = sc.score_frame(df).iloc[0]
    contrib = substitution_contributions(sc.supervised, df[sc.features], sc.reference, sc.features).iloc[0]
    factors = top_factors(contrib, 4)
    return ScoreResponse(risk=round(float(out.risk), 4), alert=bool(out.alert), priority=str(out.priority),
                         supervised_probability=round(float(out.supervised_proba), 4),
                         anomaly_percentile=round(float(out.anomaly_pct), 4), threshold=round(sc.threshold, 4),
                         model_version=sc.version, top_factors=factors, summary=describe(factors[:3]))


@app.post("/score/batch", tags=["detection"])
def score_batch(flows: list[Flow]) -> list[dict[str, Any]]:
    if not flows or len(flows) > 5000:
        raise HTTPException(422, "Provide between 1 and 5000 flows.")
    sc = scorer()
    df = add_flow_features(pd.DataFrame([f.model_dump() for f in flows]))
    return to_jsonable(sc.score_frame(df).reset_index(drop=True).to_dict(orient="records"))


@app.get("/alerts", tags=["alerts"])
def alerts(limit: int = Query(100, ge=1, le=1000), priority: Literal["critical", "high", "medium", "low"] | None = None,
           min_risk: float = Query(0.0, ge=0, le=1)) -> list[dict[str, Any]]:
    sql = ("SELECT alert_id, flow_id, ts, src_ip, dst_port, protocol, risk, priority, supervised_proba, anomaly_pct, "
           "model_version, summary, factors_json FROM alerts WHERE risk >= ?")
    params: list[Any] = [min_risk]
    if priority:
        sql += " AND priority = ?"
        params.append(priority)
    sql += " ORDER BY risk DESC LIMIT ?"
    params.append(limit)
    return to_jsonable(db.query_df(sql, params).to_dict(orient="records"))


@app.get("/stats", tags=["alerts"])
def stats() -> dict[str, Any]:
    s = db.get_meta("summary")
    if not s:
        raise HTTPException(404, "No pipeline results yet.")
    return {"threshold": s["threshold"], "results": s["results"], "n_alerts": s["n_alerts"], "splits": s["splits"]}


@app.get("/windows", tags=["streaming"])
def windows(limit: int = Query(500, ge=1, le=5000)) -> list[dict[str, Any]]:
    return to_jsonable(db.query_df("SELECT * FROM windows ORDER BY window_start LIMIT ?", (limit,)).to_dict(orient="records"))
