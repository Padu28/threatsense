"""Cached access to the ThreatSense event store (no mock data)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from threatsense.common.config import get_settings  # noqa: E402
from threatsense.storage.database import Database  # noqa: E402

settings = get_settings()


def db() -> Database:
    return Database(settings.db_path)


def ensure_pipeline() -> None:
    if db().get_meta("summary") is None:
        with st.status("First launch — running the detection pipeline (≈35 s)…", expanded=True) as s:
            from threatsense.cli import generate_sample
            from threatsense.pipeline import run_pipeline

            st.write("Generating synthetic flow capture and context features…")
            generate_sample()
            st.write("Training baselines, supervised models, Isolation Forest and hybrid scorer…")
            run_pipeline()
            s.update(label="Pipeline complete", state="complete")
        st.cache_data.clear()


@st.cache_data(ttl=120)
def summary() -> dict:
    return db().get_meta("summary", {})


@st.cache_data(ttl=120)
def results(split: str = "test") -> pd.DataFrame:
    df = db().query_df("SELECT * FROM model_results WHERE split=?", (split,))
    df["metrics"] = df.metrics_json.apply(json.loads)
    df["curves"] = df.curves_json.apply(json.loads)
    return df


@st.cache_data(ttl=120)
def group_metrics() -> pd.DataFrame:
    return db().query_df("SELECT * FROM group_metrics")


@st.cache_data(ttl=120)
def windows() -> pd.DataFrame:
    w = db().query_df("SELECT * FROM windows ORDER BY window_start")
    w["window_start"] = pd.to_datetime(w.window_start)
    return w


@st.cache_data(ttl=120)
def alerts() -> pd.DataFrame:
    a = db().query_df("SELECT * FROM alerts ORDER BY ts")
    a["ts"] = pd.to_datetime(a.ts)
    a["factors"] = a.factors_json.apply(json.loads)
    a["deviations"] = a.deviations_json.apply(json.loads)
    return a


@st.cache_data(ttl=120)
def scored_flows() -> pd.DataFrame:
    f = db().query_df("SELECT * FROM scored_flows ORDER BY ts")
    f["ts"] = pd.to_datetime(f.ts)
    return f


def metric_table() -> pd.DataFrame:
    r = results("test")
    rows = [{"model": m, **met} for m, met in zip(r.model, r.metrics)]
    return pd.DataFrame(rows)
