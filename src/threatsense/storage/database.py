"""SQLite event store (prototype; PostgreSQL-ready via the same interface)."""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value_json TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS model_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT, model TEXT, split TEXT, metrics_json TEXT, curves_json TEXT,
    created_at TEXT);
CREATE TABLE IF NOT EXISTS group_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT, model TEXT, grouping TEXT, grp TEXT, n INTEGER, n_attack INTEGER,
    recall REAL, fpr REAL);
CREATE TABLE IF NOT EXISTS windows (
    window_start TEXT PRIMARY KEY, n_flows INTEGER, n_alerts INTEGER, n_true_attacks INTEGER,
    mean_risk REAL, max_risk REAL, alert_rate REAL);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT, flow_id TEXT, ts TEXT, src_ip TEXT, dst_port INTEGER,
    protocol TEXT, true_category TEXT, is_attack INTEGER, risk REAL, priority TEXT, supervised_proba REAL,
    anomaly_pct REAL, model_version TEXT, factors_json TEXT, deviations_json TEXT, summary TEXT,
    status TEXT DEFAULT 'open');
CREATE TABLE IF NOT EXISTS scored_flows (
    flow_id TEXT PRIMARY KEY, ts TEXT, src_ip TEXT, dst_port INTEGER, protocol TEXT, category TEXT,
    is_attack INTEGER, risk REAL, supervised_proba REAL, anomaly_pct REAL, zscore REAL, alert INTEGER,
    fwd_bytes REAL, flow_bytes_per_s REAL, duration_ms REAL, src_flow_count_60s REAL, src_port_diversity_60s REAL);
CREATE INDEX IF NOT EXISTS ix_alert_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS ix_flow_ts ON scored_flows(ts);
"""


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self.path, timeout=30)
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def reset(self) -> None:
        with self.connect() as c:
            for t in ("meta", "model_results", "group_metrics", "windows", "alerts", "scored_flows"):
                c.execute(f"DELETE FROM {t}")

    def put_meta(self, key: str, value: Any) -> None:
        with self.connect() as c:
            c.execute("INSERT OR REPLACE INTO meta VALUES (?, ?, ?)", (key, json.dumps(value, default=str), utcnow()))

    def get_meta(self, key: str, default: Any = None) -> Any:
        with self.connect() as c:
            row = c.execute("SELECT value_json FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def write_df(self, table: str, df: pd.DataFrame) -> None:
        with self.connect() as c:
            df.to_sql(table, c, if_exists="append", index=False)

    def query_df(self, sql: str, params: tuple | list = ()) -> pd.DataFrame:
        with self.connect() as c:
            return pd.read_sql_query(sql, c, params=params)

    def execute(self, sql: str, params: tuple | list = ()) -> None:
        with self.connect() as c:
            c.execute(sql, params)
