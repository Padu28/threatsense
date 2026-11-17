"""Dataset loaders: synthetic capture and CIC-IDS2017 CSVs (column-mapped)."""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from threatsense.common.config import PROJECT_ROOT, get_settings
from threatsense.ingestion.synthetic import generate_flows

# CIC-IDS2017 column → ThreatSense column (columns are stripped of whitespace first)
CICIDS_MAP = {
    "Destination Port": "dst_port",
    "Flow Duration": "duration_ms",            # microseconds in CIC → converted below
    "Total Fwd Packets": "fwd_packets",
    "Total Backward Packets": "bwd_packets",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
    "SYN Flag Count": "syn_flag_count",
    "RST Flag Count": "rst_flag_count",
    "ACK Flag Count": "ack_flag_count",
    "Flow IAT Mean": "iat_mean_ms",
    "Label": "label_raw",
}

REQUIRED = ["timestamp", "src_ip", "dst_port", "protocol", "duration_ms", "fwd_packets", "bwd_packets",
            "fwd_bytes", "bwd_bytes", "syn_flag_count", "rst_flag_count", "ack_flag_count", "category", "is_attack"]


def load_cicids2017(raw_dir: Path) -> pd.DataFrame:
    files = sorted(Path(raw_dir).glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CIC-IDS2017 CSVs in {raw_dir}. See docs/DATA_CARD.md.")
    frames = []
    for f in files:
        d = pd.read_csv(f, low_memory=False)
        d.columns = d.columns.str.strip()
        frames.append(d)
    raw = pd.concat(frames, ignore_index=True).replace([np.inf, -np.inf], np.nan)
    df = raw.rename(columns=CICIDS_MAP)
    df["duration_ms"] = df["duration_ms"] / 1000.0
    df["iat_mean_ms"] = df.get("iat_mean_ms", 0) / 1000.0
    df["timestamp"] = pd.to_datetime(raw.get("Timestamp"), errors="coerce", dayfirst=True)
    df["src_ip"] = raw.get("Source IP", "unknown")
    df["protocol"] = raw.get("Protocol", 6).map({6: "TCP", 17: "UDP", 0: "ICMP"}).fillna("OTHER")
    lab = df["label_raw"].astype(str).str.strip()
    df["category"] = lab.str.lower().where(lab != "BENIGN", "benign")
    df["is_attack"] = (lab != "BENIGN").astype(int)
    df = df.dropna(subset=["timestamp"]).sort_values("timestamp", kind="stable").reset_index(drop=True)
    df["flow_id"] = [f"C{i:08d}" for i in range(len(df))]
    return df


def load_flows() -> pd.DataFrame:
    s = get_settings()
    if s.dataset["source"] == "cicids2017":
        return load_cicids2017(PROJECT_ROOT / s.dataset["raw_dir"])
    return generate_flows(s.dataset["synthetic"])


def validate_flows(df: pd.DataFrame) -> dict:
    """Schema, type, missingness and duplicate audit (runs before any modelling)."""
    missing = [c for c in REQUIRED if c not in df.columns]
    num = df.select_dtypes("number")
    return {
        "n_rows": len(df),
        "missing_columns": missing,
        "null_cells": int(df[[c for c in REQUIRED if c in df]].isna().sum().sum()),
        "duplicate_rows": int(df.drop(columns=["flow_id", "timestamp"], errors="ignore").duplicated().sum()),
        "negative_values": int((num.drop(columns=["is_attack"], errors="ignore") < 0).sum().sum()),
        "attack_rate": float(df["is_attack"].mean()) if "is_attack" in df else None,
        "categories": df["category"].value_counts().to_dict() if "category" in df else {},
        "time_ordered": bool(df["timestamp"].is_monotonic_increasing) if "timestamp" in df else False,
    }
