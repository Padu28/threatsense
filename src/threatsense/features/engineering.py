"""Flow-level and source-context feature engineering.

Context features use *only past* flows from the same source (strictly earlier
timestamps inside a sliding window) so they never leak future information.
"""
from __future__ import annotations

from collections import defaultdict, deque

import numpy as np
import pandas as pd

from threatsense.ingestion.synthetic import WELL_KNOWN


def add_flow_features(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    dur_s = np.maximum(out["duration_ms"], 1.0) / 1000.0
    pkts = out["fwd_packets"] + out["bwd_packets"]
    byts = out["fwd_bytes"] + out["bwd_bytes"]
    out["flow_bytes_per_s"] = byts / dur_s
    out["flow_packets_per_s"] = pkts / dur_s
    out["mean_pkt_size"] = byts / np.maximum(pkts, 1)
    out["fwd_bwd_byte_ratio"] = (out["fwd_bytes"] + 1) / (out["bwd_bytes"] + 1)
    if "iat_mean_ms" not in out or out["iat_mean_ms"].isna().all():
        out["iat_mean_ms"] = out["duration_ms"] / np.maximum(pkts - 1, 1)
    out["dst_port_is_wellknown"] = out["dst_port"].isin(WELL_KNOWN).astype(int)
    return out


def add_context_features(df: pd.DataFrame, window_s: float = 60.0) -> pd.DataFrame:
    """Per-source flow count and destination-port diversity over the previous ``window_s`` seconds."""
    out = df.sort_values("timestamp", kind="stable").copy()
    ts = (out["timestamp"] - out["timestamp"].min()).dt.total_seconds().to_numpy()
    srcs = out["src_ip"].to_numpy()
    ports = out["dst_port"].to_numpy()
    hist: dict[str, deque] = defaultdict(deque)
    counts = np.zeros(len(out), dtype=np.int32)
    diversity = np.zeros(len(out), dtype=np.int32)
    for i in range(len(out)):
        q = hist[srcs[i]]
        while q and q[0][0] < ts[i] - window_s:
            q.popleft()
        counts[i] = len(q)
        diversity[i] = len({p for _, p in q})
        q.append((ts[i], ports[i]))
    out["src_flow_count_60s"] = counts
    out["src_port_diversity_60s"] = diversity
    return out


def build_features(df: pd.DataFrame, window_s: float = 60.0) -> pd.DataFrame:
    return add_context_features(add_flow_features(df), window_s)


def time_split(df: pd.DataFrame, train: float, validation: float) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split by *time*, never by random shuffling, so campaigns don't leak across sets."""
    t0, t1 = df["timestamp"].min(), df["timestamp"].max()
    c1 = t0 + (t1 - t0) * train
    c2 = t0 + (t1 - t0) * (train + validation)
    return (df[df.timestamp < c1].copy(), df[(df.timestamp >= c1) & (df.timestamp < c2)].copy(),
            df[df.timestamp >= c2].copy())
