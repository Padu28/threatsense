"""Synthetic network-flow capture for reproducible, *defensive* experiments.

Generates flow-level records (no payloads, no real addresses) shaped like
CIC-IDS style features. Attack *campaigns* are placed in time so that a
time-aware split keeps them apart, and one category (``exfiltration``) only
occurs in the final (test) window to measure novel-attack detection.

This data is SYNTHETIC. It is suitable for unit tests and demonstrations,
not as proof of real-world detection performance.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

WELL_KNOWN = np.array([443, 80, 53, 22, 25, 123, 3389, 8080, 993, 445])
WELL_KNOWN_P = np.array([0.42, 0.18, 0.16, 0.04, 0.03, 0.04, 0.02, 0.05, 0.03, 0.03])
T0 = pd.Timestamp("2026-03-02 00:00:00")


def _ips(rng: np.random.Generator, n: int, subnet: str, pool: int) -> np.ndarray:
    hosts = np.array([f"{subnet}.{i}" for i in rng.choice(np.arange(2, 254), size=pool, replace=False)])
    return rng.choice(hosts, size=n)


def _benign(rng: np.random.Generator, n: int, hours: float) -> pd.DataFrame:
    # Diurnal arrival process: more traffic in working hours
    t = rng.uniform(0, hours * 3600, size=n * 2)
    hour = (t / 3600) % 24
    keep = rng.random(len(t)) < (0.35 + 0.65 * np.exp(-((hour - 14) ** 2) / 30))
    t = np.sort(t[keep][:n])
    n = len(t)
    proto = rng.choice(["TCP", "UDP", "ICMP"], size=n, p=[0.72, 0.25, 0.03])
    port = rng.choice(WELL_KNOWN, size=n, p=WELL_KNOWN_P)
    port = np.where(rng.random(n) < 0.08, rng.integers(1024, 65535, n), port)
    port = np.where(proto == "ICMP", 0, np.where(proto == "UDP", np.where(rng.random(n) < 0.7, 53, port), port))
    fwd_p = np.maximum(1, rng.lognormal(2.0, 0.9, n)).astype(int)
    bwd_p = np.maximum(0, (fwd_p * rng.uniform(0.6, 1.6, n))).astype(int)
    pkt = np.clip(rng.normal(620, 320, n), 60, 1500)
    # A minority of benign "large upload" flows makes exfiltration non-trivial
    upload = rng.random(n) < 0.015
    fwd_p = np.where(upload, fwd_p * rng.integers(20, 60, n), fwd_p)
    fwd_b = fwd_p * pkt * rng.uniform(0.8, 1.2, n)
    bwd_b = bwd_p * np.clip(rng.normal(700, 350, n), 60, 1500)
    dur = rng.lognormal(7.5, 1.4, n) * np.where(upload, 6, 1)
    return pd.DataFrame({
        "t": t, "src_ip": _ips(rng, n, "10.0.1", 180), "dst_port": port, "protocol": proto,
        "duration_ms": dur, "fwd_packets": fwd_p, "bwd_packets": bwd_p, "fwd_bytes": fwd_b, "bwd_bytes": bwd_b,
        "syn_flag_count": np.where(proto == "TCP", 1, 0) + (rng.random(n) < 0.03),
        "rst_flag_count": (rng.random(n) < 0.04).astype(int),
        "ack_flag_count": np.where(proto == "TCP", np.maximum(1, (fwd_p + bwd_p) * 0.8).astype(int), 0),
        "category": "benign",
    })


def _campaign(rng: np.random.Generator, kind: str, start_h: float, minutes: float, n: int) -> pd.DataFrame:
    t = np.sort(start_h * 3600 + rng.uniform(0, minutes * 60, n))
    if kind == "dos":
        src = _ips(rng, n, "172.16.9", 6)
        port = rng.choice([80, 443], n)
        fwd_p = rng.integers(40, 400, n)
        bwd_p = rng.integers(0, 4, n)
        pkt = rng.normal(70, 15, n).clip(40, 200)
        dur = rng.lognormal(5.0, 0.8, n)
        syn, rst, proto = fwd_p * rng.uniform(0.6, 1.0, n), rng.integers(0, 3, n), np.array(["TCP"] * n)
        bwd_pkt = 60
    elif kind == "portscan":
        src = _ips(rng, n, "172.16.4", 2)
        port = rng.integers(1, 65535, n)
        fwd_p = rng.integers(1, 3, n)
        bwd_p = rng.integers(0, 2, n)
        pkt = np.full(n, 60.0)
        dur = rng.lognormal(2.5, 0.7, n)
        syn, rst, proto = np.ones(n), rng.integers(1, 3, n), np.array(["TCP"] * n)
        bwd_pkt = 54
    elif kind == "bruteforce":
        src = _ips(rng, n, "172.16.7", 3)
        port = rng.choice([22, 3389, 21], n, p=[0.6, 0.3, 0.1])
        fwd_p = rng.integers(8, 24, n)
        bwd_p = (fwd_p * rng.uniform(0.8, 1.1, n)).astype(int)
        pkt = rng.normal(140, 20, n).clip(80, 300)
        dur = rng.lognormal(7.8, 0.4, n)
        syn, rst, proto = np.ones(n), (rng.random(n) < 0.5).astype(int), np.array(["TCP"] * n)
        bwd_pkt = 130
    elif kind == "exfiltration":
        src = _ips(rng, n, "10.0.1", 1)              # a compromised *internal* host
        port = np.full(n, 443)                       # blends with HTTPS
        fwd_p = rng.integers(1500, 6000, n)
        bwd_p = rng.integers(20, 120, n)
        pkt = rng.normal(1380, 60, n).clip(900, 1500)
        dur = rng.lognormal(11.0, 0.5, n)
        syn, rst, proto = np.ones(n), np.zeros(n), np.array(["TCP"] * n)
        bwd_pkt = 90
    else:
        raise ValueError(kind)
    fwd_b = fwd_p * pkt
    return pd.DataFrame({
        "t": t, "src_ip": src, "dst_port": port, "protocol": proto, "duration_ms": dur,
        "fwd_packets": fwd_p, "bwd_packets": bwd_p, "fwd_bytes": fwd_b, "bwd_bytes": bwd_p * bwd_pkt,
        "syn_flag_count": syn.astype(int), "rst_flag_count": rst.astype(int),
        "ack_flag_count": np.maximum(0, bwd_p).astype(int), "category": kind,
    })


def _botnet(rng: np.random.Generator, hosts: int, start_h: float, end_h: float, every_s: float) -> pd.DataFrame:
    frames = []
    for h in range(hosts):
        t = np.arange(start_h * 3600 + h * 37, end_h * 3600, every_s) + rng.normal(0, 4, 1)
        t = t + rng.normal(0, 2.5, len(t))
        n = len(t)
        frames.append(pd.DataFrame({
            "t": t, "src_ip": f"10.0.1.{240 + h}", "dst_port": rng.choice([8080, 6667, 443], n, p=[0.5, 0.3, 0.2]),
            "protocol": "TCP", "duration_ms": rng.lognormal(6.2, 0.2, n), "fwd_packets": rng.integers(3, 6, n),
            "bwd_packets": rng.integers(2, 5, n), "fwd_bytes": rng.normal(310, 20, n), "bwd_bytes": rng.normal(240, 20, n),
            "syn_flag_count": 1, "rst_flag_count": 0, "ack_flag_count": rng.integers(3, 8, n), "category": "botnet",
        }))
    return pd.concat(frames)


def generate_flows(cfg: dict, seed: int | None = None) -> pd.DataFrame:
    rng = np.random.default_rng(cfg.get("seed", 42) if seed is None else seed)
    hours = cfg["hours"]
    parts = [_benign(rng, cfg["n_benign"], hours)]
    for kind, camps in cfg["campaigns"].items():
        for start, minutes, n in camps:
            parts.append(_campaign(rng, kind, start, minutes, n))
    b = cfg["botnet"]
    parts.append(_botnet(rng, b["hosts"], b["start_hour"], hours, b["beacon_seconds"]))
    df = pd.concat(parts, ignore_index=True)
    df = df[(df.t >= 0) & (df.t < hours * 3600)].sort_values("t", kind="stable").reset_index(drop=True)

    df["timestamp"] = T0 + pd.to_timedelta(df.pop("t"), unit="s")
    df["is_attack"] = (df.category != "benign").astype(int)
    # 0.5 % label noise — real IDS labels are imperfect
    noise = rng.random(len(df)) < 0.005
    df.loc[noise & (df.category == "benign"), "is_attack"] = 1
    df["flow_id"] = [f"F{i:07d}" for i in range(len(df))]
    df["is_synthetic"] = True
    return df
