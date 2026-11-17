"""Animated replay of the held-out window with a live alert feed."""
import time

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import theme as t

import data

t.hero("Live Alerts", "Replay the held-out capture window by window. Includes benign-heavy periods so you see "
       "false-positive behaviour, not just an idealised attack demo.", badge="Streaming replay", icon="📡")

w = data.windows().reset_index(drop=True)
a = data.alerts()
thr = data.summary()["threshold"]["value"]

c1, c2 = st.columns([1, 4])
speed = c1.slider("Windows / second", 1, 30, 10)
play = c1.button("▶ Start replay", use_container_width=True)
pos = c2.slider("Scrub", 0, len(w) - 1, len(w) - 1)

kpi = st.empty()
chart = st.empty()
lc, rc = st.columns([1.4, 1])
gauge = lc.empty()
feed = rc.empty()


def gauge_fig(v: float) -> go.Figure:
    f = go.Figure(go.Indicator(mode="gauge+number", value=v, number=dict(valueformat=".2f"),
                               gauge=dict(axis=dict(range=[0, 1]), bar=dict(color=t.PRIMARY),
                                          steps=[dict(range=[0, thr], color="rgba(34,211,238,.12)"),
                                                 dict(range=[thr, 1], color="rgba(244,63,94,.15)")],
                                          threshold=dict(line=dict(color="#fff", width=3), value=thr))))
    return t.style_fig(f, 260, "Max risk in current window")


def render(i: int) -> None:
    cur = w.iloc[: i + 1]
    last = cur.iloc[-1]
    end = last.window_start + pd.Timedelta(minutes=5)
    seen = a[a.ts < end]
    fp = int((seen.is_attack == 0).sum())
    with kpi.container():
        t.kpis([
            ("Window", f"{last.window_start:%a %H:%M}", f"{i + 1}/{len(w)}", "🕒", t.SECONDARY),
            ("Flows (window)", f"{int(last.n_flows)}", f"{int(last.n_true_attacks)} truly malicious", "🌐", t.MUTED),
            ("Alerts (window)", f"{int(last.n_alerts)}", None, "🚨", t.PRIMARY),
            ("Alerts so far", f"{len(seen):,}", f"{fp} false positives", "📋", t.ACCENT),
        ])
    fig = go.Figure()
    fig.add_trace(go.Bar(x=cur.window_start, y=cur.n_true_attacks, name="true attacks", marker_color="rgba(244,63,94,.35)"))
    fig.add_trace(go.Scatter(x=cur.window_start, y=cur.n_alerts, name="alerts", mode="lines",
                             line=dict(color=t.SECONDARY, width=2.5, shape="spline")))
    fig.update_layout(xaxis=dict(range=[w.window_start.min(), w.window_start.max()]), barmode="overlay")
    chart.plotly_chart(t.style_fig(fig, 300), use_container_width=True, key=f"c{i}")
    gauge.plotly_chart(gauge_fig(float(last.max_risk)), use_container_width=True, key=f"g{i}")
    with feed.container():
        recent = seen.sort_values("ts", ascending=False).head(5)
        t.timeline([{"event_type": r.priority, "severity": "high" if r.priority in ("critical", "high") else "medium",
                     "batch_id": r.src_ip, "ts": f"{r.ts:%H:%M:%S} · risk {r.risk:.2f} · "
                     f"{'TP' if r.is_attack else 'FP'}", "message": r.summary} for r in recent.itertuples()], limit=5)


if play:
    for i in range(len(w)):
        render(i)
        time.sleep(1 / speed)
else:
    render(pos)
