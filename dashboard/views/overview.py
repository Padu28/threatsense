import plotly.graph_objects as go
import streamlit as st
import theme as t

import data

s = data.summary()
res = s["results"]
hy, rf = res["hybrid"], res["random_forest"]
w = data.windows()
a = data.alerts()
t.hero("ThreatSense", "Hybrid network-flow anomaly detection: calibrated supervised risk blended with an Isolation "
       "Forest novelty score, thresholds frozen on validation, and every alert explained.",
       badge="Monitoring test window", icon="🛡️", level=int(round(100 * (a.priority == "critical").mean())))

t.kpis([
    ("Flows analysed", f"{int(w.n_flows.sum()):,}", f"{len(w)} × 5-min windows", "🌐", t.SECONDARY),
    ("Alerts raised", f"{len(a):,}", f"{hy['alerts_per_10k']:.0f} per 10k flows", "🚨", t.PRIMARY),
    ("Hybrid PR-AUC", f"{hy['pr_auc']:.3f}", f"{hy['pr_auc'] - rf['pr_auc']:+.3f} vs random forest", "🎯", t.SUCCESS),
    ("Recall @ frozen thr.", f"{hy['recall']:.1%}", f"precision {hy['precision']:.1%}", "🧲", t.ACCENT),
    ("False alerts / 10k", f"{hy['false_alerts_per_10k']:.0f}", f"FPR {hy['fpr']:.2%}", "🧯", t.WARNING),
])

t.section("Detection pipeline")
t.flow([("Flow records", "CIC-IDS style"), ("Context features", "per-source 60 s window"), ("Supervised", "RF · calibrated"),
        ("Isolation Forest", "benign-only novelty"), ("Hybrid risk", "0.7 · p + 0.3 · pct"), ("Frozen threshold", "FPR ≤ 1 % on val"),
        ("Explained alert", "top factors")])

t.section("Traffic & alerts over the test window", "bars: true attack flows · line: alerts")
fig = go.Figure()
fig.add_trace(go.Bar(x=w.window_start, y=w.n_flows, name="all flows", marker_color="rgba(148,163,184,.18)"))
fig.add_trace(go.Bar(x=w.window_start, y=w.n_true_attacks, name="true attacks", marker_color="rgba(244,63,94,.45)"))
fig.add_trace(go.Scatter(x=w.window_start, y=w.n_alerts, name="alerts", line=dict(color=t.SECONDARY, width=2.5, shape="spline")))
fig.update_layout(barmode="overlay", xaxis_title="", yaxis_title="flows / window")
st.plotly_chart(t.style_fig(fig, 340), use_container_width=True)

c1, c2 = st.columns([1, 1.3])
with c1:
    t.section("Alert priority mix")
    pm = a.priority.value_counts().reindex(["critical", "high", "medium", "low"]).fillna(0)
    fig = go.Figure(go.Pie(labels=pm.index, values=pm.values, hole=0.62, sort=False,
                           marker=dict(colors=[t.PRIORITY_COLORS[k] for k in pm.index], line=dict(color=t.BG, width=3))))
    fig.update_layout(annotations=[dict(text=f"<b>{len(a)}</b><br>alerts", showarrow=False, font=dict(size=18))])
    st.plotly_chart(t.style_fig(fig, 320), use_container_width=True)
with c2:
    t.section("Latest critical alerts")
    crit = a[a.priority == "critical"].sort_values("ts", ascending=False).head(6)
    t.timeline([{"event_type": r.priority, "severity": "critical", "batch_id": r.src_ip,
                 "ts": f"{r.ts:%m-%d %H:%M:%S} · :{r.dst_port}/{r.protocol} · risk {r.risk:.2f}",
                 "message": r.summary} for r in crit.itertuples()], limit=6)

c1, c2, c3 = st.columns(3)
with c1:
    t.card("Novel-attack coverage", "Exfiltration never appears in training. The supervised model alone misses part of it; "
           "the benign-trained Isolation Forest component recovers it in the hybrid score.", t.SECONDARY)
with c2:
    t.card("Threshold discipline", f"Threshold <b>{s['threshold']['value']:.3f}</b> selected on validation "
           f"({s['threshold']['policy']}) and frozen before touching test labels.", t.ACCENT)
with c3:
    t.card("Safe-use boundary", "Analytics on recorded flow metadata only — no packet payloads, scanning, exploitation "
           "or credential collection.", t.PRIMARY)
