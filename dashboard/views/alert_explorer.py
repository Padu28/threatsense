import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import theme as t

import data

t.hero("Alert Explorer", "Filter alerts by time, priority, score, protocol and port, then open the explanation panel: "
       "model contributions and deviation from the benign traffic profile.", badge="Analyst view", icon="🔎")

a = data.alerts()
with st.container(border=True):
    c1, c2, c3, c4 = st.columns(4)
    pri = c1.multiselect("Priority", ["critical", "high", "medium", "low"], default=["critical", "high", "medium"])
    proto = c2.multiselect("Protocol", sorted(a.protocol.unique()), default=sorted(a.protocol.unique()))
    rmin = c3.slider("Min risk", 0.0, 1.0, float(round(a.risk.min(), 2)), 0.01)
    tmin, tmax = a.ts.min().to_pydatetime(), a.ts.max().to_pydatetime()
    rng = c4.slider("Time range", tmin, tmax, (tmin, tmax), format="MM-DD HH:mm")
    show_truth = st.toggle("Reveal ground truth (research mode)", value=True)

f = a[a.priority.isin(pri) & a.protocol.isin(proto) & (a.risk >= rmin) & a.ts.between(pd.Timestamp(rng[0]), pd.Timestamp(rng[1]))]
t.kpis([
    ("Matching alerts", f"{len(f):,}", None, "📋", t.PRIMARY),
    ("Unique sources", f"{f.src_ip.nunique()}", None, "🖥️", t.SECONDARY),
    ("Median risk", f"{f.risk.median():.2f}" if len(f) else "—", None, "📈", t.ACCENT),
    ("Precision (filtered)", f"{f.is_attack.mean():.1%}" if len(f) and show_truth else "hidden", None, "🎯", t.SUCCESS),
])

cols = ["alert_id", "ts", "src_ip", "dst_port", "protocol", "risk", "priority", "supervised_proba", "anomaly_pct", "summary"]
if show_truth:
    cols.insert(5, "true_category")
sel = st.dataframe(
    f[cols].sort_values("risk", ascending=False), use_container_width=True, hide_index=True, height=320,
    on_select="rerun", selection_mode="single-row",
    column_config={"risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=1, format="%.2f"),
                   "supervised_proba": st.column_config.NumberColumn("Supervised p", format="%.2f"),
                   "anomaly_pct": st.column_config.NumberColumn("Anomaly pct", format="%.2f"),
                   "ts": st.column_config.DatetimeColumn("Time", format="MM-DD HH:mm:ss")},
)

rows = sel.selection.rows if sel and sel.selection else []
row = f.sort_values("risk", ascending=False).iloc[rows[0]] if rows else (f.sort_values("risk", ascending=False).iloc[0] if len(f) else None)
if row is not None:
    t.section(f"Alert #{row.alert_id}", f"{row.src_ip} → :{row.dst_port}/{row.protocol} · {row.ts:%Y-%m-%d %H:%M:%S}")
    c1, c2, c3 = st.columns([0.8, 1.1, 1.1])
    with c1:
        t.ring(row.risk * 100, "Hybrid risk ×100", t.PRIORITY_COLORS.get(row.priority))
        st.markdown(f"<div style='text-align:center;margin-top:10px'>{t.chip(row.priority, t.PRIORITY_COLORS[row.priority])} "
                    f"{t.chip(row.model_version, t.MUTED)}</div>", unsafe_allow_html=True)
        st.markdown(f"<div class='card' style='margin-top:12px'><p>{row.summary}</p></div>", unsafe_allow_html=True)
    with c2:
        fac = pd.DataFrame(row.factors)
        fig = go.Figure(go.Bar(x=fac.contribution, y=fac.feature, orientation="h",
                               marker_color=[t.PRIMARY if v > 0 else t.SUCCESS for v in fac.contribution]))
        fig.update_yaxes(autorange="reversed")
        st.plotly_chart(t.style_fig(fig, 280, "Model contributions (risk drop if set to benign median)"), use_container_width=True)
    with c3:
        dev = pd.Series(row.deviations).sort_values()
        fig = go.Figure(go.Bar(x=dev.values, y=dev.index, orientation="h",
                               marker=dict(color=dev.abs().values, colorscale=[[0, t.SECONDARY], [1, t.PRIMARY]])))
        st.plotly_chart(t.style_fig(fig, 280, "Deviation from benign profile (robust z)"), use_container_width=True)
    st.markdown('<div class="disclaimer">Contributions show what the model reacted to; they are associations, not causal '
                'attribution, and do not establish malicious intent. Verify with additional context before acting.</div>',
                unsafe_allow_html=True)
