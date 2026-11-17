import numpy as np
import plotly.graph_objects as go
import streamlit as st
import theme as t

import data

t.hero("Threshold Lab", "Explore the precision / recall / workload trade-off on the VALIDATION window. The production "
       "threshold was frozen here before the test window was scored.", badge="Validation only", icon="🎚️")

val = data.results("validation").iloc[0]
risk = np.array(val.curves["risk"])
y = np.array(val.curves["y"])
frozen = val.metrics["value"]

grid = np.linspace(0.01, 0.99, 197)
tp = np.array([((risk >= g) & (y == 1)).sum() for g in grid])
fp = np.array([((risk >= g) & (y == 0)).sum() for g in grid])
pos, neg = max((y == 1).sum(), 1), max((y == 0).sum(), 1)
recall, fpr = tp / pos, fp / neg
precision = tp / np.maximum(tp + fp, 1)
per10k = (tp + fp) / len(y) * 10_000

thr = st.slider("Candidate threshold", 0.01, 0.99, float(round(frozen, 2)), 0.01)
i = int(np.argmin(np.abs(grid - thr)))
t.kpis([
    ("Recall", f"{recall[i]:.1%}", None, "🧲", t.SUCCESS),
    ("Precision", f"{precision[i]:.1%}", None, "🎯", t.SECONDARY),
    ("False-positive rate", f"{fpr[i]:.2%}", "▼ within budget" if fpr[i] <= 0.01 else "▲ over 1% budget", "🧯", t.WARNING),
    ("Analyst workload", f"{per10k[i]:.0f}", "alerts per 10k flows", "👩‍💻", t.PRIMARY),
    ("Frozen threshold", f"{frozen:.3f}", "selected on validation", "🔒", t.ACCENT),
])

fig = go.Figure()
fig.add_trace(go.Scatter(x=grid, y=recall, name="recall", line=dict(color=t.SUCCESS, width=3)))
fig.add_trace(go.Scatter(x=grid, y=precision, name="precision", line=dict(color=t.SECONDARY, width=3)))
fig.add_trace(go.Scatter(x=grid, y=fpr * 10, name="FPR × 10", line=dict(color=t.WARNING, width=2, dash="dash")))
fig.add_vline(x=frozen, line_color="#fff", line_dash="dot", annotation_text="frozen")
fig.add_vline(x=thr, line_color=t.PRIMARY, annotation_text="candidate")
fig.update_layout(xaxis_title="threshold on hybrid risk", yaxis_range=[0, 1.05])
st.plotly_chart(t.style_fig(fig, 380), use_container_width=True)

c1, c2 = st.columns(2)
with c1:
    t.section("Risk distribution", "validation · log scale")
    fig = go.Figure()
    fig.add_trace(go.Histogram(x=risk[y == 0], name="benign", nbinsx=60, marker_color="rgba(56,189,248,.6)"))
    fig.add_trace(go.Histogram(x=risk[y == 1], name="attack", nbinsx=60, marker_color="rgba(244,63,94,.65)"))
    fig.add_vline(x=thr, line_color=t.PRIMARY)
    fig.update_layout(barmode="overlay", yaxis_type="log")
    st.plotly_chart(t.style_fig(fig, 320), use_container_width=True)
with c2:
    t.section("Workload vs. recall")
    fig = go.Figure(go.Scatter(x=per10k, y=recall, mode="lines", line=dict(color=t.PRIMARY, width=3),
                               fill="tozeroy", fillcolor="rgba(244,63,94,.08)"))
    fig.add_trace(go.Scatter(x=[per10k[i]], y=[recall[i]], mode="markers", marker=dict(size=16, color="#fff")))
    fig.update_layout(showlegend=False, xaxis_title="alerts per 10k flows", yaxis_title="recall")
    st.plotly_chart(t.style_fig(fig, 320), use_container_width=True)

st.markdown('<div class="disclaimer">Changing the threshold here does not change reported test results — re-selecting a '
            'threshold after seeing test labels would leak information. Update <code>configs/thresholds.yaml</code> '
            'and rerun the pipeline instead.</div>', unsafe_allow_html=True)
