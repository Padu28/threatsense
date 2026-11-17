import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import theme as t

import data

t.hero("Traffic Profiling", "Protocol, duration, volume and rate distributions of the analysed window, plus the dataset "
       "audit and time-aware split.", badge="Data audit", icon="🌐")

s = data.summary()
flows = data.scored_flows()
audit = s["audit"]

t.kpis([
    ("Total flows", f"{audit['n_rows']:,}", None, "🌐", t.SECONDARY),
    ("Attack prevalence", f"{audit['attack_rate']:.1%}", "class imbalance", "⚖️", t.PRIMARY),
    ("Duplicates", f"{audit['duplicate_rows']}", None, "🧬", t.ACCENT),
    ("Null cells", f"{audit['null_cells']}", None, "🕳️", t.WARNING),
    ("Time-ordered", "yes" if audit["time_ordered"] else "no", None, "⏱️", t.SUCCESS),
])

t.section("Time-aware split", "campaigns never straddle train and test")
sp = pd.DataFrame(s["splits"]).T.reset_index(names="split")
fig = go.Figure()
colors = {"train": t.SECONDARY, "validation": t.ACCENT, "test": t.PRIMARY}
for r in sp.itertuples():
    fig.add_trace(go.Bar(x=[pd.Timestamp(r.end) - pd.Timestamp(r.start)], base=[pd.Timestamp(r.start)], y=["capture"],
                         orientation="h", name=f"{r.split} · {r.n:,} flows · {r.attack_rate:.1%} attacks",
                         marker_color=colors[r.split]))
fig.update_layout(barmode="stack", xaxis_type="date", height=170, legend=dict(y=1.5))
st.plotly_chart(t.style_fig(fig, 190), use_container_width=True)

cats = pd.DataFrame(s["splits"]).loc["categories"].apply(pd.Series).fillna(0).astype(int)
st.dataframe(cats, use_container_width=True)

t.section("Distributions in the test window", "log scale")
c1, c2 = st.columns(2)
feat = c1.selectbox("Feature", ["fwd_bytes", "flow_bytes_per_s", "duration_ms", "src_flow_count_60s", "src_port_diversity_60s"])
color_by = c2.radio("Colour by", ["category", "protocol"], horizontal=True)
d = flows.assign(log_value=np.log10(flows[feat].clip(lower=0) + 1))
fig = px.histogram(d, x="log_value", color=color_by, nbins=70, barmode="overlay", opacity=0.75,
                   color_discrete_map=t.CATEGORY_COLORS if color_by == "category" else None)
fig.update_layout(xaxis_title=f"log10({feat} + 1)", yaxis_type="log")
st.plotly_chart(t.style_fig(fig, 360), use_container_width=True)

c1, c2 = st.columns(2)
with c1:
    t.section("Volume vs. rate", "sample of 4 000 flows")
    smp = flows.sample(min(4000, len(flows)), random_state=0)
    fig = px.scatter(smp, x="duration_ms", y="fwd_bytes", color="category", log_x=True, log_y=True, opacity=0.7,
                     color_discrete_map=t.CATEGORY_COLORS, hover_data=["src_ip", "dst_port", "risk"])
    st.plotly_chart(t.style_fig(fig, 380), use_container_width=True)
with c2:
    t.section("Protocol mix")
    pm = flows.groupby(["protocol", "category"]).size().reset_index(name="n")
    fig = px.sunburst(pm, path=["protocol", "category"], values="n", color="category", color_discrete_map=t.CATEGORY_COLORS)
    st.plotly_chart(t.style_fig(fig, 380), use_container_width=True)
