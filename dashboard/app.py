"""ThreatSense analyst dashboard.

Run:  streamlit run dashboard/app.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import streamlit as st  # noqa: E402

st.set_page_config(page_title="ThreatSense · Network Analytics", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="collapsed")

import theme  # noqa: E402

import data  # noqa: E402

theme.apply_theme()
data.ensure_pipeline()

pages = {
    "Operations": [
        st.Page("views/overview.py", title="Overview", icon=":material/shield:", default=True),
        st.Page("views/live_alerts.py", title="Live Alerts", icon=":material/notifications_active:", url_path="live_alerts"),
        st.Page("views/alert_explorer.py", title="Alert Explorer", icon=":material/manage_search:", url_path="alert_explorer"),
    ],
    "Research": [
        st.Page("views/model_evaluation.py", title="Model Evaluation", icon=":material/query_stats:", url_path="model_evaluation"),
        st.Page("views/threshold_lab.py", title="Threshold Lab", icon=":material/tune:", url_path="threshold_lab"),
        st.Page("views/traffic_profile.py", title="Traffic Profiling", icon=":material/lan:", url_path="traffic_profile"),
    ],
}

nav = st.navigation(pages, position="top")

# ---- console strip: live alert ticker + controls (replaces the sidebar)
alerts = data.alerts()
crit = alerts[alerts.priority == "critical"].sort_values("ts", ascending=False).head(14)
c1, c2 = st.columns([6, 1])
with c1:
    theme.ticker([f"{r.priority.upper()} {r.src_ip} → :{r.dst_port}/{r.protocol} · risk {r.risk:.2f}" for r in crit.itertuples()])
with c2:
    if st.button("↻ refresh", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

nav.run()
s = data.summary()
st.markdown(
    f'<div class="disclaimer">Defensive research prototype · synthetic flow data · model {s.get("model_version", "—")} · '
    f'frozen threshold {s.get("threshold", {}).get("value", 0):.3f}. Scores prioritise analyst review — not certainty or '
    'proof of intent. No scanning or live capture is performed.</div>', unsafe_allow_html=True)
theme.footer()
