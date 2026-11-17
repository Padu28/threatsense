import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import theme as t

import data

t.hero("Model Evaluation", "Imbalance-aware comparison on the held-out time window: PR-AUC first, accuracy never. "
       "Trivial and statistical baselines are included on purpose.", badge="Test window", icon="📊")

mt = data.metric_table()
res = data.results("test")
order = ["majority_class", "zscore_threshold", "logistic_regression", "random_forest", "hist_gradient_boosting",
         "isolation_forest", "hybrid"]
mt["model"] = pd.Categorical(mt.model, order, ordered=True)
mt = mt.sort_values("model")

t.section("Leaderboard", "thresholds frozen on validation · PR-AUC with bootstrap 95% CI")
show = mt[["model", "pr_auc", "roc_auc", "precision", "recall", "f1", "fpr", "alerts_per_10k", "false_alerts_per_10k"]]
st.dataframe(show, use_container_width=True, hide_index=True, column_config={
    "pr_auc": st.column_config.ProgressColumn("PR-AUC", min_value=0, max_value=1, format="%.3f"),
    "recall": st.column_config.ProgressColumn("Recall", min_value=0, max_value=1, format="%.3f"),
    "precision": st.column_config.NumberColumn("Precision", format="%.3f"),
    "roc_auc": st.column_config.NumberColumn("ROC-AUC", format="%.3f"),
    "f1": st.column_config.NumberColumn("F1", format="%.3f"),
    "fpr": st.column_config.NumberColumn("FPR", format="%.4f"),
    "alerts_per_10k": st.column_config.NumberColumn("Alerts/10k", format="%.0f"),
    "false_alerts_per_10k": st.column_config.NumberColumn("False/10k", format="%.0f"),
})

c1, c2 = st.columns(2)
with c1:
    t.section("Precision–recall curves")
    fig = go.Figure()
    for r in res.itertuples():
        if r.model == "majority_class":
            continue
        fig.add_trace(go.Scatter(x=r.curves["recall"], y=r.curves["precision"], name=f"{r.model} ({r.metrics['pr_auc']:.3f})",
                                 line=dict(color=t.MODEL_COLORS.get(r.model), width=3 if r.model == "hybrid" else 1.8)))
    base = mt[mt.model == "majority_class"].pr_auc.iloc[0]
    fig.add_hline(y=base, line_dash="dot", line_color=t.MUTED, annotation_text="prevalence")
    fig.update_layout(xaxis_title="recall", yaxis_title="precision", yaxis_range=[0, 1.03], legend=dict(y=-0.25))
    st.plotly_chart(t.style_fig(fig, 420), use_container_width=True)
with c2:
    t.section("ROC curves (log FPR)")
    fig = go.Figure()
    for r in res.itertuples():
        if r.model == "majority_class":
            continue
        fpr = np.maximum(r.curves["fpr"], 1e-4)
        fig.add_trace(go.Scatter(x=fpr, y=r.curves["tpr"], name=r.model,
                                 line=dict(color=t.MODEL_COLORS.get(r.model), width=3 if r.model == "hybrid" else 1.8)))
    fig.add_vline(x=0.01, line_dash="dot", line_color=t.WARNING, annotation_text="FPR budget")
    fig.update_layout(xaxis=dict(type="log", title="false-positive rate"), yaxis_title="true-positive rate",
                      legend=dict(y=-0.25))
    st.plotly_chart(t.style_fig(fig, 420), use_container_width=True)

t.section("Error analysis by category", "recall per attack type · FPR on benign")
gm = data.group_metrics()
cat = gm[(gm.grouping == "category")]
models = st.multiselect("Models", order[1:], default=["random_forest", "isolation_forest", "hybrid"])
fig = go.Figure()
for m in models:
    g = cat[(cat.model == m) & (cat.grp != "benign")]
    fig.add_trace(go.Bar(x=g.grp, y=g.recall, name=m, marker_color=t.MODEL_COLORS.get(m),
                         text=g.recall.round(2), textposition="outside"))
fig.update_layout(barmode="group", yaxis_range=[0, 1.12], yaxis_title="recall")
st.plotly_chart(t.style_fig(fig, 360), use_container_width=True)

c1, c2 = st.columns(2)
with c1:
    t.section("Confusion matrix", "hybrid · test window")
    h = mt[mt.model == "hybrid"].iloc[0]
    z = [[h.tn, h.fp], [h.fn, h.tp]]
    fig = go.Figure(go.Heatmap(z=z, x=["pred benign", "pred attack"], y=["benign", "attack"], text=z, texttemplate="%{text}",
                               colorscale=[[0, "#0f172a"], [1, t.PRIMARY]], showscale=False))
    fig.update_yaxes(autorange="reversed")
    st.plotly_chart(t.style_fig(fig, 300), use_container_width=True)
with c2:
    t.section("False-positive rate by protocol")
    pr = gm[(gm.grouping == "protocol") & gm.model.isin(models)]
    fig = go.Figure()
    for m in models:
        g = pr[pr.model == m]
        fig.add_trace(go.Bar(x=g.grp, y=g.fpr, name=m, marker_color=t.MODEL_COLORS.get(m)))
    fig.update_layout(barmode="group", yaxis_tickformat=".1%")
    st.plotly_chart(t.style_fig(fig, 300), use_container_width=True)
