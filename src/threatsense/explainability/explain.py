"""Alert explanations.

1. **Model contributions** — vectorised reference substitution: how much does the
   calibrated risk drop when one feature is replaced by its benign median?
2. **Deviation profile** — robust z-scores versus benign training traffic.

Both describe what the *model* reacted to. They are not causal attributions and
do not prove intent.
"""
from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd


def substitution_contributions(predict_fn, rows: pd.DataFrame, reference: pd.Series,
                               features: list[str]) -> pd.DataFrame:
    """Return an (n_rows × n_features) frame of risk drops when each feature is set to ``reference``."""
    base = predict_fn(rows)
    n, k = len(rows), len(features)
    rep = pd.concat([rows] * k, ignore_index=True)
    for j, f in enumerate(features):
        rep.loc[j * n:(j + 1) * n - 1, f] = reference[f]
    alt = predict_fn(rep).reshape(k, n).T
    return pd.DataFrame(base[:, None] - alt, columns=features, index=rows.index)


def top_factors(contrib_row: pd.Series, k: int = 3) -> list[dict[str, Any]]:
    s = contrib_row.sort_values(key=np.abs, ascending=False).head(k)
    return [{"feature": f, "contribution": round(float(v), 4)} for f, v in s.items()]


def benign_reference(train: pd.DataFrame, features: list[str], categorical: list[str], target: str) -> pd.Series:
    b = train[train[target] == 0]
    ref = {}
    for f in features:
        ref[f] = b[f].mode().iloc[0] if f in categorical else b[f].median()
    return pd.Series(ref)


def describe(factors: list[dict[str, Any]]) -> str:
    if not factors:
        return "No dominant factor."
    parts = [f"{d['feature'].replace('_', ' ')} ({'+' if d['contribution'] >= 0 else '−'}{abs(d['contribution']):.2f})"
             for d in factors]
    return "Risk driven mainly by " + ", ".join(parts)
