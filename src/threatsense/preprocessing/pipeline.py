"""Preprocessing fitted on the training window only."""
from __future__ import annotations

import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, RobustScaler


def _log1p(x):
    return np.log1p(np.clip(x, 0, None))


def build_preprocessor(numeric: list[str], categorical: list[str], log_cols: list[str]) -> ColumnTransformer:
    logs = [c for c in numeric if c in log_cols]
    lin = [c for c in numeric if c not in log_cols]
    return ColumnTransformer(
        [
            ("log", Pipeline([("imp", SimpleImputer(strategy="median")),
                              ("log", FunctionTransformer(_log1p, feature_names_out="one-to-one")),
                              ("sc", RobustScaler())]), logs),
            ("num", Pipeline([("imp", SimpleImputer(strategy="median")), ("sc", RobustScaler())]), lin),
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), categorical),
        ],
        verbose_feature_names_out=False,
    )
