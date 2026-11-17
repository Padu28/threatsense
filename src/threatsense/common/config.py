"""Configuration loading and project paths."""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(os.getenv("THREATSENSE_ROOT", Path(__file__).resolve().parents[3]))
CONFIG_DIR = PROJECT_ROOT / "configs"


def _load(name: str) -> dict[str, Any]:
    with open(CONFIG_DIR / name, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


@dataclass(frozen=True)
class Settings:
    dataset: dict[str, Any]
    features: dict[str, Any]
    thresholds: dict[str, Any]

    @property
    def numeric(self) -> list[str]:
        return list(self.features["numeric"])

    @property
    def categorical(self) -> list[str]:
        return list(self.features["categorical"])

    @property
    def all_features(self) -> list[str]:
        return self.numeric + self.categorical

    @property
    def target(self) -> str:
        return self.dataset["target"]

    @property
    def db_path(self) -> Path:
        o = os.getenv("THREATSENSE_DB")
        return Path(o) if o else PROJECT_ROOT / self.thresholds["storage"]["database"]

    @property
    def reports_dir(self) -> Path:
        return PROJECT_ROOT / self.thresholds["storage"]["reports_dir"]

    @property
    def models_dir(self) -> Path:
        return PROJECT_ROOT / self.thresholds["storage"]["models_dir"]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(_load("dataset.yaml"), _load("features.yaml"), _load("thresholds.yaml"))
