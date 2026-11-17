import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def settings():
    from threatsense.common.config import get_settings

    return get_settings()


@pytest.fixture(scope="session")
def small_cfg(settings):
    cfg = dict(settings.dataset["synthetic"])
    cfg["n_benign"] = 6000
    cfg["campaigns"] = {k: [[h, m, max(40, n // 6)] for h, m, n in v] for k, v in cfg["campaigns"].items()}
    return cfg


@pytest.fixture(scope="session")
def flows(small_cfg):
    from threatsense.features.engineering import build_features
    from threatsense.ingestion.synthetic import generate_flows

    return build_features(generate_flows(small_cfg, seed=7))
