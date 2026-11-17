"""API tests — skipped when FastAPI/httpx are absent or the pipeline has not been run."""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    import api.main as main

    if not (main.settings.models_dir / "scorer.joblib").exists():
        pytest.skip("Run `python -m threatsense.cli pipeline` first")
    return TestClient(main.app)


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_score_benign_like_flow(client):
    r = client.post("/score", json={})
    assert r.status_code == 200
    body = r.json()
    assert 0 <= body["risk"] <= 1 and body["top_factors"]


def test_score_scan_like_flow(client):
    scan = {"dst_port": 31337, "duration_ms": 8, "fwd_packets": 1, "bwd_packets": 1, "fwd_bytes": 60, "bwd_bytes": 54,
            "rst_flag_count": 2, "ack_flag_count": 1, "src_flow_count_60s": 180, "src_port_diversity_60s": 175}
    benign = client.post("/score", json={}).json()["risk"]
    assert client.post("/score", json=scan).json()["risk"] > benign


def test_validation_error(client):
    assert client.post("/score", json={"dst_port": 70000}).status_code == 422
