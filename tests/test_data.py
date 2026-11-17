import pandas as pd

from threatsense.features.engineering import add_context_features, time_split
from threatsense.ingestion.loaders import validate_flows
from threatsense.ingestion.synthetic import generate_flows


def test_generator_is_deterministic(small_cfg):
    a = generate_flows(small_cfg, seed=1)
    b = generate_flows(small_cfg, seed=1)
    pd.testing.assert_frame_equal(a, b)


def test_audit(flows):
    rep = validate_flows(flows)
    assert rep["missing_columns"] == []
    assert rep["time_ordered"]
    assert 0.05 < rep["attack_rate"] < 0.5
    assert rep["negative_values"] == 0


def test_time_split_has_no_overlap(flows):
    tr, va, te = time_split(flows, 0.6, 0.2)
    assert tr.timestamp.max() < va.timestamp.min() <= va.timestamp.max() < te.timestamp.min()
    assert len(tr) + len(va) + len(te) == len(flows)


def test_novel_attack_only_in_test(flows):
    tr, va, te = time_split(flows, 0.6, 0.2)
    assert "exfiltration" not in set(tr.category) | set(va.category)
    assert "exfiltration" in set(te.category)


def test_context_features_use_only_past():
    ts = pd.Timestamp("2026-01-01")
    df = pd.DataFrame({"timestamp": [ts, ts + pd.Timedelta(seconds=10), ts + pd.Timedelta(seconds=100)],
                       "src_ip": ["a", "a", "a"], "dst_port": [80, 443, 22]})
    out = add_context_features(df, 60)
    assert out.src_flow_count_60s.tolist() == [0, 1, 0]
    assert out.src_port_diversity_60s.tolist() == [0, 1, 0]


def test_portscan_has_high_port_diversity(flows):
    ps = flows[flows.category == "portscan"].src_port_diversity_60s.median()
    bn = flows[flows.category == "benign"].src_port_diversity_60s.median()
    assert ps >= 5 and ps > 3 * max(bn, 1)
