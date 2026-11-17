from threatsense.storage.database import Database
from threatsense.streaming.replay import ReplaySource, run_stream


def test_replay_processes_windows_in_order(flows):
    seen = []
    n = run_stream(ReplaySource(flows.head(3000), 5), lambda start, w: seen.append((start, len(w))))
    starts = [s for s, _ in seen]
    assert n == len(seen) > 0
    assert starts == sorted(starts)
    assert sum(c for _, c in seen) == 3000


def test_database_meta_round_trip(tmp_path):
    db = Database(tmp_path / "t.db")
    db.put_meta("k", {"a": 1})
    assert db.get_meta("k") == {"a": 1}
    assert db.get_meta("missing", 5) == 5
