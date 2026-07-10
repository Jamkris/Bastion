from types import SimpleNamespace

import pytest

from bastion import history


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "settings", SimpleNamespace(data_dir=str(tmp_path)))
    return tmp_path


def test_record_and_load_roundtrip(store):
    history.record(3, 10, 5, ts=1000)
    history.record(4, 12, 5, ts=1060)
    pts = history.load()
    assert [p["banned"] for p in pts] == [3, 4]
    assert pts[1]["attackers"] == 12
    assert pts[0]["t"] == 1000


def test_load_limit_returns_last_n(store):
    for i in range(10):
        history.record(i, i, i, ts=1000 + i)
    pts = history.load(limit=3)
    assert [p["banned"] for p in pts] == [7, 8, 9]


def test_load_missing_returns_empty(store):
    assert history.load() == []


def test_trim_caps_file(store, monkeypatch):
    monkeypatch.setattr(history, "MAX_POINTS", 5)
    monkeypatch.setattr(history, "_TRIM_SLACK", 2)
    for i in range(20):
        history.record(i, i, i, ts=1000 + i)
    pts = history.load()
    assert len(pts) <= history.MAX_POINTS + history._TRIM_SLACK
    # Newest points are retained.
    assert pts[-1]["banned"] == 19


def test_load_skips_torn_line(store):
    history.record(1, 1, 1, ts=1000)
    with open(store / "history.jsonl", "a", encoding="utf-8") as f:
        f.write("{ not valid json\n")
    history.record(2, 2, 2, ts=1060)
    assert [p["banned"] for p in history.load()] == [1, 2]
