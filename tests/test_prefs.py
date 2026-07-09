from types import SimpleNamespace

import pytest

from bastion import prefs


@pytest.fixture
def store(tmp_path, monkeypatch):
    # Point the prefs store at an isolated temp dir instead of ./data.
    monkeypatch.setattr(prefs, "settings", SimpleNamespace(data_dir=str(tmp_path)))
    return tmp_path


def test_load_returns_defaults_when_missing(store):
    p = prefs.load()
    assert p["notifications"]["enabled"] is False
    assert p["notifications"]["ntfy_url"] == "https://ntfy.sh"
    assert p["allowlist"]["set"] == "bastion_allow"


def test_merge_defaults_drops_unknown_and_fills_new():
    merged = prefs.merge_defaults({"notifications": {"ntfy_topic": "alerts", "bogus": 1}})
    assert merged["notifications"]["ntfy_topic"] == "alerts"
    assert "bogus" not in merged["notifications"]
    assert merged["security"]["rate_limit_max_attempts"] == 5  # untouched default


def test_coerce_checkbox_absent_is_false():
    # Unchecked HTML checkboxes are omitted from the form entirely.
    out = prefs.coerce_section("notifications", {"ntfy_topic": "x"})
    assert out["enabled"] is False


def test_coerce_checkbox_on_is_true():
    out = prefs.coerce_section("notifications", {"enabled": "on"})
    assert out["enabled"] is True


def test_coerce_int_bad_value_falls_back():
    out = prefs.coerce_section("notifications", {"ban_spike_threshold": "not-a-number"})
    assert out["ban_spike_threshold"] == 5


def test_update_persists_and_roundtrips(store):
    prefs.update("notifications", {"enabled": "on", "ntfy_topic": "bastion", "ntfy_token": "tk_abc"})
    reloaded = prefs.load()["notifications"]
    assert reloaded["enabled"] is True
    assert reloaded["ntfy_topic"] == "bastion"
    assert reloaded["ntfy_token"] == "tk_abc"


def test_update_blank_secret_keeps_previous(store):
    prefs.update("notifications", {"ntfy_token": "tk_secret"})
    # A later save that leaves the token blank must not wipe it.
    prefs.update("notifications", {"ntfy_topic": "changed", "ntfy_token": ""})
    reloaded = prefs.load()["notifications"]
    assert reloaded["ntfy_token"] == "tk_secret"
    assert reloaded["ntfy_topic"] == "changed"


def test_update_unknown_section_raises(store):
    with pytest.raises(ValueError):
        prefs.update("nope", {})


def test_load_corrupt_file_returns_defaults(store):
    (store / "prefs.json").write_text("{ this is not json", encoding="utf-8")
    assert prefs.load()["notifications"]["enabled"] is False
