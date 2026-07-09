from types import SimpleNamespace

import pytest

from bastion.web import app as webapp


def _ban(jail, ip):
    return SimpleNamespace(jail=jail, ip=ip)


@pytest.fixture
def reset_poller(monkeypatch):
    # Fresh module state for each test.
    monkeypatch.setattr(webapp, "_seen_bans", set())
    monkeypatch.setattr(webapp, "_ban_events", [])
    monkeypatch.setattr(webapp, "_last_alert_at", 0.0)
    monkeypatch.setattr(webapp, "_primed", False)
    sent = []
    monkeypatch.setattr(webapp.notify, "send", lambda *a, **k: sent.append((a, k)) or True)
    return sent


def _prefs(monkeypatch, **over):
    n = {
        "enabled": True,
        "ntfy_url": "https://ntfy.sh",
        "ntfy_topic": "t",
        "ntfy_token": "",
        "priority": "default",
        "ban_spike_threshold": 2,
        "ban_spike_window_min": 10,
    }
    n.update(over)
    monkeypatch.setattr(webapp.prefs, "get", lambda section: n)


def _banned(monkeypatch, bans):
    monkeypatch.setattr(webapp.dashboard, "banned_ips", lambda: (bans, None))


def test_disabled_never_alerts(reset_poller, monkeypatch):
    _prefs(monkeypatch, enabled=False)
    _banned(monkeypatch, [_ban("sshd", "1.1.1.1")] * 5)
    webapp._poll_bans_once(now=1000.0)
    assert reset_poller == []


def test_first_pass_primes_without_alerting(reset_poller, monkeypatch):
    _prefs(monkeypatch)
    _banned(monkeypatch, [_ban("sshd", "1.1.1.1"), _ban("sshd", "2.2.2.2")])
    webapp._poll_bans_once(now=1000.0)
    assert reset_poller == []  # baseline recorded, no alert


def test_spike_triggers_single_alert(reset_poller, monkeypatch):
    _prefs(monkeypatch, ban_spike_threshold=2)
    # Prime with no bans.
    _banned(monkeypatch, [])
    webapp._poll_bans_once(now=1000.0)
    # Two new bans appear within the window -> alert.
    _banned(monkeypatch, [_ban("sshd", "9.9.9.9"), _ban("sshd", "8.8.8.8")])
    webapp._poll_bans_once(now=1001.0)
    assert len(reset_poller) == 1


def test_below_threshold_does_not_alert(reset_poller, monkeypatch):
    _prefs(monkeypatch, ban_spike_threshold=3)
    _banned(monkeypatch, [])
    webapp._poll_bans_once(now=1000.0)
    _banned(monkeypatch, [_ban("sshd", "9.9.9.9")])  # only 1 new
    webapp._poll_bans_once(now=1001.0)
    assert reset_poller == []
