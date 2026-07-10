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
    monkeypatch.setattr(webapp, "_seen_attackers", set())
    monkeypatch.setattr(webapp, "_attackers_primed", False)
    monkeypatch.setattr(webapp, "_seen_ports", set())
    monkeypatch.setattr(webapp, "_ports_primed", False)
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
        "notify_new_attacker": False,
        "notify_port_change": False,
    }
    n.update(over)
    monkeypatch.setattr(webapp.prefs, "get", lambda section: n)


def _banned(monkeypatch, bans):
    monkeypatch.setattr(webapp.dashboard, "banned_ips", lambda: (bans, None))


def _attackers(monkeypatch, ips):
    monkeypatch.setattr(
        webapp.dashboard, "top_attackers",
        lambda: ([SimpleNamespace(ip=ip) for ip in ips], None),
    )


def _ports(monkeypatch, entries):
    monkeypatch.setattr(
        webapp.dashboard, "open_ports",
        lambda: ([SimpleNamespace(port=p, proto=pr) for p, pr in entries], None),
    )


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


# ---------- new-attacker alerts ----------
def test_new_attacker_alert_disabled_by_default(reset_poller, monkeypatch):
    _prefs(monkeypatch)  # notify_new_attacker False
    _attackers(monkeypatch, ["1.1.1.1"])
    webapp._poll_new_attackers_once()
    _attackers(monkeypatch, ["2.2.2.2"])
    webapp._poll_new_attackers_once()
    assert reset_poller == []


def test_new_attacker_alerts_after_prime(reset_poller, monkeypatch):
    _prefs(monkeypatch, notify_new_attacker=True)
    _attackers(monkeypatch, ["1.1.1.1"])
    webapp._poll_new_attackers_once()  # prime
    assert reset_poller == []
    _attackers(monkeypatch, ["1.1.1.1", "2.2.2.2"])  # 2.2.2.2 is new
    webapp._poll_new_attackers_once()
    assert len(reset_poller) == 1


def test_new_attacker_no_alert_when_unchanged(reset_poller, monkeypatch):
    _prefs(monkeypatch, notify_new_attacker=True)
    _attackers(monkeypatch, ["1.1.1.1"])
    webapp._poll_new_attackers_once()  # prime
    webapp._poll_new_attackers_once()  # same set
    assert reset_poller == []


# ---------- port-change alerts ----------
def test_port_change_alerts_on_open_and_close(reset_poller, monkeypatch):
    _prefs(monkeypatch, notify_port_change=True)
    _ports(monkeypatch, [(22, "tcp"), (80, "tcp")])
    webapp._poll_port_changes_once()  # prime
    assert reset_poller == []
    _ports(monkeypatch, [(22, "tcp"), (443, "tcp")])  # 80 closed, 443 opened
    webapp._poll_port_changes_once()
    assert len(reset_poller) == 1


def test_port_change_no_alert_when_stable(reset_poller, monkeypatch):
    _prefs(monkeypatch, notify_port_change=True)
    _ports(monkeypatch, [(22, "tcp")])
    webapp._poll_port_changes_once()  # prime
    webapp._poll_port_changes_once()  # unchanged
    assert reset_poller == []


def test_poll_once_runs_all_detectors(reset_poller, monkeypatch):
    _prefs(monkeypatch, notify_new_attacker=True, notify_port_change=True)
    _banned(monkeypatch, [])
    _attackers(monkeypatch, [])
    _ports(monkeypatch, [])
    monkeypatch.setattr(webapp.history, "record", lambda *a, **k: None)
    webapp._poll_once(now=1000.0)  # primes all three, no alerts
    assert reset_poller == []


def test_poll_records_history(reset_poller, monkeypatch):
    _prefs(monkeypatch)  # notifications off is irrelevant; history always records
    monkeypatch.setattr(
        webapp.dashboard, "summary",
        lambda: {"total_banned": 7, "attackers": 3, "open_ports": 9, "jail_count": 2},
    )
    recorded = []
    monkeypatch.setattr(
        webapp.history, "record",
        lambda banned, attackers, ports, *, ts: recorded.append((banned, attackers, ports, ts)),
    )
    webapp._record_history_once(now=1234.0)
    assert recorded == [(7, 3, 9, 1234.0)]
