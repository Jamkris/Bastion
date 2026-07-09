import pytest

from bastion.services import actions


def _capture(monkeypatch):
    seen = []
    monkeypatch.setattr(actions, "run", lambda cmd: seen.append(cmd) or "")
    return seen


def test_ban_builds_argv(monkeypatch):
    seen = _capture(monkeypatch)
    actions.ban("sshd", "1.2.3.4")
    assert seen == [["fail2ban-client", "set", "sshd", "banip", "1.2.3.4"]]


def test_unban_builds_argv_ipv6(monkeypatch):
    seen = _capture(monkeypatch)
    actions.unban("sshd", "2001:db8::1")
    assert seen == [["fail2ban-client", "set", "sshd", "unbanip", "2001:db8::1"]]


def test_invalid_ip_rejected(monkeypatch):
    def boom(cmd):
        raise AssertionError("run must not be called for invalid input")

    monkeypatch.setattr(actions, "run", boom)
    with pytest.raises(ValueError):
        actions.ban("sshd", "1.2.3.4; rm -rf /")
    with pytest.raises(ValueError):
        actions.ban("sshd", "not-an-ip")


def test_invalid_jail_rejected(monkeypatch):
    def boom(cmd):
        raise AssertionError("run must not be called for invalid input")

    monkeypatch.setattr(actions, "run", boom)
    with pytest.raises(ValueError):
        actions.unban("sshd; evil", "1.2.3.4")
