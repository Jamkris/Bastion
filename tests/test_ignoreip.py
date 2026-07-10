from types import SimpleNamespace

import pytest

from bastion.services import ignoreip


def test_parse_tree_format():
    raw = (
        "These IP addresses/networks are ignored:\n"
        "|- 127.0.0.1/8\n"
        "|- ::1\n"
        "|- 192.168.45.0/24\n"
        "`- 203.0.113.7\n"
    )
    assert ignoreip.parse_ignoreip(raw) == [
        "127.0.0.1/8", "::1", "192.168.45.0/24", "203.0.113.7",
    ]


def test_parse_single_line_multiple():
    raw = "`- 127.0.0.1/8 192.168.45.0/24 203.0.113.7"
    assert ignoreip.parse_ignoreip(raw) == [
        "127.0.0.1/8", "192.168.45.0/24", "203.0.113.7",
    ]


def test_parse_dedupes():
    raw = "|- 10.0.0.1\n`- 10.0.0.1\n"
    assert ignoreip.parse_ignoreip(raw) == ["10.0.0.1"]


def test_parse_ignores_prose():
    assert ignoreip.parse_ignoreip("No IP addresses here at all") == []


def test_add_builds_expected_command(monkeypatch):
    calls = []
    monkeypatch.setattr(ignoreip, "run", lambda cmd: calls.append(cmd) or "")
    ignoreip.add("sshd", "1.2.3.4")
    assert calls == [["fail2ban-client", "set", "sshd", "addignoreip", "1.2.3.4"]]


def test_remove_builds_expected_command(monkeypatch):
    calls = []
    monkeypatch.setattr(ignoreip, "run", lambda cmd: calls.append(cmd) or "")
    ignoreip.remove("sshd", "10.0.0.0/24")
    assert calls == [["fail2ban-client", "set", "sshd", "delignoreip", "10.0.0.0/24"]]


def test_add_rejects_bad_jail(monkeypatch):
    monkeypatch.setattr(ignoreip, "run", lambda cmd: "")
    with pytest.raises(ValueError):
        ignoreip.add("bad jail!", "1.2.3.4")


def test_add_rejects_bad_ip(monkeypatch):
    monkeypatch.setattr(ignoreip, "run", lambda cmd: "")
    with pytest.raises(ValueError):
        ignoreip.add("sshd", "not-an-ip")


def test_list_all_groups_by_jail(monkeypatch):
    monkeypatch.setattr(
        ignoreip.dashboard, "jail_summaries",
        lambda: ([SimpleNamespace(name="sshd"), SimpleNamespace(name="nginx")], None),
    )
    monkeypatch.setattr(ignoreip, "run", lambda cmd: "|- 127.0.0.1/8\n`- 1.2.3.4\n")
    data, error = ignoreip.list_all()
    assert error is None
    assert data[0]["jail"] == "sshd"
    assert "1.2.3.4" in data[0]["entries"]


def test_list_all_reports_jail_listing_error(monkeypatch):
    monkeypatch.setattr(ignoreip.dashboard, "jail_summaries", lambda: ([], "socket down"))
    data, error = ignoreip.list_all()
    assert data == []
    assert error == "socket down"
