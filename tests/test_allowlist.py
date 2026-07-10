import json

import pytest

from bastion.services import allowlist


@pytest.fixture(autouse=True)
def target(monkeypatch):
    monkeypatch.setattr(
        allowlist.prefs, "get",
        lambda section: {"family": "inet", "table": "filter", "set": "bastion_allow"},
    )


def test_normalize_plain_ip():
    assert allowlist.normalize_ip(" 1.2.3.4 ") == "1.2.3.4"


def test_normalize_ipv6():
    assert allowlist.normalize_ip("2001:db8::1") == "2001:db8::1"


def test_normalize_cidr_snaps_to_network():
    assert allowlist.normalize_ip("10.0.0.5/24") == "10.0.0.0/24"


def test_normalize_rejects_garbage():
    with pytest.raises(ValueError):
        allowlist.normalize_ip("not-an-ip")


def test_parse_elements_strings():
    raw = json.dumps({"nftables": [{"set": {"name": "bastion_allow", "elem": ["1.1.1.1", "2.2.2.2"]}}]})
    assert allowlist.parse_elements(raw) == ["1.1.1.1", "2.2.2.2"]


def test_parse_elements_empty_set():
    raw = json.dumps({"nftables": [{"set": {"name": "bastion_allow"}}]})
    assert allowlist.parse_elements(raw) == []


def test_add_builds_expected_command(monkeypatch):
    calls = []
    monkeypatch.setattr(allowlist, "run", lambda cmd: calls.append(cmd) or "")
    allowlist.add("1.2.3.4")
    assert calls == [["nft", "add", "element", "inet", "filter", "bastion_allow", "{ 1.2.3.4 }"]]


def test_remove_builds_expected_command(monkeypatch):
    calls = []
    monkeypatch.setattr(allowlist, "run", lambda cmd: calls.append(cmd) or "")
    allowlist.remove("1.2.3.4")
    assert calls[0][:3] == ["nft", "delete", "element"]


def test_add_rejects_bad_ip(monkeypatch):
    monkeypatch.setattr(allowlist, "run", lambda cmd: "")
    with pytest.raises(ValueError):
        allowlist.add("; rm -rf /")


def test_set_missing_detects_not_found():
    assert allowlist.set_missing("Error: No such file or directory") is True
    assert allowlist.set_missing("set does not exist") is True
    assert allowlist.set_missing(None) is False
    assert allowlist.set_missing("Operation not permitted") is False


def test_create_set_builds_expected_command(monkeypatch):
    calls = []
    monkeypatch.setattr(allowlist, "run", lambda cmd: calls.append(cmd) or "")
    allowlist.create_set()
    assert calls == [[
        "nft", "add", "set", "inet", "filter", "bastion_allow",
        "{ type ipv4_addr; flags interval; }",
    ]]


def test_create_set_rejects_bad_type(monkeypatch):
    monkeypatch.setattr(allowlist, "run", lambda cmd: "")
    with pytest.raises(ValueError):
        allowlist.create_set("evil_type")


def test_list_entries_returns_error_on_missing_set(monkeypatch):
    from bastion.runner import CommandError

    def boom(cmd):
        raise CommandError(cmd, 1, "No such file or directory")

    monkeypatch.setattr(allowlist, "run", boom)
    entries, error = allowlist.list_entries()
    assert entries == []
    assert error
