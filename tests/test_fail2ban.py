from bastion.services.fail2ban import parse_jail_list, parse_jail_status


def test_parse_jail_list(fixture):
    jails = parse_jail_list(fixture("fail2ban_status.txt"))
    assert jails == ("sshd",)


def test_parse_jail_status_counts(fixture):
    status = parse_jail_status(fixture("fail2ban_status_sshd.txt"))
    assert status.name == "sshd"
    assert status.currently_failed == 9
    assert status.total_failed == 41416
    assert status.currently_banned == 941
    assert status.total_banned == 941
    assert status.file_list == ("/var/log/auth.log",)


def test_parse_jail_status_banned_ips(fixture):
    status = parse_jail_status(fixture("fail2ban_status_sshd.txt"))
    assert status.banned_ips[0] == "1.222.42.237"
    assert "102.88.137.80" in status.banned_ips
    # Fixture is trimmed to 30 IPs (real server had 941).
    assert len(status.banned_ips) == 30


def test_parse_jail_status_rejects_garbage():
    import pytest

    with pytest.raises(ValueError):
        parse_jail_status("completely unrelated text")
