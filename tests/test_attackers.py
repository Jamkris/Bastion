from bastion.services.attackers import attempt_counts, parse_attackers


def test_counts_and_ranking(fixture):
    stats = parse_attackers(fixture("auth.log"))
    top = stats[0]
    assert top.ip == "1.222.42.237"
    assert top.count == 3  # 3 failed passwords


def test_invalid_user_and_pam_counted(fixture):
    stats = parse_attackers(fixture("auth.log"))
    ips = {s.ip for s in stats}
    assert "101.126.54.36" in ips  # invalid user + failed password
    assert "102.208.34.7" in ips  # pam authentication failure


def test_accepted_login_not_counted(fixture):
    stats = parse_attackers(fixture("auth.log"))
    ips = {s.ip for s in stats}
    assert "192.168.45.10" not in ips  # accepted -> not an attack


def test_attempt_counts_returns_full_mapping(fixture):
    counts = attempt_counts(fixture("auth.log"))
    assert counts["1.222.42.237"] == 3
    assert "192.168.45.10" not in counts  # accepted login is not an attempt


def test_exclude_drops_ips_before_ranking(fixture):
    # Already-banned IPs are excluded so they never appear in Top Attackers.
    stats = parse_attackers(fixture("auth.log"), exclude={"1.222.42.237"})
    ips = {s.ip for s in stats}
    assert "1.222.42.237" not in ips
    assert "101.126.54.36" in ips  # other attackers still ranked
