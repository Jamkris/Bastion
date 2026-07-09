from bastion.services.attackers import parse_attackers


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
    assert "192.168.45.10" not in ips  # Accepted → 공격 아님
