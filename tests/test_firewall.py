from bastion.services.firewall import parse_ruleset


def test_parse_chain(fixture):
    rs = parse_ruleset(fixture("nft_ruleset.json"))
    assert len(rs.chains) == 1
    c = rs.chains[0]
    assert c.family == "inet"
    assert c.name == "f2b-chain"
    assert c.hook == "input"


def test_parse_set_elements(fixture):
    rs = parse_ruleset(fixture("nft_ruleset.json"))
    assert len(rs.sets) == 1
    s = rs.sets[0]
    assert s.name == "addr-set-sshd"
    assert "1.222.42.237" in s.elements
    assert len(s.elements) == 3


def test_parse_rule(fixture):
    rs = parse_ruleset(fixture("nft_ruleset.json"))
    assert len(rs.rules) == 1
    assert rs.rules[0].handle == 3
    assert "dport" in rs.rules[0].expr
