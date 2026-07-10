from bastion.fwview import group_rules_by_table
from bastion.models import FirewallRule


def _rule(family, table, chain, handle):
    return FirewallRule(family=family, table=table, chain=chain, handle=handle, expr="[]")


def test_empty():
    assert group_rules_by_table([]) == []


def test_groups_by_table_then_chain():
    rules = [
        _rule("ip", "filter", "INPUT", 1),
        _rule("ip", "filter", "INPUT", 2),
        _rule("ip", "filter", "FORWARD", 3),
        _rule("ip", "nat", "POSTROUTING", 4),
    ]
    groups = group_rules_by_table(rules)
    # Sorted by (family, table): filter before nat.
    assert [(g["family"], g["table"]) for g in groups] == [("ip", "filter"), ("ip", "nat")]
    filter_group = groups[0]
    assert filter_group["count"] == 3
    assert [c["chain"] for c in filter_group["chains"]] == ["INPUT", "FORWARD"]
    assert len(filter_group["chains"][0]["rules"]) == 2


def test_chain_order_is_first_seen():
    rules = [
        _rule("inet", "z", "b", 1),
        _rule("inet", "z", "a", 2),
        _rule("inet", "z", "b", 3),
    ]
    groups = group_rules_by_table(rules)
    assert [c["chain"] for c in groups[0]["chains"]] == ["b", "a"]


def test_count_matches_total_rules():
    rules = [_rule("ip", "filter", "INPUT", i) for i in range(5)]
    assert group_rules_by_table(rules)[0]["count"] == 5
