import json

from bastion.services.nftexpr import render_expr


def test_simple_dport_accept():
    expr = [
        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
        {"accept": None},
    ]
    assert render_expr(expr) == "tcp dport 22 accept"


def test_saddr_named_set_accept():
    expr = [
        {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@bastion_allow"}},
        {"accept": None},
    ]
    assert render_expr(expr) == "ip saddr @bastion_allow accept"


def test_not_equal_operator():
    expr = [
        {"match": {"op": "!=", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "@nozapret"}},
    ]
    assert render_expr(expr) == "ip daddr != @nozapret"


def test_anonymous_set_dport():
    expr = [
        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                   "right": {"set": [80, 443]}}},
        {"accept": None},
    ]
    assert render_expr(expr) == "tcp dport { 80, 443 } accept"


def test_meta_iifname_bare():
    expr = [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "enp4s0"}}]
    assert render_expr(expr) == "iifname enp4s0"


def test_ct_state():
    expr = [
        {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": {"set": ["established", "related"]}}},
        {"accept": None},
    ]
    assert render_expr(expr) == "ct state in { established, related } accept"


def test_jump_and_counter():
    expr = [{"counter": {"packets": 5, "bytes": 300}}, {"jump": {"target": "ufw-user-input"}}]
    assert render_expr(expr) == "counter jump ufw-user-input"


def test_prefix_and_range():
    expr = [
        {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                   "right": {"prefix": {"addr": "10.0.0.0", "len": 8}}}},
    ]
    assert render_expr(expr) == "ip saddr 10.0.0.0/8"


def test_log_with_prefix():
    expr = [{"log": {"prefix": "[UFW BLOCK] "}}]
    assert render_expr(expr) == 'log prefix "[UFW BLOCK] "'


def test_accepts_json_string_input():
    expr_str = json.dumps([{"drop": None}])
    assert render_expr(expr_str) == "drop"


def test_invalid_json_returns_input():
    assert render_expr("{not json") == "{not json"


def test_unknown_statement_falls_back_gracefully():
    expr = [{"weird_stmt": {"a": 1}}]
    out = render_expr(expr)
    assert "weird_stmt" in out  # does not raise, keeps information


# ---------- real UFW / iptables-nft rules from server1 ----------
def test_ufw_iifname_lo_accept():
    expr = [
        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}},
        {"counter": {"packets": 92, "bytes": 7604}},
        {"accept": None},
    ]
    assert render_expr(expr) == "iifname lo counter accept"


def test_ufw_xt_conntrack_names_the_match():
    expr = [
        {"xt": {"type": "match", "name": "conntrack"}},
        {"counter": {"packets": 7860, "bytes": 994422}},
        {"drop": None},
    ]
    assert render_expr(expr) == "conntrack counter drop"


def test_ufw_l4proto_icmp_xt_accept():
    expr = [
        {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "icmp"}},
        {"xt": {"type": "match", "name": "icmp"}},
        {"counter": {"packets": 362, "bytes": 33264}},
        {"accept": None},
    ]
    assert render_expr(expr) == "l4proto icmp icmp counter accept"


def test_docker_jump_chain():
    expr = [{"counter": {"packets": 0, "bytes": 0}}, {"jump": {"target": "DOCKER-USER"}}]
    assert render_expr(expr) == "counter jump DOCKER-USER"
