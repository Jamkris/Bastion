"""`nft -j list ruleset` (JSON) 파서 (순수 함수).

nftables JSON 스키마: {"nftables": [ {"metainfo":{...}}, {"table":{...}},
{"chain":{...}}, {"rule":{...}}, {"set":{...}}, ... ]}
각 원소는 키가 하나인 dict.
"""

import json

from bastion.models import FirewallChain, FirewallRule, FirewallRuleset, FirewallSet


def _set_elements(elem) -> tuple[str, ...]:
    # elem 항목은 문자열이거나 dict(범위/prefix 등)일 수 있다.
    if not elem:
        return ()
    return tuple(e if isinstance(e, str) else json.dumps(e, ensure_ascii=False) for e in elem)


def parse_ruleset(raw: str) -> FirewallRuleset:
    data = json.loads(raw)
    items = data.get("nftables", [])

    chains: list[FirewallChain] = []
    rules: list[FirewallRule] = []
    sets: list[FirewallSet] = []

    for item in items:
        if "chain" in item:
            c = item["chain"]
            chains.append(
                FirewallChain(
                    family=c.get("family", ""),
                    table=c.get("table", ""),
                    name=c.get("name", ""),
                    type=c.get("type"),
                    hook=c.get("hook"),
                    policy=c.get("policy"),
                )
            )
        elif "rule" in item:
            r = item["rule"]
            rules.append(
                FirewallRule(
                    family=r.get("family", ""),
                    table=r.get("table", ""),
                    chain=r.get("chain", ""),
                    handle=int(r.get("handle", 0)),
                    expr=json.dumps(r.get("expr", []), ensure_ascii=False),
                )
            )
        elif "set" in item:
            s = item["set"]
            sets.append(
                FirewallSet(
                    family=s.get("family", ""),
                    table=s.get("table", ""),
                    name=s.get("name", ""),
                    type=s.get("type", ""),
                    elements=_set_elements(s.get("elem")),
                )
            )

    return FirewallRuleset(tuple(chains), tuple(rules), tuple(sets))
