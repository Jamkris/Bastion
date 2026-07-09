"""Parser for `nft -j list ruleset` (JSON) output (pure function).

nftables JSON schema: {"nftables": [ {"metainfo":{...}}, {"table":{...}},
{"chain":{...}}, {"rule":{...}}, {"set":{...}}, ... ]}
Each element is a single-key dict.
"""

import json

from bastion.models import FirewallChain, FirewallRule, FirewallRuleset, FirewallSet


def _set_elements(elem) -> tuple[str, ...]:
    # Elements may be strings or dicts (ranges/prefixes).
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
