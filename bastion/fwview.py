"""Presentation helper: group firewall rules by table -> chain.

A real ruleset can hold well over a thousand rules; a single flat table is hard
to navigate. This groups them the way nftables is organised — by (family, table)
and then by chain — so the Firewall page can render collapsible sections.

Pure: it takes model objects and returns plain dicts, so it is easy to test and
carries no rendering concerns.
"""

from __future__ import annotations

from typing import Iterable


def group_rules_by_table(rules: Iterable) -> list[dict]:
    """Return [{family, table, count, chains: [{chain, rules: [...]}]}], sorted
    by (family, table); chains keep first-seen order (i.e. ruleset order)."""
    tables: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []

    for rule in rules:
        key = (rule.family, rule.table)
        if key not in tables:
            tables[key] = {"chains": {}, "chain_order": []}
            order.append(key)
        bucket = tables[key]
        if rule.chain not in bucket["chains"]:
            bucket["chains"][rule.chain] = []
            bucket["chain_order"].append(rule.chain)
        bucket["chains"][rule.chain].append(rule)

    result: list[dict] = []
    for family, table in sorted(order):
        bucket = tables[(family, table)]
        chains = [
            {"chain": ch, "rules": bucket["chains"][ch]}
            for ch in bucket["chain_order"]
        ]
        count = sum(len(c["rules"]) for c in chains)
        result.append({"family": family, "table": table, "count": count, "chains": chains})
    return result
