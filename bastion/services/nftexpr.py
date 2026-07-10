"""Render an nftables JSON rule expression into readable nft-like syntax.

`nft -j list ruleset` emits each rule's body as a list of statement objects.
Shown raw, that JSON is unreadable; this turns it into something close to what
`nft list ruleset` (non-JSON) prints, e.g. `tcp dport 22 accept` or
`ip saddr @allowlist accept`.

Pure and defensive: any shape it doesn't recognise falls back to a compact
form rather than raising, so a novel rule never breaks the Firewall page.
"""

from __future__ import annotations

import json
from typing import Any

# meta keys that nft prints without the leading "meta".
_BARE_META = {"iifname", "oifname", "iif", "oif", "mark", "l4proto", "nfproto"}
_VERDICTS = {"accept", "drop", "reject", "return", "continue", "masquerade"}


def render_expr(expr: Any) -> str:
    """Render a rule expression (JSON string or parsed list) to nft-like text."""
    if isinstance(expr, str):
        try:
            items = json.loads(expr)
        except ValueError:
            return expr
    else:
        items = expr
    if not isinstance(items, list):
        return str(items)
    parts = [_stmt(s) for s in items]
    return " ".join(p for p in parts if p)


def _stmt(stmt: Any) -> str:
    if not isinstance(stmt, dict) or len(stmt) != 1:
        return _value(stmt)
    key, val = next(iter(stmt.items()))

    if key in _VERDICTS:
        return key
    if key == "match":
        return _match(val)
    if key in ("jump", "goto"):
        target = val.get("target") if isinstance(val, dict) else val
        return f"{key} {target}"
    if key == "counter":
        return "counter"
    if key == "log":
        prefix = val.get("prefix") if isinstance(val, dict) else None
        return f'log prefix "{prefix}"' if prefix else "log"
    if key in ("dnat", "snat"):
        return f"{key} to {_dnat_target(val)}"
    if key == "mangle":
        # {"mangle": {"key": <left>, "value": <v>}} -> "<left> set <v>"
        return f"{_value(val.get('key'))} set {_value(val.get('value'))}".strip()
    if key == "limit":
        return "limit"
    if key == "queue":
        return "queue"
    if key == "reject":
        return "reject"
    if key == "xt":
        # iptables-nft compatibility match/target (e.g. UFW's `-m conntrack`).
        # nft can't express it natively; surface the extension name.
        name = val.get("name") if isinstance(val, dict) else None
        return name or "xt"
    # Unknown statement: show its key (and value if scalar).
    if val in (None, {}, []):
        return key
    return f"{key} {_value(val)}"


def _match(val: Any) -> str:
    if not isinstance(val, dict):
        return _value(val)
    op = val.get("op", "==")
    left = _value(val.get("left"))
    right = _value(val.get("right"))
    if op == "==":
        return f"{left} {right}".strip()
    return f"{left} {op} {right}".strip()


def _dnat_target(val: Any) -> str:
    if isinstance(val, dict):
        addr = _value(val.get("addr")) if val.get("addr") is not None else ""
        port = val.get("port")
        return f"{addr}:{port}" if port is not None else addr
    return _value(val)


def _value(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return " . ".join(_value(x) for x in v)
    if isinstance(v, dict):
        return _dict_value(v)
    return str(v)


def _dict_value(v: dict) -> str:
    if "payload" in v:  # {"payload": {"protocol": "tcp", "field": "dport"}}
        p = v["payload"]
        return f"{p.get('protocol', '')} {p.get('field', '')}".strip() or "payload"
    if "meta" in v:  # {"meta": {"key": "iifname"}}
        key = v["meta"].get("key", "")
        return key if key in _BARE_META else f"meta {key}".strip()
    if "ct" in v:  # {"ct": {"key": "state"}}
        return f"ct {v['ct'].get('key', '')}".strip()
    if "set" in v:  # anonymous set {"set": ["a", "b"]} or named "@name"
        elems = v["set"]
        if isinstance(elems, list):
            return "{ " + ", ".join(_value(e) for e in elems) + " }"
        return _value(elems)
    if "prefix" in v:  # {"prefix": {"addr": "10.0.0.0", "len": 8}}
        p = v["prefix"]
        return f"{_value(p.get('addr'))}/{p.get('len')}"
    if "range" in v:  # {"range": [1, 1024]}
        r = v["range"]
        return f"{_value(r[0])}-{_value(r[1])}" if isinstance(r, list) and len(r) == 2 else _value(r)
    if "concat" in v:
        return " . ".join(_value(x) for x in v["concat"])
    # Unknown object: compact JSON so nothing is lost.
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
