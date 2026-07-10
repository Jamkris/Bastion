"""Manage an nftables allowlist set (add / remove / list trusted IPs).

The set itself must already exist in the ruleset (created by the operator's
nftables config); Bastion only adds and removes elements. Which set is targeted
is configured on the Settings page (family / table / set name).

As with fail2ban actions, every input is strictly validated and commands run as
argv lists (never a shell string). Changes are audit-logged.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re

from bastion import prefs
from bastion.runner import CommandError, run

log = logging.getLogger("bastion.allowlist")

_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_FAMILIES = {"inet", "ip", "ip6", "arp", "bridge", "netdev"}


def _target() -> tuple[str, str, str]:
    a = prefs.get("allowlist")
    return a["family"], a["table"], a["set"]


def _validate_target(family: str, table: str, name: str) -> None:
    if family not in _FAMILIES:
        raise ValueError(f"invalid nftables family: {family!r}")
    if not _NAME_RE.match(table or ""):
        raise ValueError(f"invalid table name: {table!r}")
    if not _NAME_RE.match(name or ""):
        raise ValueError(f"invalid set name: {name!r}")


def normalize_ip(value: str) -> str:
    """Return a canonical host IP or CIDR string, or raise ValueError.
    Accepts both a single address (1.2.3.4) and a network (10.0.0.0/24)."""
    value = (value or "").strip()
    if "/" in value:
        return str(ipaddress.ip_network(value, strict=False))
    return str(ipaddress.ip_address(value))


def parse_elements(raw: str) -> list[str]:
    """Pure: extract element strings from `nft -j list set ...` output."""
    data = json.loads(raw)
    for item in data.get("nftables", []):
        if "set" in item:
            elem = item["set"].get("elem") or []
            return [e if isinstance(e, str) else json.dumps(e, ensure_ascii=False) for e in elem]
    return []


_SET_TYPES = {"ipv4_addr", "ipv6_addr"}


def set_missing(error: str | None) -> bool:
    """True when an error means the target set/table does not exist yet
    (as opposed to a permission or syntax problem)."""
    if not error:
        return False
    e = error.lower()
    return "no such file" in e or "does not exist" in e or "doesn't exist" in e


def list_entries() -> tuple[list[str], str | None]:
    """Return (entries, error). A missing set surfaces as an error string."""
    family, table, name = _target()
    try:
        _validate_target(family, table, name)
        raw = run(["nft", "-j", "list", "set", family, table, name])
        return parse_elements(raw), None
    except (ValueError, CommandError) as e:
        return [], str(e)


def create_set(set_type: str = "ipv4_addr") -> None:
    """Create the configured set (convenience for first-time setup).
    The target table must already exist. `flags interval` lets the set hold
    both single addresses and CIDR ranges."""
    family, table, name = _target()
    _validate_target(family, table, name)
    if set_type not in _SET_TYPES:
        raise ValueError(f"invalid set type: {set_type!r}")
    run(["nft", "add", "set", family, table, name,
         "{ type " + set_type + "; flags interval; }"])
    log.info("allowlist create set=%s/%s/%s type=%s", family, table, name, set_type)


def add(ip: str) -> None:
    family, table, name = _target()
    _validate_target(family, table, name)
    canonical = normalize_ip(ip)
    run(["nft", "add", "element", family, table, name, "{ " + canonical + " }"])
    log.info("allowlist add ip=%s set=%s/%s/%s", canonical, family, table, name)


def remove(ip: str) -> None:
    family, table, name = _target()
    _validate_target(family, table, name)
    canonical = normalize_ip(ip)
    run(["nft", "delete", "element", family, table, name, "{ " + canonical + " }"])
    log.info("allowlist remove ip=%s set=%s/%s/%s", canonical, family, table, name)
