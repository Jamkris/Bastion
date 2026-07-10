"""Manage fail2ban `ignoreip` (per-jail allowlist).

This is the allowlist most fail2ban setups actually use: trusted IPs that are
never banned. It works regardless of the firewall backend (UFW, iptables,
nftables) because fail2ban owns it. Entries are managed at runtime over the same
fail2ban socket Bastion already uses:

    fail2ban-client get <jail> ignoreip
    fail2ban-client set <jail> addignoreip <ip>
    fail2ban-client set <jail> delignoreip <ip>

Note: runtime changes take effect immediately but are not written back to
jail.local, so a fail2ban restart reloads whatever is in the config file. Use
the config file for permanent entries; use this for quick, live changes.
"""

from __future__ import annotations

import ipaddress
import logging
import re

from bastion import prefs
from bastion.runner import CommandError, run
from bastion.services import dashboard, jaillocal

log = logging.getLogger("bastion.ignoreip")

_JAIL_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
# Tree/branch characters fail2ban-client draws around list output.
_STRIP = "|`- \t"


def _validate_jail(jail: str) -> None:
    if not _JAIL_RE.match(jail or ""):
        raise ValueError(f"invalid jail: {jail!r}")


def normalize_ip(value: str) -> str:
    """Canonical host IP or CIDR, or raise ValueError."""
    value = (value or "").strip()
    if "/" in value:
        return str(ipaddress.ip_network(value, strict=False))
    return str(ipaddress.ip_address(value))


def _is_ip_entry(token: str) -> bool:
    try:
        normalize_ip(token)
        return True
    except ValueError:
        return False


def parse_ignoreip(raw: str) -> list[str]:
    """Pure: pull IP/CIDR entries out of `fail2ban-client get <jail> ignoreip`
    output. Robust to the various tree-drawing formats across fail2ban versions
    — any token that validates as an IP or network is kept (order preserved)."""
    seen: set[str] = set()
    out: list[str] = []
    for line in raw.splitlines():
        cleaned = line.strip().strip(_STRIP)
        for token in re.split(r"[\s,]+", cleaned):
            token = token.strip(_STRIP).strip("`'\"")
            if token and _is_ip_entry(token) and token not in seen:
                seen.add(token)
                out.append(token)
    return out


def _jail_names() -> tuple[list[str], str | None]:
    summaries, error = dashboard.jail_summaries()
    return [s.name for s in (summaries or [])], error


def list_all() -> tuple[list[dict], str | None]:
    """Return ([{jail, entries}], error). Error is set only when jails can't be
    listed at all; a single jail failing is reported as empty entries."""
    names, error = _jail_names()
    if error and not names:
        return [], error
    result: list[dict] = []
    for jail in names:
        try:
            raw = run(["fail2ban-client", "get", jail, "ignoreip"])
            result.append({"jail": jail, "entries": parse_ignoreip(raw)})
        except CommandError as e:
            result.append({"jail": jail, "entries": [], "error": str(e)})
    return result, None


def _persist_enabled() -> bool:
    return bool(prefs.get("allowlist").get("persist"))


def add(jail: str, ip: str) -> None:
    _validate_jail(jail)
    canonical = normalize_ip(ip)
    run(["fail2ban-client", "set", jail, "addignoreip", canonical])  # immediate
    if _persist_enabled():
        jaillocal.persist_add(canonical)  # durable; best-effort, never raises
    log.info("ignoreip add jail=%s ip=%s persist=%s", jail, canonical, _persist_enabled())


def remove(jail: str, ip: str) -> None:
    _validate_jail(jail)
    canonical = normalize_ip(ip)
    run(["fail2ban-client", "set", jail, "delignoreip", canonical])  # immediate
    if _persist_enabled():
        jaillocal.persist_remove(canonical)  # durable; best-effort, never raises
    log.info("ignoreip remove jail=%s ip=%s persist=%s", jail, canonical, _persist_enabled())
