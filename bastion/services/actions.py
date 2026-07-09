"""Write actions against fail2ban (ban / unban).

Uses fail2ban-client over the same socket the reader uses, so no extra
privilege is required under Docker. Inputs are strictly validated and every
command is run as an argv list (never a shell string) to prevent injection.
Actions are audit-logged.
"""

from __future__ import annotations

import ipaddress
import logging
import re

from bastion.runner import run

log = logging.getLogger("bastion.actions")

_JAIL_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def _validate(jail: str, ip: str) -> None:
    if not _JAIL_RE.match(jail or ""):
        raise ValueError(f"invalid jail: {jail!r}")
    ipaddress.ip_address(ip)  # raises ValueError for anything that is not an IP


def ban(jail: str, ip: str) -> None:
    _validate(jail, ip)
    run(["fail2ban-client", "set", jail, "banip", ip])
    log.info("ban jail=%s ip=%s", jail, ip)


def unban(jail: str, ip: str) -> None:
    _validate(jail, ip)
    run(["fail2ban-client", "set", jail, "unbanip", ip])
    log.info("unban jail=%s ip=%s", jail, ip)
