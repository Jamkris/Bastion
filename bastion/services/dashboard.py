"""Combine collectors + parsers + GeoIP into view-ready data.
Each function returns a (data, error) tuple so one failing panel does not
break the others (dev environments lack nft/fail2ban)."""

from __future__ import annotations

from bastion.collectors import authlog, fail2ban, firewall, ports
from bastion.models import AttackerStat, BannedIP
from bastion.runner import CommandError
from bastion.services import attackers as p_attackers
from bastion.services import fail2ban as p_fail2ban
from bastion.services import firewall as p_firewall
from bastion.services import ports as p_ports
from bastion.services.geoip import country_of


def _safe(fn):
    try:
        return fn(), None
    except CommandError as e:
        return None, str(e)
    except Exception as e:  # noqa: BLE001 — panel isolation is intentional
        return None, f"{type(e).__name__}: {e}"


def jail_summaries():
    def _():
        jails = p_fail2ban.parse_jail_list(fail2ban.raw_jail_list())
        return [p_fail2ban.parse_jail_status(fail2ban.raw_jail_status(j)) for j in jails]

    return _safe(_)


def banned_ips():
    def _():
        jails = p_fail2ban.parse_jail_list(fail2ban.raw_jail_list())
        out: list[BannedIP] = []
        for jail in jails:
            status = p_fail2ban.parse_jail_status(fail2ban.raw_jail_status(jail))
            for ip in status.banned_ips:
                out.append(BannedIP(ip=ip, jail=jail, country=country_of(ip)))
        return out

    return _safe(_)


def open_ports():
    return _safe(lambda: p_ports.parse_listening_ports(ports.raw_listening()))


def top_attackers():
    def _():
        stats = p_attackers.parse_attackers(authlog.raw_auth_log())
        return [AttackerStat(ip=s.ip, count=s.count, country=country_of(s.ip)) for s in stats]

    return _safe(_)


def firewall_ruleset():
    return _safe(lambda: p_firewall.parse_ruleset(firewall.raw_ruleset()))


def summary() -> dict:
    """Top-of-page counters. Tolerant of individual collector failures."""
    jails, _ = jail_summaries()
    ports, _ = open_ports()
    attackers, _ = top_attackers()
    return {
        "total_banned": sum(j.currently_banned for j in (jails or [])),
        "jail_count": len(jails or []),
        "open_ports": len(ports or []),
        "attackers": len(attackers or []),
    }
