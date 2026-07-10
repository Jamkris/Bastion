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


def _attempt_counts():
    """Best-effort auth-log attempt counts; empty if the log is unavailable."""
    try:
        return p_attackers.attempt_counts(authlog.raw_auth_log())
    except Exception:  # noqa: BLE001 — attempts are supplementary, never fatal
        return {}


def _current_banned_ips() -> set[str]:
    """Best-effort set of all currently-banned IPs across jails."""
    try:
        jails = p_fail2ban.parse_jail_list(fail2ban.raw_jail_list())
        ips: set[str] = set()
        for jail in jails:
            status = p_fail2ban.parse_jail_status(fail2ban.raw_jail_status(jail))
            ips.update(status.banned_ips)
        return ips
    except Exception:  # noqa: BLE001 — exclusion is best-effort
        return set()


def banned_ips():
    def _():
        counts = _attempt_counts()
        jails = p_fail2ban.parse_jail_list(fail2ban.raw_jail_list())
        out: list[BannedIP] = []
        for jail in jails:
            status = p_fail2ban.parse_jail_status(fail2ban.raw_jail_status(jail))
            for ip in status.banned_ips:
                out.append(BannedIP(ip=ip, jail=jail, country=country_of(ip),
                                    count=counts.get(ip, 0)))
        return out

    return _safe(_)


def open_ports():
    return _safe(lambda: p_ports.parse_listening_ports(ports.raw_listening()))


def top_attackers():
    def _():
        # Drop IPs that are already banned — no point re-listing them here.
        banned = _current_banned_ips()
        stats = p_attackers.parse_attackers(authlog.raw_auth_log(), exclude=banned)
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
