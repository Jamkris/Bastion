"""Immutable data models. Parsers (services) turn raw output into these types."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class JailStatus:
    name: str
    currently_failed: int
    total_failed: int
    currently_banned: int
    total_banned: int
    file_list: tuple[str, ...]
    banned_ips: tuple[str, ...]


@dataclass(frozen=True)
class BannedIP:
    ip: str
    jail: str
    country: str | None = None


@dataclass(frozen=True)
class OpenPort:
    proto: str
    local_address: str
    port: int
    recv_q: int
    send_q: int
    process: str | None = None
    pid: int | None = None


@dataclass(frozen=True)
class AttackerStat:
    ip: str
    count: int
    country: str | None = None


@dataclass(frozen=True)
class FirewallChain:
    family: str
    table: str
    name: str
    type: str | None
    hook: str | None
    policy: str | None


@dataclass(frozen=True)
class FirewallRule:
    family: str
    table: str
    chain: str
    handle: int
    expr: str


@dataclass(frozen=True)
class FirewallSet:
    family: str
    table: str
    name: str
    type: str
    elements: tuple[str, ...]


@dataclass(frozen=True)
class FirewallRuleset:
    chains: tuple[FirewallChain, ...]
    rules: tuple[FirewallRule, ...]
    sets: tuple[FirewallSet, ...]
