"""Aggregate attacking (failed-login) IPs from the auth log (pure function)."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable

from bastion.models import AttackerStat

# Common sshd failure patterns: "Failed password ... from <ip>",
# "Invalid user ... from <ip>", "... authentication failure ... rhost=<ip>".
_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
_PATTERNS = [
    re.compile(rf"Failed password for .* from {_IP}"),
    re.compile(rf"Invalid user .* from {_IP}"),
    re.compile(rf"Failed password for invalid user .* from {_IP}"),
    re.compile(rf"authentication failure;.*rhost={_IP}"),
]


def attempt_counts(raw: str) -> Counter[str]:
    """Full IP -> failed-attempt count mapping (no truncation)."""
    counter: Counter[str] = Counter()
    for line in raw.splitlines():
        for pat in _PATTERNS:
            m = pat.search(line)
            if m:
                counter[m.group(1)] += 1
                break
    return counter


def parse_attackers(
    raw: str, top: int = 20, exclude: Iterable[str] | None = None
) -> list[AttackerStat]:
    counter = attempt_counts(raw)
    for ip in exclude or ():
        counter.pop(ip, None)  # e.g. already-banned IPs
    return [AttackerStat(ip=ip, count=n) for ip, n in counter.most_common(top)]
