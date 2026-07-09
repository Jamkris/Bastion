"""인증 로그에서 공격(로그인 실패) IP를 집계 (순수 함수)."""

import re
from collections import Counter

from bastion.models import AttackerStat

# sshd 실패 로그의 대표 패턴들. "Failed password ... from <ip>",
# "Invalid user ... from <ip>", "... authentication failure ... rhost=<ip>"
_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
_PATTERNS = [
    re.compile(rf"Failed password for .* from {_IP}"),
    re.compile(rf"Invalid user .* from {_IP}"),
    re.compile(rf"Failed password for invalid user .* from {_IP}"),
    re.compile(rf"authentication failure;.*rhost={_IP}"),
]


def parse_attackers(raw: str, top: int = 20) -> list[AttackerStat]:
    counter: Counter[str] = Counter()
    for line in raw.splitlines():
        for pat in _PATTERNS:
            m = pat.search(line)
            if m:
                counter[m.group(1)] += 1
                break
    return [AttackerStat(ip=ip, count=n) for ip, n in counter.most_common(top)]
