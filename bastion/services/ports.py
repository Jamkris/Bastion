"""`ss -tlnp` 출력 파서 (순수 함수)."""

import re

from bastion.models import OpenPort

# users:(("node /home/jamk",pid=895,fd=20))  → 이름, pid
_PROC = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')


def parse_listening_ports(raw: str) -> list[OpenPort]:
    ports: list[OpenPort] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("State"):
            continue
        parts = line.split()
        if len(parts) < 5 or parts[0] != "LISTEN":
            continue

        # IPv6는 주소에 콜론이 많으므로 오른쪽에서 한 번만 분리
        addr, _, port = parts[3].rpartition(":")
        if not port.isdigit():
            continue

        name: str | None = None
        pid: int | None = None
        if len(parts) > 5:
            pm = _PROC.search(" ".join(parts[5:]))
            if pm:
                name, pid = pm.group(1), int(pm.group(2))

        ports.append(
            OpenPort(
                proto="tcp",
                local_address=addr,
                port=int(port),
                recv_q=int(parts[1]),
                send_q=int(parts[2]),
                process=name,
                pid=pid,
            )
        )
    return ports
