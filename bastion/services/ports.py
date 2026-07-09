"""Parser for `ss -tlnp` output (pure function)."""

import re

from bastion.models import OpenPort

# users:(("node /home/jamk",pid=895,fd=20))  -> name, pid
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

        # IPv6 addresses contain colons, so split only on the last one.
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
