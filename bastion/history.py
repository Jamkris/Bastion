"""Lightweight time-series of dashboard counters for trend sparklines.

The background poller appends one point per cycle to a JSONL file under the data
directory. The file is capped so it never grows unbounded — old points are
dropped once it exceeds the cap. All IO is best-effort and never raises to the
caller: no history just means no sparkline.
"""

from __future__ import annotations

import json
import logging
import os

from bastion.config import settings

log = logging.getLogger("bastion.history")

MAX_POINTS = 1440  # ~24h at one point per minute
_TRIM_SLACK = 240  # only rewrite the file once it grows this far past the cap


def _path() -> str:
    return os.path.join(settings.data_dir, "history.jsonl")


def record(banned: int, attackers: int, ports: int, *, ts: float) -> None:
    """Append one snapshot. `ts` is injected (epoch seconds) for testability."""
    point = {"t": int(ts), "banned": banned, "attackers": attackers, "ports": ports}
    try:
        os.makedirs(settings.data_dir, exist_ok=True)
        with open(_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(point) + "\n")
    except OSError as e:
        log.warning("could not record history: %s", e)
        return
    _trim_if_needed()


def load(limit: int | None = None) -> list[dict]:
    """Return recorded points oldest-first, optionally only the last `limit`."""
    path = _path()
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as e:
        log.warning("could not read history: %s", e)
        return []
    points: list[dict] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            points.append(json.loads(line))
        except ValueError:
            continue  # skip a torn/partial line
    return points[-limit:] if limit else points


def _trim_if_needed() -> None:
    path = _path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        if len(lines) <= MAX_POINTS + _TRIM_SLACK:
            return
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.writelines(lines[-MAX_POINTS:])
        os.replace(tmp, path)
    except OSError as e:
        log.warning("could not trim history: %s", e)
