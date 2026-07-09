"""ntfy notifications for intrusion events.

Two concerns kept apart for testability:
  * pure detection helpers (`prune`, `should_alert`) — no IO, easy to unit test;
  * `send()` — the one function that touches the network (via stdlib urllib, so
    no extra dependency).

The background poller that wires these together lives in the web app, where it
has access to the FastAPI event loop.
"""

from __future__ import annotations

import logging
import urllib.error
import urllib.request
from typing import Any, Iterable

from bastion import prefs

log = logging.getLogger("bastion")

SEND_TIMEOUT = 8  # seconds


def prune(events: Iterable[float], now: float, window_sec: float) -> list[float]:
    """Keep only event timestamps within `window_sec` of `now`."""
    return [t for t in events if t > now - window_sec]


def should_alert(events: list[float], threshold: int) -> bool:
    """True once the number of recent events reaches the threshold (>= 1)."""
    return len(events) >= max(1, threshold)


def send(
    title: str,
    message: str,
    *,
    tags: str = "",
    priority: str = "",
    n: dict[str, Any] | None = None,
) -> bool:
    """Publish a message to the configured ntfy topic. Returns True on success.
    Never raises — a failed notification must not break the caller."""
    n = n or prefs.get("notifications")
    base = str(n.get("ntfy_url", "")).strip().rstrip("/")
    topic = str(n.get("ntfy_topic", "")).strip()
    if not base or not topic:
        log.info("ntfy not configured (url/topic missing); skipping notification")
        return False

    headers = {"Title": title, "Content-Type": "text/plain; charset=utf-8"}
    if tags:
        headers["Tags"] = tags
    if priority and priority != "default":
        headers["Priority"] = str(priority)
    token = str(n.get("ntfy_token", "")).strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(
        f"{base}/{topic}", data=message.encode("utf-8"), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=SEND_TIMEOUT) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, OSError, ValueError) as e:
        log.warning("ntfy send failed: %s", e)
        return False
