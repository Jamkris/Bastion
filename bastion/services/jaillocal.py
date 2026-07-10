"""Persist allowlist entries to fail2ban's jail.local.

Runtime `fail2ban-client addignoreip` takes effect immediately but is forgotten
on restart. To make an entry permanent we edit the `ignoreip` line in the
`[DEFAULT]` section of jail.local so fail2ban loads it on every start.

The transform functions (`parse_entries`, `add_ip`, `remove_ip`) are pure —
string in, string out — so they are exhaustively unit-tested without touching
the filesystem. The IO wrapper reads/writes the configured file and never
raises to its caller: a missing or read-only file just means "not persisted".
"""

from __future__ import annotations

import logging
import os
import re

from bastion.config import settings

log = logging.getLogger("bastion.jaillocal")

_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")
_IGNOREIP_RE = re.compile(r"^(\s*)ignoreip(\s*)=(\s*)(.*)$")


def _default_bounds(lines: list[str]) -> tuple[int | None, int]:
    """Return (header_index, end_index) of the [DEFAULT] section, where
    end_index is the line of the next section (or len(lines))."""
    start: int | None = None
    for i, line in enumerate(lines):
        m = _SECTION_RE.match(line)
        if not m:
            continue
        if m.group(1).upper() == "DEFAULT":
            start = i
        elif start is not None:
            return start, i
    return (start, len(lines)) if start is not None else (None, len(lines))


def _ignoreip_index(lines: list[str], start: int, end: int) -> int | None:
    """Index of the active (uncommented) ignoreip line within [start+1, end)."""
    for i in range(start + 1, end):
        if lines[i].lstrip().startswith("#"):
            continue
        if _IGNOREIP_RE.match(lines[i]):
            return i
    return None


def parse_entries(content: str) -> list[str]:
    """The IP/CIDR tokens on the [DEFAULT] ignoreip line (empty if none)."""
    lines = content.splitlines()
    start, end = _default_bounds(lines)
    if start is None:
        return []
    idx = _ignoreip_index(lines, start, end)
    if idx is None:
        return []
    return _IGNOREIP_RE.match(lines[idx]).group(4).split()


def _rebuild_line(template: str, tokens: list[str]) -> str:
    m = _IGNOREIP_RE.match(template)
    lead, before_eq, after_eq = m.group(1), m.group(2), m.group(3) or " "
    return f"{lead}ignoreip{before_eq}={after_eq}{' '.join(tokens)}".rstrip()


def _with_trailing_newline(original: str, lines: list[str]) -> str:
    text = "\n".join(lines)
    if original.endswith("\n"):
        text += "\n"
    return text


def add_ip(content: str, ip: str) -> str:
    """Return content with `ip` present on the [DEFAULT] ignoreip line
    (idempotent). Creates the line or the [DEFAULT] section if absent."""
    lines = content.splitlines()
    start, end = _default_bounds(lines)

    if start is None:
        # No [DEFAULT] section: prepend one.
        header = ["[DEFAULT]", f"ignoreip = {ip}", ""]
        return _with_trailing_newline(content or "\n", header + lines)

    idx = _ignoreip_index(lines, start, end)
    if idx is None:
        lines.insert(start + 1, f"ignoreip = {ip}")
        return _with_trailing_newline(content, lines)

    tokens = _IGNOREIP_RE.match(lines[idx]).group(4).split()
    if ip not in tokens:
        tokens.append(ip)
        lines[idx] = _rebuild_line(lines[idx], tokens)
    return _with_trailing_newline(content, lines)


def remove_ip(content: str, ip: str) -> str:
    """Return content with `ip` removed from the [DEFAULT] ignoreip line
    (no-op if absent)."""
    lines = content.splitlines()
    start, end = _default_bounds(lines)
    if start is None:
        return content
    idx = _ignoreip_index(lines, start, end)
    if idx is None:
        return content
    tokens = [t for t in _IGNOREIP_RE.match(lines[idx]).group(4).split() if t != ip]
    lines[idx] = _rebuild_line(lines[idx], tokens)
    return _with_trailing_newline(content, lines)


# ---------- IO (best-effort; never raises) ----------
def is_writable() -> bool:
    path = settings.jail_local
    return os.path.isfile(path) and os.access(path, os.W_OK)


def _apply(transform, ip: str) -> bool:
    path = settings.jail_local
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        new_content = transform(content, ip)
        if new_content == content:
            return True  # already in desired state
        tmp = path + ".bastion.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(new_content)
        os.replace(tmp, path)
        return True
    except OSError as e:
        log.warning("could not persist ignoreip to %s: %s", path, e)
        return False


def persist_add(ip: str) -> bool:
    return _apply(add_ip, ip)


def persist_remove(ip: str) -> bool:
    return _apply(remove_ip, ip)
