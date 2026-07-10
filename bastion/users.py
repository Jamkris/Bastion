"""User account store with salted password hashing.

Layered on top of the single-password gate: when at least one user exists,
Bastion runs in multi-user mode (username + password login); with no users it
falls back to `BASTION_AUTH_PASSWORD`, and with neither it runs open.

Passwords are hashed with PBKDF2-HMAC-SHA256 (per-user random salt). The hashing
helpers are pure so they can be unit-tested with a fixed salt; the store does
best-effort JSON IO under the data directory.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re

from bastion.config import settings

log = logging.getLogger("bastion.users")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
_ITERATIONS = 200_000


def hash_password(password: str, *, salt: bytes | str | None = None, iterations: int = _ITERATIONS) -> str:
    """Return a self-describing `pbkdf2_sha256$iters$salt$hash` string.
    Pass `salt` (hex or bytes) for a deterministic result in tests."""
    if salt is None:
        salt = os.urandom(16)
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_hash(password: str, stored: str) -> bool:
    """Constant-time check of `password` against a stored hash string."""
    try:
        algo, iters, salt_hex, _ = stored.split("$")
    except (ValueError, AttributeError):
        return False
    if algo != "pbkdf2_sha256":
        return False
    candidate = hash_password(password, salt=salt_hex, iterations=int(iters))
    return hmac.compare_digest(candidate, stored)


# ---------- store (best-effort JSON IO) ----------
def _path() -> str:
    return os.path.join(settings.data_dir, "users.json")


def load() -> dict[str, str]:
    path = _path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError) as e:
        log.warning("could not read users (%s)", e)
        return {}


def save(users: dict[str, str]) -> None:
    os.makedirs(settings.data_dir, exist_ok=True)
    path = _path()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def count() -> int:
    return len(load())


def exists(username: str) -> bool:
    return username in load()


def usernames() -> list[str]:
    return sorted(load().keys())


def add(username: str, password: str) -> None:
    if not USERNAME_RE.match(username or ""):
        raise ValueError(f"invalid username: {username!r}")
    if not password:
        raise ValueError("password must not be empty")
    users = load()
    users[username] = hash_password(password)
    save(users)
    log.info("user added: %s", username)


def set_password(username: str, password: str) -> None:
    if not password:
        raise ValueError("password must not be empty")
    users = load()
    if username not in users:
        raise ValueError(f"no such user: {username!r}")
    users[username] = hash_password(password)
    save(users)
    log.info("password changed: %s", username)


def remove(username: str) -> None:
    users = load()
    if username in users:
        del users[username]
        save(users)
        log.info("user removed: %s", username)


def verify(username: str, password: str) -> bool:
    stored = load().get(username)
    return bool(stored) and verify_hash(password, stored)
