"""Stable server secret used to sign multi-user session cookies.

Resolution order: BASTION_SECRET_KEY env, then a persisted random key under the
data directory (created once, 0600), then an in-memory fallback if the data dir
is not writable (sessions won't survive a restart, but auth still works).
"""

from __future__ import annotations

import logging
import os
import secrets

from bastion.config import settings

log = logging.getLogger("bastion.secretkey")

_ephemeral: str | None = None


def get() -> str:
    env = os.environ.get("BASTION_SECRET_KEY")
    if env:
        return env
    path = os.path.join(settings.data_dir, ".secret")
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return f.read().strip()
        os.makedirs(settings.data_dir, exist_ok=True)
        key = secrets.token_hex(32)
        with open(path, "w", encoding="utf-8") as f:
            f.write(key)
        os.chmod(path, 0o600)
        return key
    except OSError as e:
        global _ephemeral
        if _ephemeral is None:
            log.warning("data dir not writable (%s); using an ephemeral session key", e)
            _ephemeral = secrets.token_hex(32)
        return _ephemeral
