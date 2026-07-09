"""Auth log raw text. Prefers the file (/var/log/auth.log), falls back to journald."""

import os

from bastion import demo_data
from bastion.config import settings
from bastion.runner import run

DEFAULT_AUTH_LOG = os.environ.get("BASTION_AUTH_LOG", "/var/log/auth.log")


def raw_auth_log(path: str = DEFAULT_AUTH_LOG, max_bytes: int = 5_000_000) -> str:
    """Read the auth log. Fall back to journalctl if the file is absent."""
    if settings.demo:
        return demo_data.AUTH_LOG
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()[-max_bytes:]
    return run(["journalctl", "-u", "ssh", "--no-pager", "-n", "10000"])
