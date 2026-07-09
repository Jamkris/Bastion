"""인증 로그 원시 텍스트. 파일(/var/log/auth.log) 우선, 없으면 journald."""

import os

from bastion import demo_data
from bastion.config import settings
from bastion.runner import run

DEFAULT_AUTH_LOG = os.environ.get("BASTION_AUTH_LOG", "/var/log/auth.log")


def raw_auth_log(path: str = DEFAULT_AUTH_LOG, max_bytes: int = 5_000_000) -> str:
    """auth.log 파일을 읽어 반환. 파일이 없으면 journalctl로 폴백."""
    if settings.demo:
        return demo_data.AUTH_LOG
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()[-max_bytes:]
    return run(["journalctl", "-u", "ssh", "--no-pager", "-n", "10000"])
