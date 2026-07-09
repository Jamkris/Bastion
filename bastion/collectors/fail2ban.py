"""Run fail2ban-client -> raw text."""

from bastion import demo_data
from bastion.config import settings
from bastion.runner import run


def raw_jail_list() -> str:
    if settings.demo:
        return demo_data.FAIL2BAN_STATUS
    return run(["fail2ban-client", "status"])


def raw_jail_status(jail: str) -> str:
    if settings.demo:
        return demo_data.FAIL2BAN_STATUS_SSHD
    return run(["fail2ban-client", "status", jail])
