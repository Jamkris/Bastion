"""Environment-based settings so the same code runs under Docker
(container root) or systemd (via sudo)."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # Whether to prefix commands with sudo.
    #   Docker (container root + NET_ADMIN) -> false
    #   systemd bare-metal as an unprivileged user -> true (needs sudoers allowlist)
    sudo: bool = os.environ.get("BASTION_SUDO", "false").lower() == "true"

    # Demo mode: return sample data instead of running commands
    # (for environments without the Linux CLIs, and for a public demo).
    demo: bool = os.environ.get("BASTION_DEMO", "false").lower() == "true"

    # fail2ban jails to query (comma-separated). Empty -> auto-discover via `status`.
    jails: tuple[str, ...] = tuple(
        j.strip() for j in os.environ.get("BASTION_JAILS", "").split(",") if j.strip()
    )

    # Path to a GeoLite2 Country/City .mmdb. Empty -> skip country enrichment.
    geoip_db: str = os.environ.get("BASTION_GEOIP_DB", "")

    # Command timeout in seconds.
    command_timeout: int = int(os.environ.get("BASTION_CMD_TIMEOUT", "10"))

    @property
    def sudo_prefix(self) -> tuple[str, ...]:
        return ("sudo",) if self.sudo else ()


settings = Settings()
