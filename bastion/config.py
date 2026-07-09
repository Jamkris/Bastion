"""Environment-based settings so the same code runs under Docker
(container root) or systemd (via sudo)."""

import os
from dataclasses import dataclass


def _load_dotenv(path: str = ".env") -> None:
    """Load KEY=VALUE lines from a .env file into the environment (if present).
    Existing env vars win (setdefault), so Docker/shell values are not overridden.
    Set BASTION_NO_DOTENV=1 to skip loading entirely (used by the test suite so
    that runs are not affected by a developer's local .env)."""
    if os.environ.get("BASTION_NO_DOTENV") == "1":
        return
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()


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

    # Single shared password for the login gate. Empty -> auth disabled (open).
    auth_password: str = os.environ.get("BASTION_AUTH_PASSWORD", "")

    # Command timeout in seconds.
    command_timeout: int = int(os.environ.get("BASTION_CMD_TIMEOUT", "10"))

    @property
    def sudo_prefix(self) -> tuple[str, ...]:
        return ("sudo",) if self.sudo else ()


settings = Settings()
