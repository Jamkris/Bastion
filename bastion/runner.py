"""Command execution wrapper. Tests monkeypatch this or inject fake output
into collectors so parsers can be verified in isolation."""

from __future__ import annotations

import subprocess

from bastion.config import settings


class CommandError(RuntimeError):
    def __init__(self, cmd: list[str], returncode: int, stderr: str):
        self.cmd = cmd
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"command failed ({returncode}): {' '.join(cmd)}\n{stderr.strip()}")


def run(cmd: list[str], timeout: int | None = None) -> str:
    """Run cmd and return stdout. Raise CommandError on non-zero exit or a
    missing binary, so callers only ever need to handle CommandError."""
    full = list(settings.sudo_prefix) + cmd
    try:
        proc = subprocess.run(
            full,
            capture_output=True,
            text=True,
            timeout=timeout or settings.command_timeout,
        )
    except FileNotFoundError as e:
        raise CommandError(full, 127, f"command not found: {e}") from e
    if proc.returncode != 0:
        raise CommandError(full, proc.returncode, proc.stderr)
    return proc.stdout
