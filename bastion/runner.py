"""명령 실행 추상화. 테스트에서는 이 함수를 monkeypatch 하거나
collectors에 가짜 출력을 주입해 파서를 순수하게 검증한다."""

from __future__ import annotations

import subprocess

from bastion.config import settings


class CommandError(RuntimeError):
    def __init__(self, cmd: list[str], returncode: int, stderr: str):
        self.cmd = cmd
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"명령 실패({returncode}): {' '.join(cmd)}\n{stderr.strip()}")


def run(cmd: list[str], timeout: int | None = None) -> str:
    """cmd를 실행하고 stdout(str)을 반환. 실패 시 CommandError."""
    full = list(settings.sudo_prefix) + cmd
    proc = subprocess.run(
        full,
        capture_output=True,
        text=True,
        timeout=timeout or settings.command_timeout,
    )
    if proc.returncode != 0:
        raise CommandError(full, proc.returncode, proc.stderr)
    return proc.stdout
