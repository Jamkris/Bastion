"""ss 실행 → 원시 텍스트."""

from bastion import demo_data
from bastion.config import settings
from bastion.runner import run


def raw_listening() -> str:
    if settings.demo:
        return demo_data.SS_TLNP
    return run(["ss", "-tlnp"])
