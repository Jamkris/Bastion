"""nft 실행 → 원시 JSON 텍스트."""

from bastion import demo_data
from bastion.config import settings
from bastion.runner import run


def raw_ruleset() -> str:
    if settings.demo:
        return demo_data.NFT_RULESET
    return run(["nft", "-j", "list", "ruleset"])
