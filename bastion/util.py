"""Small presentation helpers."""

from __future__ import annotations


def flag_emoji(country: str | None) -> str:
    """Convert an ISO 3166-1 alpha-2 code (e.g. 'KR') to a flag emoji."""
    if not country or len(country) != 2 or not country.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c.upper()) - ord("A")) for c in country)


def port_scope(local_address: str) -> str:
    """Classify a listen address as any / ipv6 / local / specific."""
    if local_address in ("0.0.0.0", "*"):
        return "any"
    if local_address.startswith("[") or ":" in local_address:
        return "ipv6"
    if local_address.startswith("127.") or local_address == "::1":
        return "local"
    return "specific"
