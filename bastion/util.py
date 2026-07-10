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


def sparkline_points(values, width: int = 120, height: int = 28, pad: int = 3) -> str:
    """Map a series of numbers to an SVG polyline `points` string. Pure and
    dependency-free so trends render server-side without a charting library.
    Returns "" for an empty series; a flat line sits at the vertical middle."""
    nums = [float(v) for v in values]
    if not nums:
        return ""
    if len(nums) == 1:
        nums = nums * 2
    lo, hi = min(nums), max(nums)
    span = hi - lo
    step = (width - 2 * pad) / (len(nums) - 1)
    mid = height / 2
    coords = []
    for i, v in enumerate(nums):
        x = pad + i * step
        # Invert y (SVG origin is top-left); flat series -> mid line.
        y = mid if span == 0 else (height - pad) - (v - lo) / span * (height - 2 * pad)
        coords.append(f"{x:.1f},{y:.1f}")
    return " ".join(coords)
