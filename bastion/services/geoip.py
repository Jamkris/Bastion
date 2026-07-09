"""IP -> country code enrichment. Uses a GeoIP2/DB-IP .mmdb if present, else None."""

from __future__ import annotations

from functools import lru_cache

from bastion.config import settings

try:
    import geoip2.database  # type: ignore

    _HAS_GEOIP = True
except ImportError:  # the app must still work without geoip2 installed
    _HAS_GEOIP = False


@lru_cache(maxsize=1)
def _reader():
    if not (_HAS_GEOIP and settings.geoip_db):
        return None
    try:
        return geoip2.database.Reader(settings.geoip_db)
    except Exception:
        return None


def is_active() -> bool:
    """True when a GeoIP database is loaded and ready."""
    return _reader() is not None


@lru_cache(maxsize=8192)
def country_of(ip: str) -> str | None:
    reader = _reader()
    if reader is None:
        return None
    try:
        return reader.country(ip).country.iso_code
    except Exception:
        return None
