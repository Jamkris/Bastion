"""IP → 국가 코드 보강. GeoLite2 .mmdb가 있으면 사용, 없으면 None."""

from __future__ import annotations

from functools import lru_cache

from bastion.config import settings

try:
    import geoip2.database  # type: ignore

    _HAS_GEOIP = True
except ImportError:  # geoip2 미설치 환경에서도 앱은 동작해야 함
    _HAS_GEOIP = False


@lru_cache(maxsize=1)
def _reader():
    if not (_HAS_GEOIP and settings.geoip_db):
        return None
    try:
        return geoip2.database.Reader(settings.geoip_db)
    except Exception:
        return None


@lru_cache(maxsize=8192)
def country_of(ip: str) -> str | None:
    reader = _reader()
    if reader is None:
        return None
    try:
        return reader.country(ip).country.iso_code
    except Exception:
        return None
