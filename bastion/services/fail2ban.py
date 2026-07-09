"""fail2ban-client 텍스트 출력 파서 (순수 함수)."""

import re

from bastion.models import JailStatus

_JAIL_NAME = re.compile(r"Status for the jail:\s*(\S+)")
_CUR_FAILED = re.compile(r"Currently failed:\s*(\d+)")
_TOT_FAILED = re.compile(r"Total failed:\s*(\d+)")
_FILE_LIST = re.compile(r"File list:\s*(.+)")
_CUR_BANNED = re.compile(r"Currently banned:\s*(\d+)")
_TOT_BANNED = re.compile(r"Total banned:\s*(\d+)")
_BANNED_IPS = re.compile(r"Banned IP list:\s*(.*)")

_NUM_JAIL = re.compile(r"Number of jail:\s*(\d+)")
_JAIL_LIST = re.compile(r"Jail list:\s*(.*)")


def _int(pattern: re.Pattern, raw: str, default: int = 0) -> int:
    m = pattern.search(raw)
    return int(m.group(1)) if m else default


def parse_jail_list(raw: str) -> tuple[str, ...]:
    """`fail2ban-client status` 출력에서 jail 이름 목록을 추출."""
    m = _JAIL_LIST.search(raw)
    if not m:
        return ()
    return tuple(j for j in re.split(r"[,\s]+", m.group(1).strip()) if j)


def parse_jail_status(raw: str) -> JailStatus:
    """`fail2ban-client status <jail>` 출력을 JailStatus로 변환."""
    name_m = _JAIL_NAME.search(raw)
    if not name_m:
        raise ValueError("fail2ban jail status를 파싱할 수 없습니다 (헤더 없음)")

    file_m = _FILE_LIST.search(raw)
    files = tuple(file_m.group(1).split()) if file_m else ()

    ips_m = _BANNED_IPS.search(raw)
    ips = tuple(ips_m.group(1).split()) if ips_m else ()

    return JailStatus(
        name=name_m.group(1),
        currently_failed=_int(_CUR_FAILED, raw),
        total_failed=_int(_TOT_FAILED, raw),
        currently_banned=_int(_CUR_BANNED, raw),
        total_banned=_int(_TOT_BANNED, raw),
        file_list=files,
        banned_ips=ips,
    )
