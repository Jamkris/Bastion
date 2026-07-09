"""환경변수 기반 설정. Docker(컨테이너 root)든 systemd(sudo)든 동일 코드가 돌도록."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # 명령 실행 시 sudo 프리픽스 여부.
    #   Docker(컨테이너 내부 root + NET_ADMIN) → false
    #   systemd 베어메탈에서 비권한 유저로 실행 → true (sudoers 화이트리스트 필요)
    sudo: bool = os.environ.get("BASTION_SUDO", "false").lower() == "true"

    # 데모 모드: 실제 명령 대신 샘플 데이터를 반환 (리눅스 명령 없는 개발환경/공개 데모).
    demo: bool = os.environ.get("BASTION_DEMO", "false").lower() == "true"

    # 조회할 fail2ban jail 목록 (쉼표 구분). 비면 `status`로 자동 발견.
    jails: tuple[str, ...] = tuple(
        j.strip() for j in os.environ.get("BASTION_JAILS", "").split(",") if j.strip()
    )

    # GeoLite2 Country/City .mmdb 경로. 없으면 국가 보강 생략.
    geoip_db: str = os.environ.get("BASTION_GEOIP_DB", "")

    # 명령 타임아웃(초).
    command_timeout: int = int(os.environ.get("BASTION_CMD_TIMEOUT", "10"))

    @property
    def sudo_prefix(self) -> tuple[str, ...]:
        return ("sudo",) if self.sudo else ()


settings = Settings()
