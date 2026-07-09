"""Minimal i18n. English is the default; Korean is the alternate.
Language is resolved from a `lang` cookie and switchable via `?lang=` on the index."""

from __future__ import annotations

SUPPORTED = ("en", "ko")
DEFAULT = "en"

TRANSLATIONS = {
    "en": {
        "auto_refresh": "Auto-refresh every 30s",
        "loading": "Loading…",
        "filter": "Filter…",
        "matched": "matched",
        "nav_home": "Home",
        "view_details": "Details",
        "empty": "No data",
        "login_title": "Sign in to continue",
        "password": "Password",
        "sign_in": "Sign in",
        "wrong_password": "Wrong password",
        "logout": "Logout",
        "panel_banned": "Banned IPs",
        "panel_attackers": "Top Attackers",
        "panel_ports": "Open Ports",
        "panel_firewall": "Firewall Rules",
        "sum_banned": "Banned IPs",
        "sum_attackers": "Attackers",
        "sum_ports": "Open ports",
        "sum_jails": "Jails",
        "th_rank": "#",
        "th_ip": "IP",
        "th_country": "Country",
        "th_jail": "Jail",
        "th_port": "Port",
        "th_proto": "Proto",
        "th_address": "Address",
        "th_scope": "Scope",
        "th_process": "Process",
        "th_pid": "PID",
        "th_queue": "Recv/Send Q",
        "th_attempts": "Attempts",
        "th_share": "Share",
        "th_type": "Type",
        "th_family_table": "Family / Table",
        "th_name": "Name",
        "th_hook": "Hook",
        "th_policy": "Policy",
        "th_elements": "Elements",
        "th_expression": "Expression",
        "th_detail": "Detail",
        "summary_currently_banned": "currently banned",
        "summary_total_failed": "total failed",
        "fw_chains": "chains",
        "fw_rules": "rules",
        "fw_sets": "sets",
    },
    "ko": {
        "auto_refresh": "30초마다 자동 갱신",
        "loading": "불러오는 중…",
        "filter": "검색…",
        "matched": "일치",
        "nav_home": "홈",
        "view_details": "자세히",
        "empty": "데이터 없음",
        "login_title": "계속하려면 로그인",
        "password": "비밀번호",
        "sign_in": "로그인",
        "wrong_password": "비밀번호가 틀렸습니다",
        "logout": "로그아웃",
        "panel_banned": "차단된 IP",
        "panel_attackers": "자주 공격하는 IP",
        "panel_ports": "열린 포트",
        "panel_firewall": "방화벽 규칙",
        "sum_banned": "차단 IP",
        "sum_attackers": "공격자",
        "sum_ports": "열린 포트",
        "sum_jails": "Jail",
        "th_rank": "#",
        "th_ip": "IP",
        "th_country": "국가",
        "th_jail": "jail",
        "th_port": "포트",
        "th_proto": "프로토콜",
        "th_address": "주소",
        "th_scope": "범위",
        "th_process": "프로세스",
        "th_pid": "PID",
        "th_queue": "수신/송신 큐",
        "th_attempts": "시도",
        "th_share": "비율",
        "th_type": "종류",
        "th_family_table": "패밀리 / 테이블",
        "th_name": "이름",
        "th_hook": "훅",
        "th_policy": "정책",
        "th_elements": "원소",
        "th_expression": "표현식",
        "th_detail": "내용",
        "summary_currently_banned": "현재 차단",
        "summary_total_failed": "누적 실패",
        "fw_chains": "체인",
        "fw_rules": "규칙",
        "fw_sets": "셋",
    },
}


def normalize(lang: str | None) -> str:
    return lang if lang in SUPPORTED else DEFAULT


def translator(lang: str):
    lang = normalize(lang)
    table = TRANSLATIONS[lang]

    def t(key: str) -> str:
        return table.get(key, TRANSLATIONS[DEFAULT].get(key, key))

    return t
