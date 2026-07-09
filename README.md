# 🛡 Bastion

셀프호스팅 단일 서버용 **fail2ban + nftables 관측 대시보드**. 무겁고 클라우드에 의존하는 도구 없이, 컨테이너 하나로 방화벽 상태를 웹에서 본다.

## Features (v1.0 — read-only)

- **차단된 IP** — fail2ban jail별 밴 목록 + 국가(GeoIP)
- **자주 공격하는 IP** — auth.log/journald 로그인 실패 집계 top N
- **열린 포트** — `ss -tlnp` 리스닝 포트 + 프로세스
- **방화벽 규칙** — `nft -j list ruleset` (nftables) 체인·규칙·셋

> v0.2에서 허용/차단 IP 조작, 밴/언밴 버튼을 권한 분리 설계로 추가 예정.

## 아키텍처

```
collectors/  명령 실행 → 원시 텍스트   (fail2ban-client, nft, ss, auth.log)
services/    원시 → 파싱 → dataclass   (순수 함수, 100% 테스트 대상)
web/         FastAPI + HTMX / JSON API
```

로직이 전부 `services/`에 있어 CLI·API·HTMX가 같은 코드를 재사용한다.

## 설치 — Docker (권장)

```bash
cp .env.example .env       # 필요 시 편집
docker compose up -d --build
```

호스트 방화벽을 읽기 위해 `network_mode: host` + `cap_add: NET_ADMIN` + fail2ban 소켓/`/var/log` 마운트를 사용한다 (compose에 포함). 앱은 `:8009`로 리슨한다.

> **보안**: 관리 도구이므로 인터넷에 직접 노출하지 말 것. Cloudflare Access나 VPN(wg-easy) 뒤에 둘 것.

## 설치 — systemd (베어메탈)

같은 코드가 컨테이너 없이도 동작한다.

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
BASTION_SUDO=true .venv/bin/uvicorn bastion.web.app:app --host 127.0.0.1 --port 8009
```

`BASTION_SUDO=true`면 명령에 `sudo`를 붙인다. sudoers에 아래만 NOPASSWD 화이트리스트로 허용:

```
bastion ALL=(root) NOPASSWD: /usr/sbin/nft -j list ruleset, /usr/bin/fail2ban-client status *
```

## 설정 (환경변수)

| 변수 | 기본값 | 설명 |
|---|---|---|
| `BASTION_SUDO` | `false` | 명령에 sudo 프리픽스 |
| `BASTION_JAILS` | (자동) | 조회할 jail, 쉼표 구분 |
| `BASTION_GEOIP_DB` | (없음) | GeoLite2 .mmdb 경로 |
| `BASTION_AUTH_LOG` | `/var/log/auth.log` | 인증 로그 경로 |

## 개발

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest httpx
.venv/bin/python -m pytest      # 파서 테스트 (실서버 없이 픽스처로)
```

## 라이선스

MIT
