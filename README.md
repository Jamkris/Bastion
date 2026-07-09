# 🛡 Bastion

A lightweight **fail2ban + nftables security dashboard** for a single self-hosted
server. See your firewall state, ban and unban IPs, manage an allowlist, and get
push alerts on attack spikes — all from the browser, in one small container.

English · [한국어](#-한국어)

---

## Features

**Observability**
- **Banned IPs** — per-jail fail2ban ban list with country flags (GeoIP)
- **Top attackers** — failed-login aggregation from `auth.log` / journald
- **Open ports** — listening sockets from `ss -tlnp` with the owning process
- **Firewall rules** — chains, rules and sets from `nft -j list ruleset`
- Client-side search/filter and click-to-sort on every table; 30s live refresh (HTMX)

**Management**
- **Ban / unban** any IP through `fail2ban-client`, with SweetAlert2 confirmations
- **Bulk ban** selected or all Top Attackers in one action
- **Allowlist** — add/remove trusted IPs (or CIDRs) in an nftables set

**Alerting**
- **ntfy push notifications** on a ban spike (configurable threshold + window),
  with a one-click *Send test* button

**Security & UX**
- Single-password **login gate** (HMAC-signed session cookie)
- **Login rate limiting** per client IP (brute-force protection)
- **Settings page** to configure notifications, allowlist target, and rate limits
  at runtime — no redeploy needed
- **English / Korean** UI, switchable from the header (persisted via cookie)

Every input is strictly validated (`ipaddress` + name allowlists), commands run as
argv lists (never a shell string), and all write actions are audit-logged. Write
actions require authentication.

## Architecture

```
runner.py     run one command -> stdout       (fail2ban-client, nft, ss)
services/     raw text -> parse -> dataclass   (pure functions, fully tested)
prefs.py      runtime user preferences         (JSON on disk, layered on env)
web/          FastAPI + HTMX pages + JSON API
```

All logic lives in `services/` / `prefs.py`, so the HTMX pages and the JSON API
reuse the same code. Parsers are pure functions tested against real-server fixtures.

## Install — Docker (recommended)

```bash
cp .env.example .env       # set BASTION_AUTH_PASSWORD (recommended)
docker compose up -d --build
```

Reading the host firewall requires `network_mode: host` + `cap_add: NET_ADMIN`,
plus mounts for the fail2ban socket and `/var/log` (all in the compose file).
A named volume `bastion_data` persists your Settings-page preferences across
restarts. The app listens on **:8009**.

> **Security**: this is an admin tool — never expose it to the internet. Put it
> behind Cloudflare Access or a VPN (e.g. wg-easy).

## Install — systemd (bare metal)

The same code runs without a container.

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
BASTION_SUDO=true .venv/bin/uvicorn bastion.web.app:app --host 127.0.0.1 --port 8009
```

`BASTION_SUDO=true` prefixes commands with `sudo`. Add a NOPASSWD allowlist in
sudoers for the exact commands Bastion runs (`nft`, `fail2ban-client`).

## Settings (configured in-app)

Open **⚙ Settings** in the sidebar. Changes are written to `data/prefs.json` and
take effect immediately.

- **Notifications (ntfy)** — enable alerts, set the ntfy server URL, topic, and an
  optional access token, and tune the ban-spike threshold and window. Use *Send
  test* to verify delivery. A background poller checks fail2ban every 60s and
  pushes one alert when the threshold is crossed within the window.
- **Allowlist (nftables)** — choose the `family` / `table` / `set` that holds your
  trusted IPs. The set must already exist in your nftables config; Bastion only
  adds and removes elements. Manage entries on the **✅ Allowlist** page.
- **Login security** — max failed attempts and the lockout window for per-IP login
  rate limiting.

## Authentication

Set `BASTION_AUTH_PASSWORD` to require a login; the whole dashboard is then gated
behind a single-password sign-in (session stored in an HMAC-signed cookie).
Repeated failures from one IP are locked out (see *Login security* above). Leave
the password empty to run open (dev/demo) — a warning is logged on startup.
`/healthz`, `/login` and static assets stay public.

This is a deliberately minimal gate; keep the app behind HTTPS. A full
multi-user model can be layered on later without changing call sites.

## GeoIP (country flags)

Docker builds automatically download the free **DB-IP IP-to-Country Lite** database
(CC BY 4.0, no account) and set `BASTION_GEOIP_DB`, so country flags work out of the
box. To refresh, rebuild the image. For bare metal:

```bash
scripts/download-geoip.sh /path/to/dbip-country-lite.mmdb
export BASTION_GEOIP_DB=/path/to/dbip-country-lite.mmdb
```

MaxMind GeoLite2-Country works too (same `.mmdb` format). IP geolocation data
© [DB-IP](https://db-ip.com) (CC BY 4.0).

## Demo mode

Set `BASTION_DEMO=true` to serve sample data instead of running commands — handy
for previewing the UI on a machine without the Linux CLIs (e.g. macOS).

## Configuration (environment variables)

Infrastructure knobs only — everything else lives in the Settings page.

| Variable | Default | Description |
|---|---|---|
| `BASTION_AUTH_PASSWORD` | (empty) | Login password; empty = open |
| `BASTION_SUDO` | `false` | Prefix commands with sudo (bare metal) |
| `BASTION_DEMO` | `false` | Serve sample data |
| `BASTION_JAILS` | (auto) | Jails to query, comma-separated |
| `BASTION_GEOIP_DB` | (auto in Docker) | Path to a DB-IP/GeoLite2 `.mmdb` |
| `BASTION_AUTH_LOG` | `/var/log/auth.log` | Auth log path |
| `BASTION_DATA_DIR` | `data` | Where `prefs.json` is stored |

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest httpx
.venv/bin/python -m pytest      # pure logic + fixtures, no live server needed
```

Tests are isolated from any local `.env` (see `tests/conftest.py`).

## License

MIT

---

## 🇰🇷 한국어

단일 자체 호스팅 서버를 위한 가벼운 **fail2ban + nftables 보안 대시보드**입니다.
방화벽 상태 확인, IP 차단/해제, 허용 목록 관리, 공격 급증 시 푸시 알림까지 —
모두 브라우저에서, 하나의 작은 컨테이너로 처리합니다.

### 주요 기능

- **관측** — 차단된 IP(국가 플래그 포함), 자주 공격하는 IP, 열린 포트, 방화벽 규칙
- **관리** — fail2ban 기반 IP 차단/해제, 선택·전체 일괄 차단, nftables 허용 목록 추가/삭제
- **알림** — 차단 급증 시 **ntfy** 푸시(임계값·기간 설정 가능, 테스트 전송 버튼 제공)
- **보안/UX** — 단일 비밀번호 로그인, IP별 로그인 시도 제한(무차별 대입 방어),
  런타임 **설정 페이지**, **영어/한국어** UI

모든 입력은 엄격히 검증되고(`ipaddress` + 이름 허용 목록), 명령은 셸 문자열이 아닌
argv 리스트로 실행되며, 쓰기 작업은 감사 로그에 남습니다. 쓰기 작업은 인증이 필요합니다.

### 설치 — Docker (권장)

```bash
cp .env.example .env       # BASTION_AUTH_PASSWORD 설정 권장
docker compose up -d --build
```

호스트 방화벽을 읽으려면 `network_mode: host` + `cap_add: NET_ADMIN`, 그리고
fail2ban 소켓과 `/var/log` 마운트가 필요합니다(compose 파일에 포함). 설정 페이지의
환경설정은 `bastion_data` 볼륨에 저장되어 재시작 후에도 유지됩니다. 앱은 **:8009**
포트에서 동작합니다.

> **보안**: 관리 도구이므로 절대 인터넷에 직접 노출하지 마세요. Cloudflare Access나
> VPN(wg-easy 등) 뒤에 두세요.

### 설정 페이지

사이드바의 **⚙ 설정**에서 알림(ntfy), 허용 목록 대상 셋, 로그인 시도 제한을 런타임에
바로 변경할 수 있습니다. 변경 사항은 `data/prefs.json`에 저장되며 즉시 적용됩니다.

- **알림(ntfy)**: ntfy 서버 주소·토픽·토큰과 차단 급증 임계값/기간을 설정합니다.
  백그라운드 폴러가 60초마다 fail2ban을 확인해 임계값 초과 시 한 번 알립니다.
- **허용 목록(nftables)**: 신뢰 IP를 담는 `family` / `table` / `set`을 지정합니다.
  셋은 nftables 설정에 이미 존재해야 하며, Bastion은 원소만 추가·삭제합니다.
- **로그인 보안**: 최대 실패 횟수와 잠금 기간을 설정합니다.

### 인증

`BASTION_AUTH_PASSWORD`를 설정하면 전체 대시보드가 단일 비밀번호 로그인으로 보호됩니다
(HMAC 서명 쿠키 세션). 한 IP에서 실패가 반복되면 잠깁니다. 비워두면 개방 모드로
실행되며 시작 시 경고가 로그에 남습니다. `/healthz`, `/login`, 정적 자산은 공개입니다.

### 개발

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest httpx
.venv/bin/python -m pytest
```

라이선스: MIT
