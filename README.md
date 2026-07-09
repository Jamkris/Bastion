# 🛡 Bastion

A lightweight **fail2ban + nftables observability dashboard** for a single self-hosted server. See your firewall state in the browser — no heavy, cloud-dependent tooling, just one container.

## Features (v1.0 — read-only)

- **Banned IPs** — per-jail fail2ban ban list + country (GeoIP)
- **Top attackers** — failed-login aggregation from auth.log / journald
- **Open ports** — listening ports from `ss -tlnp` with owning process
- **Firewall rules** — chains, rules and sets from `nft -j list ruleset` (nftables)
- Client-side search/filter on every panel; live 30s refresh via HTMX

### Actions (v2)

The Banned IPs page can **ban** an IP (jail + IP form) and **unban** any banned IP
(per-row button). Actions go through `fail2ban-client` over the same socket used for
reading, so no extra privilege is needed under Docker. Inputs are strictly validated
(`ipaddress` + jail allowlist), commands run as argv lists (never a shell string), and
every action is audit-logged. Requires authentication.

Planned next: nftables-level allowlist management and ntfy alerts.

## Architecture

```
collectors/  run commands -> raw text     (fail2ban-client, nft, ss, auth.log)
services/    raw -> parse -> dataclass     (pure functions, fully tested)
web/         FastAPI + HTMX / JSON API
```

All logic lives in `services/`, so the CLI, API and HTMX layers reuse the same code.

## Install — Docker (recommended)

```bash
cp .env.example .env       # edit if needed
docker compose up -d --build
```

Reading the host firewall requires `network_mode: host` + `cap_add: NET_ADMIN` plus mounts for the fail2ban socket and `/var/log` (included in the compose file). The app listens on `:8009`.

> **Security**: this is an admin tool — never expose it to the internet. Put it behind Cloudflare Access or a VPN (wg-easy).

## Install — systemd (bare metal)

The same code runs without a container.

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
BASTION_SUDO=true .venv/bin/uvicorn bastion.web.app:app --host 127.0.0.1 --port 8009
```

`BASTION_SUDO=true` prefixes commands with `sudo`. Add a NOPASSWD allowlist in sudoers:

```
bastion ALL=(root) NOPASSWD: /usr/sbin/nft -j list ruleset, /usr/bin/fail2ban-client status *
```

## Authentication

Set `BASTION_AUTH_PASSWORD` to require a login; the whole dashboard is then gated
behind a single-password sign-in (session stored in an HMAC-signed cookie). Leave
it empty to run open (dev/demo) — a warning is logged on startup. `/healthz` stays
public for monitoring.

This is a minimal gate; keep the app behind HTTPS (Cloudflare Access / VPN). A full
user/session model can be added later on top of this.

## GeoIP (country flags)

Docker builds automatically download the free **DB-IP IP-to-Country Lite** database
(CC BY 4.0, no account required) and set `BASTION_GEOIP_DB`, so country flags work
out of the box. To refresh it, rebuild the image (`docker compose build --no-cache`)
or mount your own database and point `BASTION_GEOIP_DB` at it.

For bare metal, download it once and set the env var:

```bash
scripts/download-geoip.sh /path/to/dbip-country-lite.mmdb
export BASTION_GEOIP_DB=/path/to/dbip-country-lite.mmdb
```

MaxMind GeoLite2-Country works too — it uses the same `.mmdb` format; just point
`BASTION_GEOIP_DB` at it. IP geolocation data © [DB-IP](https://db-ip.com) (CC BY 4.0).

## Demo mode

Set `BASTION_DEMO=true` to serve sample data instead of running commands — useful for previewing the UI on a machine without the Linux CLIs (e.g. macOS) and for a public demo.

```bash
BASTION_DEMO=true .venv/bin/uvicorn bastion.web.app:app --reload --port 8009
```

## Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `BASTION_AUTH_PASSWORD` | (empty) | Login password; empty = open |
| `BASTION_SUDO` | `false` | Prefix commands with sudo |
| `BASTION_DEMO` | `false` | Serve sample data |
| `BASTION_JAILS` | (auto) | Jails to query, comma-separated |
| `BASTION_GEOIP_DB` | (auto in Docker) | Path to a DB-IP/GeoLite2 .mmdb |
| `BASTION_AUTH_LOG` | `/var/log/auth.log` | Auth log path |

## Internationalization

English is the default UI language; Korean is available. Switch with the `EN`/`KO` toggle in the header (persisted via cookie).

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest httpx
.venv/bin/python -m pytest      # parser tests run against fixtures, no live server
```

## License

MIT
