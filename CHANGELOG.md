# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-07-10

### Added
- **Settings page** (standalone) with a top-right profile dropdown (Settings /
  Logout). Configure language, notifications, allowlist, and login security at
  runtime — no redeploy needed. Preferences persist to `data/prefs.json`.
- **ntfy notifications** on a ban spike, with a configurable threshold/window,
  a background poller, and a one-click *Send test* button.
- **Allowlist** management with two modes:
  - fail2ban `ignoreip` (default) — works with any firewall backend.
  - nftables set — with a first-run setup guide and *Create set* button.
- **Login rate limiting** per client IP (brute-force protection).
- **JSON stats endpoint** `GET /api/stats` and **HTTP Basic auth** for the API,
  for dashboard widgets (e.g. Homepage `customapi`).
- Shield **favicon** and static asset serving.
- **Responsive layout** for mobile (sidebar, header, tables, settings, login).

### Changed
- Settings moved out of the sidebar into the profile dropdown.

## [1.0.0] - 2026-07-08

### Added
- Read-only dashboard: banned IPs, top attackers, open ports, firewall rules.
- Sortable/filterable detail pages and a home overview with live refresh (HTMX).
- Real GeoIP country flags via the free DB-IP database.
- English / Korean i18n.
- Single-password login gate (HMAC session cookie).
- Ban / unban actions via `fail2ban-client`, including bulk ban, with
  SweetAlert2 confirmations.

[1.1.0]: https://github.com/Jamkris/Bastion/releases/tag/v1.1.0
[1.0.0]: https://github.com/Jamkris/Bastion/releases/tag/v1.0.0
