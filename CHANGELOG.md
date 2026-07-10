# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-10

Initial public release.

### Observability
- Dashboard for banned IPs, top attackers, open ports, and firewall rules.
- Sortable/filterable detail pages and a home overview with live refresh (HTMX).
- Real GeoIP country flags via the free DB-IP database.

### Management
- Ban / unban via `fail2ban-client`, including bulk ban, with SweetAlert2 confirms.
- Allowlist with two modes: fail2ban `ignoreip` (default, any firewall) and a
  dedicated nftables set (with a first-run setup guide + *Create set* button).

### Alerting
- ntfy push notifications on a ban spike (configurable threshold/window),
  a background poller, and a *Send test* button.

### Security & UX
- Single-password login gate (HMAC session cookie) with per-IP rate limiting.
- Standalone Settings page + profile dropdown to configure language,
  notifications, allowlist, and login security at runtime.
- English / Korean i18n; responsive layout for mobile.
- JSON stats endpoint `GET /api/stats` and HTTP Basic auth for dashboard widgets.

[1.0.0]: https://github.com/Jamkris/Bastion/releases/tag/v1.0.0
