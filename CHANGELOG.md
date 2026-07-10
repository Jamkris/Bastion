# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Allowlist: **Persist to jail.local** option (ignoreip mode) — writes changes to
  the `[DEFAULT] ignoreip` line so they survive a fail2ban restart.
- Notifications: alert on **new attacker IPs** and on **open-port changes**, each
  independently toggleable in Settings (in addition to ban-spike alerts).
- Home **trend sparklines** for banned IPs and attackers, backed by a capped
  time-series recorded by the poller. New `GET /api/history` endpoint.
- **Multi-user login** — named accounts with PBKDF2-hashed passwords, managed in
  Settings → Users, with signed session cookies. Falls back to the single shared
  password when no users exist; HTTP Basic auth works with user credentials.

### Changed
- Firewall page now renders rules in **readable nft syntax** (e.g. `tcp dport 22
  accept`) instead of raw JSON; the original JSON is available on hover.
- Firewall rules are **grouped by table → chain** in collapsible sections, with a
  filter that auto-opens matching groups (much easier on large rulesets).

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
