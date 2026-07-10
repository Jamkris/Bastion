"""FastAPI app.

- Home (`/`) is an auto-refreshing overview of four HTMX panels.
- Each category has a full detail page (`/view/*`) with a sortable, filterable table.
- A JSON API is exposed alongside so future clients can reuse the same data.
- A single-password login gate protects everything when BASTION_AUTH_PASSWORD is set.
"""

from __future__ import annotations

import asyncio
import html
import logging
import os
import time
from contextlib import asynccontextmanager
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from bastion import __version__, auth, i18n, prefs
from bastion.config import settings
from bastion.ratelimit import RateLimiter
from bastion.runner import CommandError
from bastion.services import actions, allowlist, dashboard, geoip, ignoreip, notify
from bastion.util import flag_emoji, port_scope

log = logging.getLogger("bastion")

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
templates = Jinja2Templates(directory=_TEMPLATE_DIR)
templates.env.globals["flag"] = flag_emoji
templates.env.globals["scope"] = port_scope

@asynccontextmanager
async def _lifespan(app: FastAPI):
    task = asyncio.create_task(_alert_loop())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="Bastion", version=__version__, lifespan=_lifespan)
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

# Paths reachable without authentication.
_PUBLIC_PATHS = {"/login", "/logout", "/healthz", "/favicon.ico"}

if not settings.auth_password:
    log.warning("BASTION_AUTH_PASSWORD is not set — the dashboard is OPEN (no login).")


# ---------- Ban-spike alerting (background poller) ----------
# Poll fail2ban periodically; when a burst of new bans crosses the configured
# threshold within the window, push one ntfy alert (rate-limited by the window).
POLL_INTERVAL_SEC = 60

_seen_bans: set[tuple[str, str]] = set()
_ban_events: list[float] = []
_last_alert_at = 0.0
_primed = False


def _poll_bans_once(now: float) -> None:
    """One alerting pass. Pure-ish: time is injected so it can be tested."""
    global _seen_bans, _ban_events, _last_alert_at, _primed
    n = prefs.get("notifications")
    if not n["enabled"]:
        return
    data, error = dashboard.banned_ips()
    if error:
        return
    current = {(b.jail, b.ip) for b in (data or [])}

    if not _primed:
        # First pass just records the baseline so we don't alert on IPs that
        # were already banned before the poller started.
        _seen_bans = current
        _primed = True
        return

    new = current - _seen_bans
    _seen_bans = current
    window_sec = n["ban_spike_window_min"] * 60
    _ban_events = notify.prune(_ban_events + [now] * len(new), now, window_sec)

    if (
        new
        and notify.should_alert(_ban_events, n["ban_spike_threshold"])
        and now - _last_alert_at > window_sec
    ):
        count = len(_ban_events)
        sample = ", ".join(ip for _, ip in list(new)[:5])
        notify.send(
            f"Bastion: ban spike ({count})",
            f"{count} IPs banned in the last {n['ban_spike_window_min']} min. "
            f"Newest: {sample}",
            tags="rotating_light",
            priority=n["priority"],
            n=n,
        )
        _last_alert_at = now
        _ban_events = []


async def _alert_loop() -> None:
    while True:
        await asyncio.sleep(POLL_INTERVAL_SEC)
        try:
            _poll_bans_once(time.time())
        except Exception as e:  # never let the loop die
            log.warning("ban-spike poll failed: %s", e)


@app.middleware("http")
async def auth_gate(request: Request, call_next):
    password = settings.auth_password
    path = request.url.path
    if not password or path in _PUBLIC_PATHS or path.startswith("/static/"):
        return await call_next(request)
    if auth.is_authenticated(request.cookies.get(auth.COOKIE_NAME), password):
        return await call_next(request)
    if path.startswith(("/api", "/panel", "/action")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return RedirectResponse("/login", status_code=303)


@app.middleware("http")
async def lang_cookie(request: Request, call_next):
    """Persist `?lang=` as a cookie on any page so the toggle works everywhere."""
    response = await call_next(request)
    lang = request.query_params.get("lang")
    if lang in i18n.SUPPORTED:
        response.set_cookie("lang", lang, max_age=31_536_000, samesite="lax")
    return response


def _lang(request: Request) -> str:
    # Honor `?lang=` for the current render; the cookie persists it (middleware).
    return i18n.normalize(request.query_params.get("lang") or request.cookies.get("lang"))


def _ctx(request: Request, lang: str, active: str = "", **extra) -> dict:
    return {
        "lang": lang,
        "t": i18n.translator(lang),
        "version": __version__,
        "active": active,
        "geoip_active": geoip.is_active(),
        "auth_enabled": bool(settings.auth_password),
        **extra,
    }


# ---------- Auth ----------
# Per-IP brute-force protection for the login form (limits from prefs.security).
_login_limiter = RateLimiter()


def _client_key(request: Request) -> str:
    """Best-effort client IP. Honors the first X-Forwarded-For hop so the limit
    is per real client when Bastion sits behind a reverse proxy / Cloudflare."""
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    lang = _lang(request)
    return templates.TemplateResponse(request, "login.html", _ctx(request, lang, error=""))


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request):
    lang = _lang(request)
    t = i18n.translator(lang)
    sec = prefs.get("security")
    key = _client_key(request)
    now = time.time()
    window = sec["rate_limit_window_min"] * 60

    if _login_limiter.is_locked(key, now, sec["rate_limit_max_attempts"], window):
        return templates.TemplateResponse(
            request, "login.html", _ctx(request, lang, error=t("too_many_attempts")),
            status_code=429,
        )

    form = await request.form()
    if auth.verify_password(form.get("password"), settings.auth_password):
        _login_limiter.clear(key)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            auth.COOKIE_NAME,
            auth.expected_token(settings.auth_password),
            httponly=True,
            samesite="lax",
            max_age=auth.COOKIE_MAX_AGE,
        )
        return response

    _login_limiter.record_failure(key, now)
    return templates.TemplateResponse(
        request, "login.html", _ctx(request, lang, error=t("wrong_password")),
        status_code=401,
    )


@app.get("/logout")
def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(auth.COOKIE_NAME)
    return response


# ---------- Write actions (ban / unban via fail2ban) ----------
@app.post("/action/ban", response_class=HTMLResponse)
async def action_ban(request: Request):
    form = await request.form()
    try:
        actions.ban(form.get("jail", ""), form.get("ip", ""))
        return RedirectResponse("/view/banned", status_code=303)
    except (ValueError, CommandError) as e:
        return RedirectResponse(f"/view/banned?err={quote(str(e))}", status_code=303)


@app.post("/action/ban-bulk")
async def action_ban_bulk(request: Request):
    form = await request.form()
    jail = form.get("jail", "")
    if form.get("scope") == "all":
        data, _ = dashboard.top_attackers()
        ips = [a.ip for a in (data or [])]
    else:
        ips = form.getlist("ip")

    ok = fail = 0
    for ip in ips:
        try:
            actions.ban(jail, ip)
            ok += 1
        except (ValueError, CommandError):
            fail += 1

    # HX-Redirect makes HTMX do a full client-side navigation to the result page.
    return HTMLResponse("", headers={"HX-Redirect": f"/view/attackers?ok={ok}&fail={fail}"})


@app.post("/action/allowlist/add", response_class=HTMLResponse)
async def action_allowlist_add(request: Request):
    form = await request.form()
    try:
        allowlist.add(form.get("ip", ""))
        return RedirectResponse("/view/allowlist", status_code=303)
    except (ValueError, CommandError) as e:
        return RedirectResponse(f"/view/allowlist?err={quote(str(e))}", status_code=303)


@app.post("/action/allowlist/create", response_class=HTMLResponse)
async def action_allowlist_create(request: Request):
    form = await request.form()
    try:
        allowlist.create_set(form.get("set_type", "ipv4_addr"))
        return RedirectResponse("/view/allowlist", status_code=303)
    except (ValueError, CommandError) as e:
        return RedirectResponse(f"/view/allowlist?err={quote(str(e))}", status_code=303)


@app.post("/action/allowlist/remove", response_class=HTMLResponse)
async def action_allowlist_remove(request: Request):
    form = await request.form()
    try:
        allowlist.remove(form.get("ip", ""))
        return HTMLResponse("")  # HTMX removes the row on success
    except (ValueError, CommandError) as e:
        return HTMLResponse(
            f'<tr><td colspan="3" class="err">{html.escape(str(e))}</td></tr>'
        )


@app.post("/action/ignoreip/add", response_class=HTMLResponse)
async def action_ignoreip_add(request: Request):
    form = await request.form()
    try:
        ignoreip.add(form.get("jail", ""), form.get("ip", ""))
        return RedirectResponse("/view/allowlist", status_code=303)
    except (ValueError, CommandError) as e:
        return RedirectResponse(f"/view/allowlist?err={quote(str(e))}", status_code=303)


@app.post("/action/ignoreip/remove", response_class=HTMLResponse)
async def action_ignoreip_remove(request: Request):
    form = await request.form()
    try:
        ignoreip.remove(form.get("jail", ""), form.get("ip", ""))
        return HTMLResponse("")  # HTMX removes the row on success
    except (ValueError, CommandError) as e:
        return HTMLResponse(
            f'<tr><td colspan="3" class="err">{html.escape(str(e))}</td></tr>'
        )


@app.post("/action/unban", response_class=HTMLResponse)
async def action_unban(request: Request):
    form = await request.form()
    try:
        actions.unban(form.get("jail", ""), form.get("ip", ""))
        return HTMLResponse("")  # HTMX removes the row on success
    except (ValueError, CommandError) as e:
        # 200 so HTMX swaps the error row into place.
        return HTMLResponse(
            f'<tr><td colspan="5" class="err">{html.escape(str(e))}</td></tr>'
        )


# ---------- Settings ----------
@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    p = prefs.load()
    return templates.TemplateResponse(
        request, "views/settings.html",
        _ctx(request, _lang(request), active="settings",
             n=p["notifications"], a=p["allowlist"], s=p["security"],
             saved=request.query_params.get("saved"),
             test_result=request.query_params.get("test")),
    )


@app.post("/settings/notifications/test")
async def settings_test_notify(request: Request):
    # Persist the submitted values first, then send a probe with them.
    form = await request.form()
    n = prefs.update("notifications", dict(form))
    ok = notify.send(
        "Bastion test", "Notifications are working.", tags="white_check_mark", n=n
    )
    return RedirectResponse(f"/settings?test={'ok' if ok else 'fail'}", status_code=303)


@app.post("/settings/{section}")
async def settings_save(request: Request, section: str):
    form = await request.form()
    try:
        prefs.update(section, dict(form))
    except ValueError:
        return RedirectResponse("/settings", status_code=303)
    return RedirectResponse(f"/settings?saved={section}", status_code=303)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    # `?lang=` is honored here and persisted as a cookie by the lang middleware.
    return templates.TemplateResponse(
        request, "index.html",
        _ctx(request, _lang(request), active="home", summary=dashboard.summary()),
    )


# ---------- Detail pages (full, sortable + filterable) ----------
@app.get("/view/banned", response_class=HTMLResponse)
def view_banned(request: Request):
    data, error = dashboard.banned_ips()
    summaries, _ = dashboard.jail_summaries()
    jails = [s.name for s in (summaries or [])]
    return templates.TemplateResponse(
        request, "views/banned.html",
        _ctx(request, _lang(request), active="banned", banned=data or [],
             summaries=summaries or [], jails=jails, error=error,
             action_error=request.query_params.get("err", "")),
    )


@app.get("/view/attackers", response_class=HTMLResponse)
def view_attackers(request: Request):
    data, error = dashboard.top_attackers()
    summaries, _ = dashboard.jail_summaries()
    total = sum(a.count for a in (data or [])) or 1
    return templates.TemplateResponse(
        request, "views/attackers.html",
        _ctx(request, _lang(request), active="attackers", attackers=data or [],
             jails=[s.name for s in (summaries or [])], total=total, error=error,
             ok=request.query_params.get("ok"), fail=request.query_params.get("fail")),
    )


@app.get("/view/ports", response_class=HTMLResponse)
def view_ports(request: Request):
    data, error = dashboard.open_ports()
    return templates.TemplateResponse(
        request, "views/ports.html",
        _ctx(request, _lang(request), active="ports", ports=data or [], error=error),
    )


@app.get("/view/allowlist", response_class=HTMLResponse)
def view_allowlist(request: Request):
    cfg = prefs.get("allowlist")
    mode = cfg.get("mode", "ignoreip")
    common = dict(active="allowlist", mode=mode, target=cfg,
                  action_error=request.query_params.get("err", ""))
    if mode == "nftset":
        entries, error = allowlist.list_entries()
        ctx = _ctx(request, _lang(request), entries=entries, error=error,
                   missing=allowlist.set_missing(error), **common)
    else:
        groups, error = ignoreip.list_all()
        jails = [g["jail"] for g in groups]
        ctx = _ctx(request, _lang(request), groups=groups, jails=jails, error=error, **common)
    return templates.TemplateResponse(request, "views/allowlist.html", ctx)


@app.get("/view/firewall", response_class=HTMLResponse)
def view_firewall(request: Request):
    data, error = dashboard.firewall_ruleset()
    return templates.TemplateResponse(
        request, "views/firewall.html",
        _ctx(request, _lang(request), active="firewall", ruleset=data, error=error),
    )


# ---------- HTMX partials (home overview) ----------
@app.get("/panel/banned", response_class=HTMLResponse)
def panel_banned(request: Request):
    data, error = dashboard.banned_ips()
    summaries, _ = dashboard.jail_summaries()
    return templates.TemplateResponse(
        request, "partials/banned.html",
        _ctx(request, _lang(request), banned=data or [], summaries=summaries or [], error=error),
    )


@app.get("/panel/ports", response_class=HTMLResponse)
def panel_ports(request: Request):
    data, error = dashboard.open_ports()
    return templates.TemplateResponse(
        request, "partials/ports.html", _ctx(request, _lang(request), ports=data or [], error=error)
    )


@app.get("/panel/attackers", response_class=HTMLResponse)
def panel_attackers(request: Request):
    data, error = dashboard.top_attackers()
    return templates.TemplateResponse(
        request, "partials/attackers.html",
        _ctx(request, _lang(request), attackers=data or [], error=error),
    )


@app.get("/panel/firewall", response_class=HTMLResponse)
def panel_firewall(request: Request):
    data, error = dashboard.firewall_ruleset()
    return templates.TemplateResponse(
        request, "partials/firewall.html", _ctx(request, _lang(request), ruleset=data, error=error)
    )


# ---------- JSON API (for future clients) ----------
@app.get("/api/banned")
def api_banned():
    data, error = dashboard.banned_ips()
    return {"data": [b.__dict__ for b in (data or [])], "error": error}


@app.get("/api/ports")
def api_ports():
    data, error = dashboard.open_ports()
    return {"data": [p.__dict__ for p in (data or [])], "error": error}


@app.get("/api/attackers")
def api_attackers():
    data, error = dashboard.top_attackers()
    return {"data": [a.__dict__ for a in (data or [])], "error": error}


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(os.path.join(_STATIC_DIR, "favicon.svg"), media_type="image/svg+xml")


@app.get("/healthz")
def healthz():
    return {"status": "ok", "version": __version__, "geoip": geoip.is_active()}
