"""FastAPI app. HTMX loads/refreshes each panel; a JSON API is exposed
alongside so future clients can reuse the same data."""

from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from bastion import __version__, i18n
from bastion.services import dashboard

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=_TEMPLATE_DIR)

app = FastAPI(title="Bastion", version=__version__)


def _lang(request: Request) -> str:
    return i18n.normalize(request.cookies.get("lang", i18n.DEFAULT))


def _ctx(request: Request, lang: str, **extra) -> dict:
    return {"request": request, "lang": lang, "t": i18n.translator(lang), **extra}


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    # `?lang=` switches and is persisted as a cookie; panels inherit it.
    lang = i18n.normalize(request.query_params.get("lang") or request.cookies.get("lang"))
    response = templates.TemplateResponse(
        "index.html", _ctx(request, lang, version=__version__)
    )
    response.set_cookie("lang", lang, max_age=31_536_000, samesite="lax")
    return response


# ---------- HTMX partials ----------
@app.get("/panel/banned", response_class=HTMLResponse)
def panel_banned(request: Request):
    data, error = dashboard.banned_ips()
    summaries, _ = dashboard.jail_summaries()
    return templates.TemplateResponse(
        "partials/banned.html",
        _ctx(request, _lang(request), banned=data or [], summaries=summaries or [], error=error),
    )


@app.get("/panel/ports", response_class=HTMLResponse)
def panel_ports(request: Request):
    data, error = dashboard.open_ports()
    return templates.TemplateResponse(
        "partials/ports.html", _ctx(request, _lang(request), ports=data or [], error=error)
    )


@app.get("/panel/attackers", response_class=HTMLResponse)
def panel_attackers(request: Request):
    data, error = dashboard.top_attackers()
    return templates.TemplateResponse(
        "partials/attackers.html", _ctx(request, _lang(request), attackers=data or [], error=error)
    )


@app.get("/panel/firewall", response_class=HTMLResponse)
def panel_firewall(request: Request):
    data, error = dashboard.firewall_ruleset()
    return templates.TemplateResponse(
        "partials/firewall.html", _ctx(request, _lang(request), ruleset=data, error=error)
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


@app.get("/healthz")
def healthz():
    return {"status": "ok", "version": __version__}
