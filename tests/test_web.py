from fastapi.testclient import TestClient

from bastion.web.app import app


def test_lang_toggle_on_detail_page():
    # `?lang=ko` on a non-home page must render Korean and persist the cookie.
    c = TestClient(app)
    r = c.get("/view/banned?lang=ko")
    assert "차단된 IP" in r.text
    assert "lang=ko" in r.headers.get("set-cookie", "")


def test_lang_persists_via_cookie_across_pages():
    c = TestClient(app)
    c.get("/view/banned?lang=ko")  # sets the cookie
    r = c.get("/view/ports")       # no query param -> should read the cookie
    assert "열린 포트" in r.text


def test_lang_switch_back_to_english():
    c = TestClient(app)
    c.get("/view/banned?lang=ko")
    r = c.get("/view/banned?lang=en")
    assert "Banned IPs" in r.text
    assert "lang=en" in r.headers.get("set-cookie", "")


def test_healthz_public():
    c = TestClient(app)
    assert c.get("/healthz").status_code == 200


def test_favicon_served():
    c = TestClient(app)
    r = c.get("/favicon.ico")
    assert r.status_code == 200
    assert "svg" in r.headers.get("content-type", "")


def test_static_favicon_served():
    c = TestClient(app)
    r = c.get("/static/favicon.svg")
    assert r.status_code == 200
    assert "<svg" in r.text


def test_settings_page_renders_sections():
    c = TestClient(app)
    r = c.get("/settings")
    assert r.status_code == 200
    assert "Notifications (ntfy)" in r.text
    assert "Allowlist (nftables)" in r.text
    assert "Login security" in r.text


def test_settings_page_korean():
    c = TestClient(app)
    r = c.get("/settings?lang=ko")
    assert "알림 (ntfy)" in r.text
