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
