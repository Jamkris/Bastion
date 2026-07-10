import pytest
from fastapi.testclient import TestClient

from bastion.ratelimit import RateLimiter
from bastion.web import app as webapp
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


def test_api_stats_returns_flat_counters():
    c = TestClient(app)
    r = c.get("/api/stats")
    assert r.status_code == 200
    body = r.json()
    for key in ("total_banned", "attackers", "open_ports", "jail_count"):
        assert key in body
        assert isinstance(body[key], int)


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


def test_settings_has_language_section():
    c = TestClient(app)
    r = c.get("/settings")
    assert "English" in r.text and "한국어" in r.text
    assert 'href="/settings?lang=ko"' in r.text


def test_settings_is_standalone_page():
    # The settings screen is its own document, not the sidebar app shell.
    c = TestClient(app)
    r = c.get("/settings")
    assert "<!doctype html>" in r.text.lower()
    assert 'class="sidebar"' not in r.text


def test_api_history_returns_points_list():
    c = TestClient(app)
    r = c.get("/api/history?limit=10")
    assert r.status_code == 200
    assert isinstance(r.json().get("points"), list)


def test_home_renders_with_sparkline_context(monkeypatch):
    # With history present, the home page includes an SVG sparkline.
    monkeypatch.setattr(
        webapp.history, "load",
        lambda limit=None: [{"t": 1, "banned": 1, "attackers": 2, "ports": 3},
                            {"t": 2, "banned": 4, "attackers": 5, "ports": 3}],
    )
    c = TestClient(app)
    r = c.get("/")
    assert r.status_code == 200
    assert '<svg class="spark"' in r.text


@pytest.fixture
def one_user(monkeypatch):
    from bastion import users as u
    monkeypatch.setattr(webapp, "_login_limiter", RateLimiter())
    u.add("alice", "pw12345")
    yield ("alice", "pw12345")
    u.remove("alice")


def test_multiuser_requires_login(one_user):
    c = TestClient(app)
    r = c.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_multiuser_login_page_has_username_field(one_user):
    c = TestClient(app)
    assert 'name="username"' in c.get("/login").text


def test_multiuser_login_success_grants_access(one_user):
    user, pw = one_user
    c = TestClient(app)
    r = c.post("/login", data={"username": user, "password": pw}, follow_redirects=False)
    assert r.status_code == 303
    assert "bastion_user" in r.headers.get("set-cookie", "")
    assert c.get("/", follow_redirects=False).status_code == 200


def test_multiuser_wrong_password_401(one_user):
    user, _ = one_user
    c = TestClient(app)
    r = c.post("/login", data={"username": user, "password": "nope"}, follow_redirects=False)
    assert r.status_code == 401


def test_multiuser_api_basic_auth(one_user):
    user, pw = one_user
    c = TestClient(app)
    assert c.get("/api/stats", follow_redirects=False).status_code == 401
    assert c.get("/api/stats", auth=(user, pw)).status_code == 200


def test_firewall_grouped_view(monkeypatch):
    from bastion.models import FirewallRule, FirewallRuleset

    rs = FirewallRuleset(
        chains=(),
        rules=(
            FirewallRule("ip", "filter", "INPUT", 1, '[{"accept": null}]'),
            FirewallRule("ip", "nat", "POSTROUTING", 2, '[{"masquerade": null}]'),
        ),
        sets=(),
    )
    monkeypatch.setattr(webapp.dashboard, "firewall_ruleset", lambda: (rs, None))
    c = TestClient(app)
    r = c.get("/view/firewall")
    assert r.status_code == 200
    assert 'class="fw-table"' in r.text
    assert "ip filter" in r.text and "ip nat" in r.text
    assert "accept" in r.text  # rendered readable expression


def test_dashboard_has_profile_menu():
    c = TestClient(app)
    r = c.get("/")
    assert r.status_code == 200
    assert 'id="profileBtn"' in r.text
    assert 'href="/settings"' in r.text
    # Settings was removed from the sidebar nav (now in the profile dropdown).
    assert '<span class="ico">⚙</span>' in r.text  # present only in the dropdown


def test_login_locks_out_after_repeated_failures(monkeypatch):
    monkeypatch.setattr(webapp, "_login_limiter", RateLimiter())
    monkeypatch.setattr(
        webapp.prefs, "get",
        lambda section: {"rate_limit_max_attempts": 3, "rate_limit_window_min": 15},
    )
    c = TestClient(app)
    for _ in range(3):
        assert c.post("/login", data={"password": "wrong"}).status_code == 401
    # Fourth attempt within the window is locked out.
    r = c.post("/login", data={"password": "wrong"})
    assert r.status_code == 429
    assert "Too many attempts" in r.text


def test_allowlist_ignoreip_mode_default():
    # Default mode is fail2ban ignoreip; the page renders even without fail2ban.
    c = TestClient(app)
    r = c.get("/view/allowlist")
    assert r.status_code == 200
    assert "Allowlist" in r.text
    assert "fail2ban ignoreip" in r.text


def test_allowlist_nftset_mode_shows_setup(monkeypatch):
    # In nftset mode, a "set not found" error must render the create-set setup
    # guide. Force both prefs and the lookup so the test does not depend on
    # whether/how `nft` fails in the CI environment.
    monkeypatch.setattr(
        webapp.prefs, "get",
        lambda section: {"mode": "nftset", "family": "inet", "table": "filter", "set": "bastion_allow"},
    )
    monkeypatch.setattr(
        webapp.allowlist, "list_entries",
        lambda: ([], "Error: No such file or directory"),
    )
    c = TestClient(app)
    r = c.get("/view/allowlist")
    assert r.status_code == 200
    assert 'action="/action/allowlist/create"' in r.text
