"""Simple single-password login gate.

Pure helpers (password passed in) so they are trivially testable. The web layer
wires them to `settings.auth_password`. When no password is configured, auth is
disabled and every request passes.

The session cookie is an HMAC of the password — an attacker cannot forge it
without knowing the password. This is a minimal gate; a real user/session model
can replace it later without changing call sites much.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac

COOKIE_NAME = "bastion_auth"
COOKIE_MAX_AGE = 60 * 60 * 24 * 7  # 7 days


def expected_token(password: str) -> str:
    return hmac.new(password.encode(), b"bastion-session", hashlib.sha256).hexdigest()


def verify_password(candidate: str | None, password: str) -> bool:
    return bool(password) and hmac.compare_digest(candidate or "", password)


def is_authenticated(cookie_value: str | None, password: str) -> bool:
    if not password:  # auth disabled
        return True
    return bool(cookie_value) and hmac.compare_digest(cookie_value, expected_token(password))


def verify_basic(auth_header: str | None, password: str) -> bool:
    """Accept HTTP Basic auth where the password half matches. The username is
    ignored. Lets header-only API clients (dashboards, scripts) reach the JSON
    API without the cookie login flow. Returns False when no password is set."""
    if not password or not auth_header:
        return False
    scheme, _, encoded = auth_header.partition(" ")
    if scheme.lower() != "basic" or not encoded:
        return False
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    _, sep, candidate = decoded.partition(":")
    return bool(sep) and hmac.compare_digest(candidate, password)
