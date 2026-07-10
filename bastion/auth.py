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
USER_COOKIE = "bastion_user"
COOKIE_MAX_AGE = 60 * 60 * 24 * 7  # 7 days


def expected_token(password: str) -> str:
    return hmac.new(password.encode(), b"bastion-session", hashlib.sha256).hexdigest()


def verify_password(candidate: str | None, password: str) -> bool:
    return bool(password) and hmac.compare_digest(candidate or "", password)


def is_authenticated(cookie_value: str | None, password: str) -> bool:
    if not password:  # auth disabled
        return True
    return bool(cookie_value) and hmac.compare_digest(cookie_value, expected_token(password))


def sign_session(username: str, secret: str) -> str:
    """Return a `username.signature` session token for multi-user mode."""
    sig = hmac.new(secret.encode(), username.encode(), hashlib.sha256).hexdigest()
    return f"{username}.{sig}"


def verify_session(cookie_value: str | None, secret: str) -> str | None:
    """Return the username if the session token is valid, else None."""
    if not cookie_value or "." not in cookie_value:
        return None
    username, _, sig = cookie_value.rpartition(".")
    if not username:
        return None
    expected = hmac.new(secret.encode(), username.encode(), hashlib.sha256).hexdigest()
    return username if hmac.compare_digest(sig, expected) else None


def decode_basic(auth_header: str | None) -> tuple[str, str] | None:
    """Return (username, password) from an HTTP Basic header, or None."""
    if not auth_header:
        return None
    scheme, _, encoded = auth_header.partition(" ")
    if scheme.lower() != "basic" or not encoded:
        return None
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    username, sep, password = decoded.partition(":")
    return (username, password) if sep else None


def verify_basic(auth_header: str | None, password: str) -> bool:
    """Accept HTTP Basic auth where the password half matches. The username is
    ignored. Lets header-only API clients (dashboards, scripts) reach the JSON
    API without the cookie login flow. Returns False when no password is set."""
    if not password:
        return False
    creds = decode_basic(auth_header)
    return creds is not None and hmac.compare_digest(creds[1], password)
