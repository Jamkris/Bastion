"""Simple single-password login gate.

Pure helpers (password passed in) so they are trivially testable. The web layer
wires them to `settings.auth_password`. When no password is configured, auth is
disabled and every request passes.

The session cookie is an HMAC of the password — an attacker cannot forge it
without knowing the password. This is a minimal gate; a real user/session model
can replace it later without changing call sites much.
"""

from __future__ import annotations

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
