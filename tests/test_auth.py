import base64

from bastion.auth import expected_token, is_authenticated, verify_basic, verify_password


def _basic(user, pw):
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()


def test_token_is_deterministic_and_password_specific():
    assert expected_token("secret") == expected_token("secret")
    assert expected_token("secret") != expected_token("other")


def test_verify_password():
    assert verify_password("secret", "secret") is True
    assert verify_password("wrong", "secret") is False
    assert verify_password("", "secret") is False
    assert verify_password(None, "secret") is False
    # No password configured -> nothing verifies.
    assert verify_password("anything", "") is False


def test_is_authenticated_when_enabled():
    pw = "secret"
    good = expected_token(pw)
    assert is_authenticated(good, pw) is True
    assert is_authenticated("forged", pw) is False
    assert is_authenticated(None, pw) is False


def test_is_authenticated_when_disabled():
    # Empty password -> auth disabled -> everything passes.
    assert is_authenticated(None, "") is True
    assert is_authenticated("whatever", "") is True


def test_verify_basic_matches_password_ignoring_username():
    assert verify_basic(_basic("homepage", "secret"), "secret") is True
    assert verify_basic(_basic("anyone", "secret"), "secret") is True


def test_verify_basic_rejects_wrong_password():
    assert verify_basic(_basic("u", "nope"), "secret") is False


def test_verify_basic_rejects_password_with_colon_still_works():
    # Password may itself contain a colon; only the first colon splits user:pass.
    assert verify_basic(_basic("u", "a:b:c"), "a:b:c") is True


def test_verify_basic_rejects_malformed_or_missing():
    assert verify_basic(None, "secret") is False
    assert verify_basic("Bearer token", "secret") is False
    assert verify_basic("Basic !!!notbase64", "secret") is False
    assert verify_basic(_basic("u", "secret"), "") is False  # no password configured
