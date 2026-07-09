from bastion.auth import expected_token, is_authenticated, verify_password


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
