from types import SimpleNamespace

import pytest

from bastion import users


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(users, "settings", SimpleNamespace(data_dir=str(tmp_path)))
    return tmp_path


# ---------- pure hashing ----------
def test_hash_is_deterministic_with_fixed_salt():
    salt = "00" * 16
    assert users.hash_password("pw", salt=salt) == users.hash_password("pw", salt=salt)


def test_hash_differs_by_salt():
    assert users.hash_password("pw", salt="00" * 16) != users.hash_password("pw", salt="11" * 16)


def test_verify_hash_roundtrip():
    stored = users.hash_password("secret", salt="ab" * 16)
    assert users.verify_hash("secret", stored) is True
    assert users.verify_hash("wrong", stored) is False


def test_verify_hash_rejects_malformed():
    assert users.verify_hash("x", "not-a-hash") is False
    assert users.verify_hash("x", "") is False


# ---------- store ----------
def test_add_and_verify(store):
    users.add("alice", "hunter2")
    assert users.verify("alice", "hunter2") is True
    assert users.verify("alice", "nope") is False
    assert users.count() == 1
    assert users.exists("alice")


def test_stored_password_is_hashed_not_plaintext(store):
    users.add("bob", "plaintext-pw")
    raw = (store / "users.json").read_text(encoding="utf-8")
    assert "plaintext-pw" not in raw
    assert "pbkdf2_sha256$" in raw


def test_set_password(store):
    users.add("carol", "old")
    users.set_password("carol", "new")
    assert users.verify("carol", "old") is False
    assert users.verify("carol", "new") is True


def test_set_password_unknown_user_raises(store):
    with pytest.raises(ValueError):
        users.set_password("ghost", "x")


def test_remove(store):
    users.add("dave", "pw")
    users.remove("dave")
    assert users.exists("dave") is False


def test_add_rejects_invalid_username(store):
    with pytest.raises(ValueError):
        users.add("bad name!", "pw")


def test_add_rejects_empty_password(store):
    with pytest.raises(ValueError):
        users.add("eve", "")


def test_usernames_sorted(store):
    users.add("zoe", "pw")
    users.add("amy", "pw")
    assert users.usernames() == ["amy", "zoe"]
