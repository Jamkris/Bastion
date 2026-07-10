from types import SimpleNamespace

from bastion.services import jaillocal

BASE = """[DEFAULT]
bantime = 1h
ignoreip = 127.0.0.1/8 ::1 192.168.45.0/24

[sshd]
enabled = true
"""


def test_parse_entries():
    assert jaillocal.parse_entries(BASE) == ["127.0.0.1/8", "::1", "192.168.45.0/24"]


def test_add_appends_new_ip():
    out = jaillocal.add_ip(BASE, "203.0.113.7")
    assert jaillocal.parse_entries(out) == [
        "127.0.0.1/8", "::1", "192.168.45.0/24", "203.0.113.7",
    ]
    # Other content is untouched.
    assert "[sshd]" in out and "bantime = 1h" in out


def test_add_is_idempotent():
    out = jaillocal.add_ip(BASE, "192.168.45.0/24")
    assert out == BASE


def test_remove_existing():
    out = jaillocal.remove_ip(BASE, "::1")
    assert jaillocal.parse_entries(out) == ["127.0.0.1/8", "192.168.45.0/24"]


def test_remove_absent_is_noop():
    assert jaillocal.remove_ip(BASE, "8.8.8.8") == BASE


def test_add_when_no_ignoreip_line_inserts_one():
    content = "[DEFAULT]\nbantime = 1h\n\n[sshd]\nenabled = true\n"
    out = jaillocal.add_ip(content, "10.0.0.1")
    assert jaillocal.parse_entries(out) == ["10.0.0.1"]
    assert "bantime = 1h" in out and "[sshd]" in out


def test_add_when_no_default_section_creates_one():
    content = "[sshd]\nenabled = true\n"
    out = jaillocal.add_ip(content, "10.0.0.1")
    assert jaillocal.parse_entries(out) == ["10.0.0.1"]
    assert "[sshd]" in out


def test_commented_ignoreip_is_ignored():
    content = "[DEFAULT]\n#ignoreip = 1.1.1.1\nbantime = 1h\n"
    # No active ignoreip -> parse empty, add inserts a real one.
    assert jaillocal.parse_entries(content) == []
    out = jaillocal.add_ip(content, "2.2.2.2")
    assert jaillocal.parse_entries(out) == ["2.2.2.2"]
    assert "#ignoreip = 1.1.1.1" in out  # comment preserved


def test_preserves_trailing_newline_absence():
    content = "[DEFAULT]\nignoreip = 1.1.1.1"  # no trailing newline
    out = jaillocal.add_ip(content, "2.2.2.2")
    assert not out.endswith("\n")
    assert jaillocal.parse_entries(out) == ["1.1.1.1", "2.2.2.2"]


def test_remove_leaves_empty_line_when_last_removed():
    content = "[DEFAULT]\nignoreip = 1.1.1.1\n"
    out = jaillocal.remove_ip(content, "1.1.1.1")
    assert jaillocal.parse_entries(out) == []
    assert "ignoreip =" in out  # line kept, just empty


# ---------- IO ----------
def test_persist_add_writes_file(tmp_path, monkeypatch):
    f = tmp_path / "jail.local"
    f.write_text(BASE, encoding="utf-8")
    monkeypatch.setattr(jaillocal, "settings", SimpleNamespace(jail_local=str(f)))
    assert jaillocal.is_writable() is True
    assert jaillocal.persist_add("203.0.113.7") is True
    assert "203.0.113.7" in jaillocal.parse_entries(f.read_text(encoding="utf-8"))


def test_persist_missing_file_returns_false(tmp_path, monkeypatch):
    monkeypatch.setattr(
        jaillocal, "settings", SimpleNamespace(jail_local=str(tmp_path / "nope.local"))
    )
    assert jaillocal.is_writable() is False
    assert jaillocal.persist_add("1.2.3.4") is False  # best-effort, no raise
