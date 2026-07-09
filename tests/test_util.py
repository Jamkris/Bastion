from bastion.util import flag_emoji, port_scope


def test_flag_emoji_valid():
    assert flag_emoji("KR") == "🇰🇷"
    assert flag_emoji("us") == "🇺🇸"


def test_flag_emoji_invalid():
    assert flag_emoji(None) == ""
    assert flag_emoji("") == ""
    assert flag_emoji("USA") == ""
    assert flag_emoji("1A") == ""


def test_port_scope():
    assert port_scope("0.0.0.0") == "any"
    assert port_scope("*") == "any"
    assert port_scope("[::]") == "ipv6"
    assert port_scope("127.0.0.1") == "local"
    assert port_scope("192.168.45.16") == "specific"
