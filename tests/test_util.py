from bastion.util import flag_emoji, port_scope, sparkline_points


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


def test_sparkline_empty():
    assert sparkline_points([]) == ""


def test_sparkline_single_value_is_two_points():
    pts = sparkline_points([5]).split()
    assert len(pts) == 2


def test_sparkline_maps_extremes_within_bounds():
    pts = sparkline_points([0, 10], width=100, height=20, pad=2)
    coords = [tuple(map(float, p.split(","))) for p in pts.split()]
    xs = [x for x, _ in coords]
    ys = [y for _, y in coords]
    # X spans the padded width; Y stays within the padded box.
    assert xs[0] == 2.0 and xs[-1] == 98.0
    assert min(ys) >= 2.0 and max(ys) <= 18.0
    # Higher value sits higher on screen (smaller y).
    assert ys[1] < ys[0]


def test_sparkline_flat_series_sits_at_mid():
    pts = sparkline_points([4, 4, 4], height=20)
    ys = {float(p.split(",")[1]) for p in pts.split()}
    assert ys == {10.0}
