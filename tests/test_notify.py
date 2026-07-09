from bastion.services import notify


def test_prune_drops_events_outside_window():
    now = 1000.0
    events = [900.0, 950.0, 999.0]  # ages: 100s, 50s, 1s
    kept = notify.prune(events, now, window_sec=60)
    assert kept == [950.0, 999.0]


def test_should_alert_threshold():
    assert notify.should_alert([1, 2, 3], threshold=3) is True
    assert notify.should_alert([1, 2], threshold=3) is False


def test_should_alert_treats_zero_threshold_as_one():
    assert notify.should_alert([], threshold=0) is False
    assert notify.should_alert([1], threshold=0) is True


def test_send_returns_false_when_unconfigured():
    # No topic -> no network call, no exception, just False.
    assert notify.send("t", "m", n={"ntfy_url": "https://ntfy.sh", "ntfy_topic": ""}) is False
    assert notify.send("t", "m", n={"ntfy_url": "", "ntfy_topic": "x"}) is False


def test_send_swallows_network_errors():
    # Unroutable host must not raise; send returns False.
    n = {"ntfy_url": "http://127.0.0.1:1", "ntfy_topic": "bastion"}
    assert notify.send("t", "m", n=n) is False
