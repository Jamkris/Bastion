from bastion.ratelimit import RateLimiter, count_within


def test_count_within_window():
    assert count_within([900, 950, 999], now=1000, window_sec=60) == 2


def test_not_locked_below_threshold():
    rl = RateLimiter()
    rl.record_failure("1.2.3.4", now=100)
    rl.record_failure("1.2.3.4", now=101)
    assert rl.is_locked("1.2.3.4", now=102, max_attempts=3, window_sec=900) is False


def test_locked_at_threshold():
    rl = RateLimiter()
    for i in range(3):
        rl.record_failure("1.2.3.4", now=100 + i)
    assert rl.is_locked("1.2.3.4", now=103, max_attempts=3, window_sec=900) is True


def test_old_failures_expire():
    rl = RateLimiter()
    for i in range(5):
        rl.record_failure("1.2.3.4", now=100 + i)
    # Far in the future -> all failures fell out of the window.
    assert rl.is_locked("1.2.3.4", now=100_000, max_attempts=3, window_sec=900) is False


def test_clear_resets_key():
    rl = RateLimiter()
    for i in range(5):
        rl.record_failure("1.2.3.4", now=100 + i)
    rl.clear("1.2.3.4")
    assert rl.is_locked("1.2.3.4", now=110, max_attempts=3, window_sec=900) is False


def test_keys_are_independent():
    rl = RateLimiter()
    for i in range(3):
        rl.record_failure("1.1.1.1", now=100 + i)
    assert rl.is_locked("1.1.1.1", now=103, max_attempts=3, window_sec=900) is True
    assert rl.is_locked("2.2.2.2", now=103, max_attempts=3, window_sec=900) is False
