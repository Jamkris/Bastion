import pytest

from bastion.runner import CommandError, run


def test_missing_binary_raises_commanderror():
    # A non-existent binary must surface as CommandError, not FileNotFoundError,
    # so every caller can handle it uniformly.
    with pytest.raises(CommandError):
        run(["definitely-not-a-real-binary-xyzzy"])
