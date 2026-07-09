import os

import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def fixture():
    def _load(name: str) -> str:
        with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as f:
            return f.read()

    return _load
