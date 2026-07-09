import os

# Isolate the suite from a developer's local .env (which may enable auth or
# demo mode). This must run before any `bastion.*` import triggers config load.
os.environ["BASTION_NO_DOTENV"] = "1"
for _k in ("BASTION_AUTH_PASSWORD", "BASTION_DEMO", "BASTION_SUDO", "BASTION_JAILS"):
    os.environ.pop(_k, None)

import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def fixture():
    def _load(name: str) -> str:
        with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as f:
            return f.read()

    return _load
