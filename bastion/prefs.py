"""Runtime, user-editable preferences layered on top of the env-based config.

`config.settings` holds infrastructure knobs that only an operator sets at deploy
time (sudo, data_dir, auth_password). Preferences here are the things a logged-in
user tweaks from the Settings page — notification targets, allowlist location,
login rate limits — and they are persisted to a JSON file under `data_dir` so
they survive restarts.

All helpers are pure/immutable: `load()` returns a fresh dict every call and
`update()` returns the new section rather than mutating in place.
"""

from __future__ import annotations

import copy
import json
import logging
import os
from typing import Any

from bastion.config import settings

log = logging.getLogger("bastion")

# Section -> {key: default}. The default's *type* drives form coercion, so keep
# every value typed correctly (bool, int, or str).
DEFAULTS: dict[str, dict[str, Any]] = {
    "notifications": {
        "enabled": False,
        "ntfy_url": "https://ntfy.sh",
        "ntfy_topic": "",
        "ntfy_token": "",
        "priority": "default",
        "ban_spike_threshold": 5,
        "ban_spike_window_min": 10,
    },
    "allowlist": {
        "family": "inet",
        "table": "filter",
        "set": "bastion_allow",
    },
    "security": {
        "rate_limit_max_attempts": 5,
        "rate_limit_window_min": 15,
    },
}

# Keys never cleared by an empty form field (so a blank input keeps the stored
# secret instead of wiping it). To clear one, edit the JSON file directly.
SECRET_KEYS: dict[str, tuple[str, ...]] = {
    "notifications": ("ntfy_token",),
}


def _path() -> str:
    return os.path.join(settings.data_dir, "prefs.json")


def merge_defaults(stored: dict[str, Any]) -> dict[str, Any]:
    """Overlay `stored` onto DEFAULTS so newly added keys always appear and
    unknown keys are dropped. Returns a fresh, fully-populated dict."""
    out = copy.deepcopy(DEFAULTS)
    for section, values in (stored or {}).items():
        if section not in out or not isinstance(values, dict):
            continue
        for key, value in values.items():
            if key in out[section]:
                out[section][key] = value
    return out


def coerce_section(section: str, values: dict[str, Any]) -> dict[str, Any]:
    """Coerce raw (string) form input to the types declared in DEFAULTS.
    Unchecked checkboxes are absent from form data, so bool keys default to
    False; ints fall back to the default on parse failure and are clamped >= 0."""
    result: dict[str, Any] = {}
    for key, default in DEFAULTS[section].items():
        raw = values.get(key)
        if isinstance(default, bool):
            result[key] = str(raw).strip().lower() in ("true", "on", "1", "yes")
        elif isinstance(default, int):
            try:
                result[key] = max(0, int(raw))
            except (TypeError, ValueError):
                result[key] = default
        else:
            result[key] = str(raw).strip() if raw is not None else default
    return result


def load() -> dict[str, Any]:
    """Read prefs.json (merged with defaults). Missing/corrupt file -> defaults."""
    path = _path()
    if not os.path.exists(path):
        return copy.deepcopy(DEFAULTS)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return merge_defaults(json.load(f))
    except (OSError, ValueError) as e:
        log.warning("could not read prefs (%s); using defaults", e)
        return copy.deepcopy(DEFAULTS)


def get(section: str) -> dict[str, Any]:
    return load()[section]


def save(prefs: dict[str, Any]) -> None:
    """Atomically persist a full, merged prefs dict (tmp file + rename)."""
    os.makedirs(settings.data_dir, exist_ok=True)
    path = _path()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(prefs, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def update(section: str, values: dict[str, Any]) -> dict[str, Any]:
    """Coerce+validate one section's form input, persist, and return it.
    Blank secret fields keep their previously stored value."""
    if section not in DEFAULTS:
        raise ValueError(f"unknown settings section: {section}")
    current = load()
    new_section = coerce_section(section, values)
    for key in SECRET_KEYS.get(section, ()):
        if not new_section.get(key):
            new_section[key] = current[section].get(key, "")
    current[section] = new_section
    save(current)
    return new_section
