"""Персистентное состояние sync-режима: соответствие AD objectGUID <-> запись в MD."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any


def load_state(path: str) -> dict[str, Any]:
    if not os.path.exists(path):
        return {"users": {}}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data.setdefault("users", {})
    return data


def save_state(path: str, state: dict[str, Any]) -> None:
    """Атомарная запись, чтобы не повредить файл при падении посреди записи."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".state_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise
