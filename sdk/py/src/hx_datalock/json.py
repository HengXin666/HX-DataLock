from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def dumps_stable_json(raw: dict[str, Any]) -> str:
    return json.dumps(raw, ensure_ascii=False, indent=2) + "\n"


def read_json_document(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json_document(path: str | Path, raw: dict[str, Any]) -> None:
    Path(path).write_text(dumps_stable_json(raw), encoding="utf-8")


def is_stable_json_document(path: str | Path, stable_json: str) -> bool:
    return Path(path).read_text(encoding="utf-8") == stable_json
