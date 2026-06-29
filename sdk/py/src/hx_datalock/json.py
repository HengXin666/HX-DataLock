from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .constants import MAX_ENVELOPE_JSON_BYTES
from .errors import DataLockError, DataLockErrorCode


def dumps_stable_json(raw: dict[str, Any]) -> str:
    return json.dumps(raw, ensure_ascii=False, indent=2) + "\n"


def read_json_document(path: str | Path, *, max_bytes: int = MAX_ENVELOPE_JSON_BYTES) -> dict[str, Any]:
    document_path = Path(path)
    if document_path.stat().st_size > max_bytes:
        raise DataLockError(DataLockErrorCode.OVERSIZED_FILE, "JSON document exceeds the v1 size limit")
    raw = json.loads(document_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise DataLockError(DataLockErrorCode.UNSUPPORTED_SCHEMA, "JSON document must be an object")
    return raw


def write_json_document(path: str | Path, raw: dict[str, Any]) -> None:
    Path(path).write_text(dumps_stable_json(raw), encoding="utf-8")


def is_stable_json_document(path: str | Path, stable_json: str) -> bool:
    return Path(path).read_text(encoding="utf-8") == stable_json
