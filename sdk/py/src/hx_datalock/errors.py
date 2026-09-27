from __future__ import annotations

from enum import Enum


# Declared support starts at Python 3.10 (pyproject requires-python), where
# enum.StrEnum does not exist, so this uses the str-mixin form that behaves the
# same on 3.10 through 3.13. Values are the public cross-language contract.
class DataLockErrorCode(str, Enum):
    INVALID_KEYRING = "INVALID_KEYRING"
    INVALID_PUBLIC_KEY_DOCUMENT = "INVALID_PUBLIC_KEY_DOCUMENT"
    WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING = "WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING"
    ENVELOPE_RECIPIENT_MISMATCH = "ENVELOPE_RECIPIENT_MISMATCH"
    TAMPERED_ENVELOPE = "TAMPERED_ENVELOPE"
    UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"
    OVERSIZED_FILE = "OVERSIZED_FILE"
    INVALID_UTF8 = "INVALID_UTF8"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"

    def __str__(self) -> str:
        return self.value


class DataLockError(Exception):
    def __init__(self, code: DataLockErrorCode, message: str):
        self.code = code
        super().__init__(message)
