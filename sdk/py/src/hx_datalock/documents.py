from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import x25519

from .constants import ENVELOPE_SCHEMA, KEYRING_SCHEMA, MAX_PUBLIC_KEY_JSON_BYTES, PUBLIC_KEY_SCHEMA
from .crypto_codec import (
    unwrap_read_key,
    validate_envelope_alg,
    validate_envelope_fields,
    validate_keyring_encrypted_read_key,
    validate_public_write_key,
)
from .errors import DataLockError, DataLockErrorCode
from .json import dumps_stable_json, read_json_document, write_json_document


@dataclass(frozen=True)
class Keyring:
    raw: dict[str, Any]

    @property
    def key_id(self) -> str:
        return self.raw["publicWriteKey"]["keyId"]

    @property
    def public_write_key(self) -> x25519.X25519PublicKey:
        return validate_public_write_key(self.raw, error_code=DataLockErrorCode.INVALID_KEYRING)

    def verify(self) -> None:
        if self.raw.get("schema") != KEYRING_SCHEMA:
            raise DataLockError(
                DataLockErrorCode.UNSUPPORTED_SCHEMA,
                f"Unsupported Keyring schema: {self.raw.get('schema')}",
            )
        if not isinstance(self.raw.get("encryptedReadKey"), dict):
            raise DataLockError(DataLockErrorCode.INVALID_KEYRING, "Keyring must contain encrypted Read Key")
        validate_keyring_encrypted_read_key(self.raw["encryptedReadKey"])
        validate_public_write_key(self.raw, error_code=DataLockErrorCode.INVALID_KEYRING)

    def to_json(self) -> str:
        return dumps_stable_json(self.raw)

    def write(self, path: str | Path) -> None:
        write_json_document(path, self.raw)

    def unwrap_read_key(self, master_password: str) -> x25519.X25519PrivateKey:
        self.verify()
        return unwrap_read_key(self.raw["encryptedReadKey"], self.key_id, master_password)


@dataclass(frozen=True)
class DataEnvelope:
    raw: dict[str, Any]

    def to_json(self) -> str:
        return dumps_stable_json(self.raw)

    def write(self, path: str | Path) -> None:
        write_json_document(path, self.raw)

    @classmethod
    def read(cls, path: str | Path) -> "DataEnvelope":
        document = cls(read_json_document(path))
        document.verify()
        return document

    def verify(self) -> None:
        raw = self.raw
        if raw.get("schema") != ENVELOPE_SCHEMA:
            raise DataLockError(
                DataLockErrorCode.UNSUPPORTED_SCHEMA,
                f"Unsupported Data Envelope schema: {raw.get('schema')}",
            )
        validate_envelope_alg(raw)
        validate_envelope_fields(raw)


@dataclass(frozen=True)
class PublicKeyDocument:
    raw: dict[str, Any]

    @property
    def key_id(self) -> str:
        return self.raw["publicWriteKey"]["keyId"]

    @property
    def public_write_key(self) -> x25519.X25519PublicKey:
        return validate_public_write_key(
            self.raw,
            error_code=DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT,
        )

    def verify(self) -> None:
        if self.raw.get("schema") != PUBLIC_KEY_SCHEMA:
            raise DataLockError(
                DataLockErrorCode.UNSUPPORTED_SCHEMA,
                f"Unsupported Public Key Document schema: {self.raw.get('schema')}",
            )
        if "encryptedReadKey" in self.raw:
            raise DataLockError(
                DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT,
                "Public Key Document must not contain encrypted Read Key material",
            )
        validate_public_write_key(
            self.raw,
            error_code=DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT,
        )

    def to_json(self) -> str:
        return dumps_stable_json(self.raw)

    def write(self, path: str | Path) -> None:
        write_json_document(path, self.raw)

    @classmethod
    def read(cls, path: str | Path) -> "PublicKeyDocument":
        document = cls(read_json_document(path, max_bytes=MAX_PUBLIC_KEY_JSON_BYTES))
        document.verify()
        return document
