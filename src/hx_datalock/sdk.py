from __future__ import annotations

import base64
import hashlib
import json
import secrets
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, TypedDict

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEYRING_SCHEMA = "hxdl.keyring.v1"
ENVELOPE_SCHEMA = "hxdl.envelope.v1"
DEFAULT_SCRYPT_N = 2**18
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
KEY_LENGTH = 32
PUBLIC_KEY_SCHEMA = "hxdl.publicKey.v1"
ENVELOPE_ALG = {
    "kem": "X25519",
    "kdf": "HKDF-SHA256",
    "aead": "AES-256-GCM",
}


class PasswordStrengthReport(TypedDict, total=False):
    level: Literal["weak", "fair", "good", "strong"]
    allowed: bool
    warnings: list[str]
    suggestions: list[str]
    estimatedEntropyBits: float


class DataLockErrorCode(StrEnum):
    INVALID_KEYRING = "INVALID_KEYRING"
    INVALID_PUBLIC_KEY_DOCUMENT = "INVALID_PUBLIC_KEY_DOCUMENT"
    WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING = "WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING"
    ENVELOPE_RECIPIENT_MISMATCH = "ENVELOPE_RECIPIENT_MISMATCH"
    TAMPERED_ENVELOPE = "TAMPERED_ENVELOPE"
    UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"
    OVERSIZED_FILE = "OVERSIZED_FILE"
    INVALID_UTF8 = "INVALID_UTF8"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"


class DataLockError(Exception):
    def __init__(self, code: DataLockErrorCode, message: str):
        self.code = code
        super().__init__(message)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _from_b64(
    value: str,
    field: str,
    *,
    error_code: DataLockErrorCode = DataLockErrorCode.INVALID_KEYRING,
) -> bytes:
    if not isinstance(value, str):
        raise DataLockError(error_code, f"Missing or invalid base64 field: {field}")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise DataLockError(error_code, f"Missing or invalid base64 field: {field}") from exc


def _sha256_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _keyring_aad(key_id: str) -> bytes:
    return f"{KEYRING_SCHEMA}:{key_id}:scrypt:AES-256-GCM".encode("utf-8")


def _envelope_aad(key_id: str, alg: dict[str, str] | None = None) -> bytes:
    envelope_alg = alg or ENVELOPE_ALG
    return (
        f"{ENVELOPE_SCHEMA}:{key_id}:"
        f"{envelope_alg['kem']}:{envelope_alg['kdf']}:{envelope_alg['aead']}"
    ).encode("utf-8")


def _derive_password_key(master_password: str, kdf: dict[str, Any]) -> bytes:
    if kdf.get("name") != "scrypt":
        raise DataLockError(
            DataLockErrorCode.UNSUPPORTED_ALGORITHM,
            f"Unsupported password KDF: {kdf.get('name')}",
        )
    normalized_password = unicodedata.normalize("NFC", master_password)
    return Scrypt(
        salt=_from_b64(kdf["salt"], "encryptedReadKey.kdf.salt"),
        length=int(kdf.get("keyLength", KEY_LENGTH)),
        n=int(kdf["N"]),
        r=int(kdf["r"]),
        p=int(kdf["p"]),
    ).derive(normalized_password.encode("utf-8"))


def _validate_scrypt_n(value: int) -> None:
    if value < 2**14 or value & (value - 1):
        raise ValueError("scrypt_n must be a power of two and at least 16384")


def _validate_public_write_key(raw: dict[str, Any], *, error_code: DataLockErrorCode) -> x25519.X25519PublicKey:
    if not isinstance(raw.get("publicWriteKey"), dict):
        raise DataLockError(error_code, "Document must contain a public Write Key")
    public_write_key = raw["publicWriteKey"]
    if public_write_key.get("alg") != "X25519":
        raise DataLockError(
            DataLockErrorCode.UNSUPPORTED_ALGORITHM,
            "publicWriteKey must use X25519",
        )

    try:
        public_der = _from_b64(
            public_write_key["spki"],
            "publicWriteKey.spki",
            error_code=error_code,
        )
        expected_key_id = f"x25519:{_sha256_base64url(public_der)[:22]}"
        if not secrets.compare_digest(public_write_key["keyId"], expected_key_id):
            raise DataLockError(error_code, "keyId does not match the Write Key")
        loaded = serialization.load_der_public_key(public_der)
    except DataLockError:
        raise
    except Exception as exc:
        raise DataLockError(error_code, "Invalid public Write Key") from exc

    if not isinstance(loaded, x25519.X25519PublicKey):
        raise DataLockError(
            DataLockErrorCode.UNSUPPORTED_ALGORITHM,
            "publicWriteKey.spki is not an X25519 public key",
        )
    return loaded


def _validate_envelope_alg(raw: dict[str, Any]) -> None:
    if raw.get("alg") != ENVELOPE_ALG:
        raise DataLockError(
            DataLockErrorCode.UNSUPPORTED_ALGORITHM,
            "Data Envelope must use X25519, HKDF-SHA256, and AES-256-GCM",
        )


def _envelope_b64(raw: dict[str, Any], field: str) -> bytes:
    return _from_b64(raw[field], field, error_code=DataLockErrorCode.TAMPERED_ENVELOPE)


def check_password_strength(master_password: str) -> PasswordStrengthReport:
    unique_chars = len(set(master_password))
    estimated_entropy = min(128.0, round(len(master_password) * 3.0 + unique_chars * 1.5, 1))
    warnings: list[str] = []
    suggestions: list[str] = []

    common_passwords = {"password", "123456", "qwerty", "admin", "letmein"}
    lower_password = master_password.lower()
    if len(master_password) < 12:
        warnings.append("Master Password is short.")
        suggestions.append("Use a longer passphrase.")
    if lower_password in common_passwords:
        warnings.append("Master Password is a commonly used password.")
        suggestions.append("Avoid common passwords.")
    if unique_chars <= 4 and len(master_password) >= 8:
        warnings.append("Master Password uses too little character variety.")
        suggestions.append("Use several unrelated words or more varied characters.")

    if warnings:
        level: Literal["weak", "fair", "good", "strong"] = "weak"
    elif len(master_password) >= 32 and unique_chars >= 12:
        level = "strong"
    elif len(master_password) >= 20 and unique_chars >= 10:
        level = "good"
    else:
        level = "fair"

    report: PasswordStrengthReport = {
        "level": level,
        "allowed": True,
        "warnings": warnings,
        "suggestions": suggestions,
        "estimatedEntropyBits": estimated_entropy,
    }
    return report


@dataclass(frozen=True)
class Keyring:
    raw: dict[str, Any]

    @property
    def key_id(self) -> str:
        return self.raw["publicWriteKey"]["keyId"]

    @property
    def public_write_key(self) -> x25519.X25519PublicKey:
        return _validate_public_write_key(self.raw, error_code=DataLockErrorCode.INVALID_KEYRING)

    def verify(self) -> None:
        if self.raw.get("schema") != KEYRING_SCHEMA:
            raise DataLockError(
                DataLockErrorCode.UNSUPPORTED_SCHEMA,
                f"Unsupported Keyring schema: {self.raw.get('schema')}",
            )
        if not isinstance(self.raw.get("encryptedReadKey"), dict):
            raise DataLockError(DataLockErrorCode.INVALID_KEYRING, "Keyring must contain encrypted Read Key")
        encrypted = self.raw["encryptedReadKey"]
        if encrypted.get("kdf", {}).get("name") != "scrypt":
            raise DataLockError(
                DataLockErrorCode.UNSUPPORTED_ALGORITHM,
                f"Unsupported password KDF: {encrypted.get('kdf', {}).get('name')}",
            )
        if encrypted.get("aead", {}).get("name") != "AES-256-GCM":
            raise DataLockError(
                DataLockErrorCode.UNSUPPORTED_ALGORITHM,
                "encryptedReadKey must use AES-256-GCM",
            )
        _validate_public_write_key(self.raw, error_code=DataLockErrorCode.INVALID_KEYRING)

    def to_json(self) -> str:
        return json.dumps(self.raw, ensure_ascii=False, indent=2) + "\n"

    def write(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    def unwrap_read_key(self, master_password: str) -> x25519.X25519PrivateKey:
        self.verify()
        encrypted = self.raw["encryptedReadKey"]
        wrapping_key = _derive_password_key(master_password, encrypted["kdf"])
        aead = encrypted["aead"]
        nonce = _from_b64(aead["nonce"], "encryptedReadKey.aead.nonce")
        tag = _from_b64(aead["tag"], "encryptedReadKey.aead.tag")
        ciphertext = _from_b64(encrypted["ciphertext"], "encryptedReadKey.ciphertext")
        try:
            private_der = AESGCM(wrapping_key).decrypt(
                nonce,
                ciphertext + tag,
                _keyring_aad(self.key_id),
            )
        except InvalidTag as exc:
            raise DataLockError(
                DataLockErrorCode.WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING,
                "Wrong master password or tampered Keyring",
            ) from exc

        loaded = serialization.load_der_private_key(private_der, password=None)
        if not isinstance(loaded, x25519.X25519PrivateKey):
            raise DataLockError(
                DataLockErrorCode.INVALID_KEYRING,
                "Unwrapped Read Key is not an X25519 private key",
            )
        return loaded


@dataclass(frozen=True)
class DataEnvelope:
    raw: dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(self.raw, ensure_ascii=False, indent=2) + "\n"

    def write(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def read(cls, path: str | Path) -> "DataEnvelope":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def verify(self) -> None:
        raw = self.raw
        if raw.get("schema") != ENVELOPE_SCHEMA:
            raise DataLockError(
                DataLockErrorCode.UNSUPPORTED_SCHEMA,
                f"Unsupported Data Envelope schema: {raw.get('schema')}",
            )
        _validate_envelope_alg(raw)


@dataclass(frozen=True)
class PublicKeyDocument:
    raw: dict[str, Any]

    @property
    def key_id(self) -> str:
        return self.raw["publicWriteKey"]["keyId"]

    @property
    def public_write_key(self) -> x25519.X25519PublicKey:
        return _validate_public_write_key(
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
        _validate_public_write_key(
            self.raw,
            error_code=DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT,
        )

    def to_json(self) -> str:
        return json.dumps(self.raw, ensure_ascii=False, indent=2) + "\n"

    def write(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def read(cls, path: str | Path) -> "PublicKeyDocument":
        document = cls(json.loads(Path(path).read_text(encoding="utf-8")))
        document.verify()
        return document


def create_keyring(master_password: str, *, scrypt_n: int = DEFAULT_SCRYPT_N) -> Keyring:
    check_password_strength(master_password)
    _validate_scrypt_n(scrypt_n)

    private_key = x25519.X25519PrivateKey.generate()
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_id = f"x25519:{_sha256_base64url(public_der)[:22]}"
    kdf = {
        "name": "scrypt",
        "salt": _b64(secrets.token_bytes(32)),
        "N": scrypt_n,
        "r": DEFAULT_SCRYPT_R,
        "p": DEFAULT_SCRYPT_P,
        "keyLength": KEY_LENGTH,
    }
    wrapping_key = _derive_password_key(master_password, kdf)
    nonce = secrets.token_bytes(12)
    sealed = AESGCM(wrapping_key).encrypt(nonce, private_der, _keyring_aad(key_id))
    keyring = Keyring(
        {
            "schema": KEYRING_SCHEMA,
            "createdAt": _utc_now(),
            "publicWriteKey": {
                "alg": "X25519",
                "keyId": key_id,
                "spki": _b64(public_der),
            },
            "encryptedReadKey": {
                "kdf": kdf,
                "aead": {
                    "name": "AES-256-GCM",
                    "nonce": _b64(nonce),
                    "tag": _b64(sealed[-16:]),
                },
                "ciphertext": _b64(sealed[:-16]),
            },
        }
    )
    keyring.verify()
    return keyring


def init_keyring(path: str | Path, master_password: str, *, scrypt_n: int = DEFAULT_SCRYPT_N) -> Keyring:
    keyring = create_keyring(master_password, scrypt_n=scrypt_n)
    keyring.write(path)
    return keyring


def load_keyring(path: str | Path) -> Keyring:
    keyring = Keyring(json.loads(Path(path).read_text(encoding="utf-8")))
    keyring.verify()
    return keyring


def export_public_key_document(keyring: Keyring) -> PublicKeyDocument:
    keyring.verify()
    document = PublicKeyDocument(
        {
            "schema": PUBLIC_KEY_SCHEMA,
            "createdAt": _utc_now(),
            "publicWriteKey": dict(keyring.raw["publicWriteKey"]),
        }
    )
    document.verify()
    return document


def make_v1_compatibility_manifest() -> dict[str, Any]:
    return {
        "schema": "hxdl.compatibilityManifest.v1",
        "cases": [
            {
                "id": "v1-keyring-document",
                "kind": "keyring",
                "producer": "fixture",
                "consumers": ["python", "typescript", "android-kotlin"],
                "documents": [
                    {
                        "schema": KEYRING_SCHEMA,
                        "document": "Keyring",
                    }
                ],
            },
            {
                "id": "v1-public-key-document",
                "kind": "publicKeyDocument",
                "producer": "fixture",
                "consumers": ["python", "typescript"],
                "documents": [
                    {
                        "schema": PUBLIC_KEY_SCHEMA,
                        "document": "Public Key Document",
                    }
                ],
            },
            {
                "id": "v1-data-envelope-document",
                "kind": "dataEnvelope",
                "producer": "fixture",
                "consumers": ["python", "typescript", "android-kotlin"],
                "documents": [
                    {
                        "schema": ENVELOPE_SCHEMA,
                        "document": "Data Envelope",
                    }
                ],
            },
            {
                "id": "v1-expected-failure-codes",
                "kind": "failureModes",
                "producer": "fixture",
                "consumers": ["python", "typescript", "android-kotlin"],
                "expectations": [
                    {
                        "failure": "wrong-master-password-or-tampered-keyring",
                        "expectedCode": DataLockErrorCode.WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING.value,
                    },
                    {
                        "failure": "envelope-recipient-mismatch",
                        "expectedCode": DataLockErrorCode.ENVELOPE_RECIPIENT_MISMATCH.value,
                    },
                    {
                        "failure": "tampered-envelope",
                        "expectedCode": DataLockErrorCode.TAMPERED_ENVELOPE.value,
                    },
                    {
                        "failure": "unsupported-schema",
                        "expectedCode": DataLockErrorCode.UNSUPPORTED_SCHEMA.value,
                    },
                    {
                        "failure": "unsupported-algorithm",
                        "expectedCode": DataLockErrorCode.UNSUPPORTED_ALGORITHM.value,
                    },
                ],
            },
        ],
    }


def encrypt_message(keyring: Keyring, plaintext: bytes) -> DataEnvelope:
    keyring.verify()
    ephemeral_private = x25519.X25519PrivateKey.generate()
    shared_secret = ephemeral_private.exchange(keyring.public_write_key)
    hkdf_salt = secrets.token_bytes(32)
    content_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=hkdf_salt,
        info=f"{ENVELOPE_SCHEMA}:{keyring.key_id}".encode("utf-8"),
    ).derive(shared_secret)
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(content_key).encrypt(nonce, plaintext, _envelope_aad(keyring.key_id))
    ephemeral_public_der = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return DataEnvelope(
        {
            "schema": ENVELOPE_SCHEMA,
            "createdAt": _utc_now(),
            "recipientKeyId": keyring.key_id,
            "alg": ENVELOPE_ALG.copy(),
            "ephemeralPublicKey": _b64(ephemeral_public_der),
            "hkdfSalt": _b64(hkdf_salt),
            "nonce": _b64(nonce),
            "tag": _b64(encrypted[-16:]),
            "ciphertext": _b64(encrypted[:-16]),
        }
    )


def decrypt_message(keyring: Keyring, master_password: str, envelope: DataEnvelope) -> bytes:
    keyring.verify()
    raw = envelope.raw
    envelope.verify()
    if raw.get("recipientKeyId") != keyring.key_id:
        raise DataLockError(
            DataLockErrorCode.ENVELOPE_RECIPIENT_MISMATCH,
            "Data Envelope recipient does not match the Keyring",
        )

    read_key = keyring.unwrap_read_key(master_password)
    try:
        loaded_public = serialization.load_der_public_key(
            _envelope_b64(raw, "ephemeralPublicKey")
        )
    except DataLockError as exc:
        raise DataLockError(DataLockErrorCode.TAMPERED_ENVELOPE, "Invalid Data Envelope public key") from exc
    if not isinstance(loaded_public, x25519.X25519PublicKey):
        raise DataLockError(
            DataLockErrorCode.UNSUPPORTED_ALGORITHM,
            "ephemeralPublicKey is not an X25519 public key",
        )

    shared_secret = read_key.exchange(loaded_public)
    content_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=_envelope_b64(raw, "hkdfSalt"),
        info=f"{ENVELOPE_SCHEMA}:{keyring.key_id}".encode("utf-8"),
    ).derive(shared_secret)
    try:
        return AESGCM(content_key).decrypt(
            _envelope_b64(raw, "nonce"),
            _envelope_b64(raw, "ciphertext") + _envelope_b64(raw, "tag"),
            _envelope_aad(keyring.key_id, raw["alg"]),
        )
    except InvalidTag as exc:
        raise DataLockError(DataLockErrorCode.TAMPERED_ENVELOPE, "Ciphertext authentication failed") from exc


def send_file(keyring_path: str | Path, input_path: str | Path, output_path: str | Path) -> DataEnvelope:
    keyring = load_keyring(keyring_path)
    envelope = encrypt_message(keyring, Path(input_path).read_bytes())
    envelope.write(output_path)
    return envelope


def open_file(
    keyring_path: str | Path,
    envelope_path: str | Path,
    output_path: str | Path,
    master_password: str,
) -> bytes:
    keyring = load_keyring(keyring_path)
    plaintext = decrypt_message(keyring, master_password, DataEnvelope.read(envelope_path))
    Path(output_path).write_bytes(plaintext)
    return plaintext
