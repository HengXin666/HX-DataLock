from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
import unicodedata
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .constants import (
    ENVELOPE_ALG,
    ENVELOPE_SCHEMA,
    KEY_LENGTH,
    KEYRING_SCHEMA,
    MAX_SCRYPT_N,
    MAX_SCRYPT_P,
    MAX_SCRYPT_R,
    MAX_V1_FILE_BYTES,
    MIN_SCRYPT_N,
)
from .errors import DataLockError, DataLockErrorCode


X25519_SPKI_MAX_BYTES = 512
WRAPPED_READ_KEY_MAX_BYTES = 4096


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _max_b64_chars(max_bytes: int) -> int:
    return ((max_bytes + 2) // 3) * 4


def from_b64(
    value: str,
    field: str,
    *,
    error_code: DataLockErrorCode = DataLockErrorCode.INVALID_KEYRING,
    exact_length: int | None = None,
    max_length: int | None = None,
) -> bytes:
    if not isinstance(value, str):
        raise DataLockError(error_code, f"Missing or invalid base64 field: {field}")
    if exact_length is not None and len(value) > _max_b64_chars(exact_length):
        raise DataLockError(error_code, f"Invalid binary length for field: {field}")
    if max_length is not None and len(value) > _max_b64_chars(max_length):
        raise DataLockError(error_code, f"Invalid binary length for field: {field}")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DataLockError(error_code, f"Missing or invalid base64 field: {field}") from exc
    if exact_length is not None and len(decoded) != exact_length:
        raise DataLockError(error_code, f"Invalid binary length for field: {field}")
    if max_length is not None and len(decoded) > max_length:
        raise DataLockError(error_code, f"Invalid binary length for field: {field}")
    return decoded


def sha256_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def keyring_aad(key_id: str) -> bytes:
    return f"{KEYRING_SCHEMA}:{key_id}:scrypt:AES-256-GCM".encode("utf-8")


def envelope_aad(key_id: str, alg: dict[str, str] | None = None) -> bytes:
    envelope_alg = alg or ENVELOPE_ALG
    return (
        f"{ENVELOPE_SCHEMA}:{key_id}:"
        f"{envelope_alg['kem']}:{envelope_alg['kdf']}:{envelope_alg['aead']}"
    ).encode("utf-8")


def validate_scrypt_n(value: int) -> None:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < MIN_SCRYPT_N
        or value > MAX_SCRYPT_N
        or value & (value - 1)
    ):
        raise ValueError(
            f"scrypt_n must be a power of two between {MIN_SCRYPT_N} and {MAX_SCRYPT_N}"
        )


def _require_int(raw: dict[str, Any], field: str, *, error_code: DataLockErrorCode) -> int:
    value = raw.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        raise DataLockError(error_code, f"Invalid scrypt parameter: {field}")
    return value


def validate_scrypt_params(
    kdf: dict[str, Any],
    *,
    error_code: DataLockErrorCode = DataLockErrorCode.INVALID_KEYRING,
) -> None:
    if not isinstance(kdf, dict) or kdf.get("name") != "scrypt":
        raise DataLockError(
            DataLockErrorCode.UNSUPPORTED_ALGORITHM,
            f"Unsupported password KDF: {kdf.get('name') if isinstance(kdf, dict) else None}",
        )

    n = _require_int(kdf, "N", error_code=error_code)
    r = _require_int(kdf, "r", error_code=error_code)
    p = _require_int(kdf, "p", error_code=error_code)
    key_length = _require_int(kdf, "keyLength", error_code=error_code)

    if n < MIN_SCRYPT_N or n > MAX_SCRYPT_N or n & (n - 1):
        raise DataLockError(error_code, "Invalid scrypt N parameter")
    if r < 1 or r > MAX_SCRYPT_R:
        raise DataLockError(error_code, "Invalid scrypt r parameter")
    if p < 1 or p > MAX_SCRYPT_P:
        raise DataLockError(error_code, "Invalid scrypt p parameter")
    if key_length != KEY_LENGTH:
        raise DataLockError(error_code, "Invalid scrypt keyLength parameter")
    from_b64(kdf.get("salt"), "encryptedReadKey.kdf.salt", error_code=error_code, exact_length=32)


def validate_keyring_encrypted_read_key(encrypted: dict[str, Any]) -> None:
    if not isinstance(encrypted, dict):
        raise DataLockError(DataLockErrorCode.INVALID_KEYRING, "Keyring must contain encrypted Read Key")
    validate_scrypt_params(encrypted.get("kdf", {}), error_code=DataLockErrorCode.INVALID_KEYRING)
    aead = encrypted.get("aead")
    if not isinstance(aead, dict):
        raise DataLockError(DataLockErrorCode.INVALID_KEYRING, "encryptedReadKey must contain AEAD metadata")
    if aead.get("name") != "AES-256-GCM":
        raise DataLockError(
            DataLockErrorCode.UNSUPPORTED_ALGORITHM,
            "encryptedReadKey must use AES-256-GCM",
        )
    from_b64(aead.get("nonce"), "encryptedReadKey.aead.nonce", exact_length=12)
    from_b64(aead.get("tag"), "encryptedReadKey.aead.tag", exact_length=16)
    from_b64(encrypted.get("ciphertext"), "encryptedReadKey.ciphertext", max_length=WRAPPED_READ_KEY_MAX_BYTES)


def validate_envelope_fields(raw: dict[str, Any]) -> None:
    if not isinstance(raw.get("recipientKeyId"), str) or not raw["recipientKeyId"]:
        raise DataLockError(DataLockErrorCode.TAMPERED_ENVELOPE, "Data Envelope must contain recipientKeyId")
    from_b64(
        raw.get("ephemeralPublicKey"),
        "ephemeralPublicKey",
        error_code=DataLockErrorCode.TAMPERED_ENVELOPE,
        max_length=X25519_SPKI_MAX_BYTES,
    )
    from_b64(raw.get("hkdfSalt"), "hkdfSalt", error_code=DataLockErrorCode.TAMPERED_ENVELOPE, exact_length=32)
    from_b64(raw.get("nonce"), "nonce", error_code=DataLockErrorCode.TAMPERED_ENVELOPE, exact_length=12)
    from_b64(raw.get("tag"), "tag", error_code=DataLockErrorCode.TAMPERED_ENVELOPE, exact_length=16)
    ciphertext = raw.get("ciphertext")
    if not isinstance(ciphertext, str):
        raise DataLockError(DataLockErrorCode.TAMPERED_ENVELOPE, "Missing or invalid base64 field: ciphertext")
    if len(ciphertext) > _max_b64_chars(MAX_V1_FILE_BYTES):
        raise DataLockError(DataLockErrorCode.OVERSIZED_FILE, "Data Envelope ciphertext exceeds the v1 size limit")
    decoded_ciphertext = from_b64(
        ciphertext,
        "ciphertext",
        error_code=DataLockErrorCode.TAMPERED_ENVELOPE,
    )
    if len(decoded_ciphertext) > MAX_V1_FILE_BYTES:
        raise DataLockError(DataLockErrorCode.OVERSIZED_FILE, "Data Envelope ciphertext exceeds the v1 size limit")


def derive_password_key(master_password: str, kdf: dict[str, Any]) -> bytes:
    validate_scrypt_params(kdf)
    normalized_password = unicodedata.normalize("NFC", master_password)
    return Scrypt(
        salt=from_b64(kdf["salt"], "encryptedReadKey.kdf.salt", exact_length=32),
        length=kdf["keyLength"],
        n=kdf["N"],
        r=kdf["r"],
        p=kdf["p"],
    ).derive(normalized_password.encode("utf-8"))


def validate_public_write_key(raw: dict[str, Any], *, error_code: DataLockErrorCode) -> x25519.X25519PublicKey:
    if not isinstance(raw.get("publicWriteKey"), dict):
        raise DataLockError(error_code, "Document must contain a public Write Key")
    public_write_key = raw["publicWriteKey"]
    if public_write_key.get("alg") != "X25519":
        raise DataLockError(
            DataLockErrorCode.UNSUPPORTED_ALGORITHM,
            "publicWriteKey must use X25519",
        )
    if not isinstance(public_write_key.get("keyId"), str):
        raise DataLockError(error_code, "publicWriteKey.keyId must be a string")

    try:
        public_der = from_b64(
            public_write_key["spki"],
            "publicWriteKey.spki",
            error_code=error_code,
            max_length=X25519_SPKI_MAX_BYTES,
        )
        expected_key_id = f"x25519:{sha256_base64url(public_der)[:22]}"
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


def validate_envelope_alg(raw: dict[str, Any]) -> None:
    if raw.get("alg") != ENVELOPE_ALG:
        raise DataLockError(
            DataLockErrorCode.UNSUPPORTED_ALGORITHM,
            "Data Envelope must use X25519, HKDF-SHA256, and AES-256-GCM",
        )


def envelope_b64(raw: dict[str, Any], field: str) -> bytes:
    return from_b64(raw.get(field), field, error_code=DataLockErrorCode.TAMPERED_ENVELOPE)


def seal_read_key(key_id: str, master_password: str, kdf: dict[str, Any], private_der: bytes) -> dict[str, Any]:
    wrapping_key = derive_password_key(master_password, kdf)
    nonce = secrets.token_bytes(12)
    sealed = AESGCM(wrapping_key).encrypt(nonce, private_der, keyring_aad(key_id))
    return {
        "kdf": kdf,
        "aead": {
            "name": "AES-256-GCM",
            "nonce": b64(nonce),
            "tag": b64(sealed[-16:]),
        },
        "ciphertext": b64(sealed[:-16]),
    }


def unwrap_read_key(
    encrypted: dict[str, Any],
    key_id: str,
    master_password: str,
) -> x25519.X25519PrivateKey:
    validate_keyring_encrypted_read_key(encrypted)
    wrapping_key = derive_password_key(master_password, encrypted["kdf"])
    aead = encrypted["aead"]
    nonce = from_b64(aead["nonce"], "encryptedReadKey.aead.nonce", exact_length=12)
    tag = from_b64(aead["tag"], "encryptedReadKey.aead.tag", exact_length=16)
    ciphertext = from_b64(encrypted["ciphertext"], "encryptedReadKey.ciphertext", max_length=WRAPPED_READ_KEY_MAX_BYTES)
    try:
        private_der = AESGCM(wrapping_key).decrypt(
            nonce,
            ciphertext + tag,
            keyring_aad(key_id),
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


def lock_bytes_with_public_key_raw(
    key_id: str,
    public_write_key: x25519.X25519PublicKey,
    payload_bytes: bytes,
) -> dict[str, Any]:
    ephemeral_private = x25519.X25519PrivateKey.generate()
    shared_secret = ephemeral_private.exchange(public_write_key)
    hkdf_salt = secrets.token_bytes(32)
    content_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=hkdf_salt,
        info=f"{ENVELOPE_SCHEMA}:{key_id}".encode("utf-8"),
    ).derive(shared_secret)
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(content_key).encrypt(nonce, payload_bytes, envelope_aad(key_id))
    ephemeral_public_der = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        "schema": ENVELOPE_SCHEMA,
        "createdAt": utc_now(),
        "recipientKeyId": key_id,
        "alg": ENVELOPE_ALG.copy(),
        "ephemeralPublicKey": b64(ephemeral_public_der),
        "hkdfSalt": b64(hkdf_salt),
        "nonce": b64(nonce),
        "tag": b64(encrypted[-16:]),
        "ciphertext": b64(encrypted[:-16]),
    }


def open_envelope_payload(
    key_id: str,
    read_key: x25519.X25519PrivateKey,
    raw: dict[str, Any],
) -> bytes:
    validate_envelope_fields(raw)
    try:
        loaded_public = serialization.load_der_public_key(
            envelope_b64(raw, "ephemeralPublicKey")
        )
    except DataLockError as exc:
        raise DataLockError(DataLockErrorCode.TAMPERED_ENVELOPE, "Invalid Data Envelope public key") from exc
    except Exception as exc:
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
        salt=envelope_b64(raw, "hkdfSalt"),
        info=f"{ENVELOPE_SCHEMA}:{key_id}".encode("utf-8"),
    ).derive(shared_secret)
    try:
        return AESGCM(content_key).decrypt(
            envelope_b64(raw, "nonce"),
            envelope_b64(raw, "ciphertext") + envelope_b64(raw, "tag"),
            envelope_aad(key_id, raw["alg"]),
        )
    except InvalidTag as exc:
        raise DataLockError(DataLockErrorCode.TAMPERED_ENVELOPE, "Ciphertext authentication failed") from exc
