from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from .compatibility import make_v1_compatibility_manifest
from .constants import (
    DEFAULT_SCRYPT_N,
    DEFAULT_SCRYPT_P,
    DEFAULT_SCRYPT_R,
    ENVELOPE_SCHEMA,
    KEY_LENGTH,
    KEYRING_SCHEMA,
    MAX_KEYRING_JSON_BYTES,
    PUBLIC_KEY_SCHEMA,
)
from .crypto_codec import (
    b64,
    lock_bytes_with_public_key_raw,
    seal_read_key,
    sha256_base64url,
    utc_now,
    validate_scrypt_n,
)
from .datalocks import SenderDataLock, UserDataLock
from .documents import DataEnvelope, Keyring, PublicKeyDocument
from .errors import DataLockError, DataLockErrorCode
from .json import is_stable_json_document, read_json_document
from .password_strength import PasswordStrengthReport, check_password_strength


def create_keyring(master_password: str, *, scrypt_n: int = DEFAULT_SCRYPT_N) -> Keyring:
    check_password_strength(master_password)
    validate_scrypt_n(scrypt_n)

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
    key_id = f"x25519:{sha256_base64url(public_der)[:22]}"
    kdf = {
        "name": "scrypt",
        "salt": b64(secrets.token_bytes(32)),
        "N": scrypt_n,
        "r": DEFAULT_SCRYPT_R,
        "p": DEFAULT_SCRYPT_P,
        "keyLength": KEY_LENGTH,
    }
    keyring = Keyring(
        {
            "schema": KEYRING_SCHEMA,
            "createdAt": utc_now(),
            "publicWriteKey": {
                "alg": "X25519",
                "keyId": key_id,
                "spki": b64(public_der),
            },
            "encryptedReadKey": seal_read_key(key_id, master_password, kdf, private_der),
        }
    )
    keyring.verify()
    return keyring


def init_keyring(path: str | Path, master_password: str, *, scrypt_n: int = DEFAULT_SCRYPT_N) -> Keyring:
    keyring = create_keyring(master_password, scrypt_n=scrypt_n)
    keyring.write(path)
    return keyring


def load_keyring(path: str | Path) -> Keyring:
    keyring = Keyring(read_json_document(path, max_bytes=MAX_KEYRING_JSON_BYTES))
    keyring.verify()
    return keyring


def verify_keyring_file(path: str | Path, *, require_stable_json: bool = False) -> Keyring:
    keyring = load_keyring(path)
    if require_stable_json and not is_stable_json_document(path, keyring.to_json()):
        raise DataLockError(DataLockErrorCode.INVALID_KEYRING, "Keyring does not use stable v1 JSON")
    return keyring


def verify_public_key_document_file(
    path: str | Path,
    *,
    require_stable_json: bool = False,
) -> PublicKeyDocument:
    document = PublicKeyDocument.read(path)
    if require_stable_json and not is_stable_json_document(path, document.to_json()):
        raise DataLockError(
            DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT,
            "Public Key Document does not use stable v1 JSON",
        )
    return document


def export_public_key_document(keyring: Keyring) -> PublicKeyDocument:
    keyring.verify()
    document = PublicKeyDocument(
        {
            "schema": PUBLIC_KEY_SCHEMA,
            "createdAt": utc_now(),
            "publicWriteKey": dict(keyring.raw["publicWriteKey"]),
        }
    )
    document.verify()
    return document


def verify_public_key_document_key_id(
    publicKeyDocument: PublicKeyDocument | dict[str, Any],
    expected_key_id: str,
) -> PublicKeyDocument:
    document = publicKeyDocument if isinstance(publicKeyDocument, PublicKeyDocument) else PublicKeyDocument(publicKeyDocument)
    document.verify()
    if document.key_id != expected_key_id:
        raise DataLockError(
            DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT,
            "Public Key Document keyId does not match the expected keyId",
        )
    return document


def makeSenderDataLock(
    publicKeyDocument: PublicKeyDocument,
    *,
    expected_key_id: str | None = None,
) -> SenderDataLock:
    if isinstance(publicKeyDocument, Keyring) or (
        isinstance(publicKeyDocument, dict) and publicKeyDocument.get("schema") == KEYRING_SCHEMA
    ):
        raise DataLockError(
            DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT,
            "Sender DataLock requires a Public Key Document, not a full Keyring",
        )
    if isinstance(publicKeyDocument, dict):
        publicKeyDocument = PublicKeyDocument(publicKeyDocument)
    if not isinstance(publicKeyDocument, PublicKeyDocument):
        raise DataLockError(
            DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT,
            "Sender DataLock requires a Public Key Document",
        )
    publicKeyDocument.verify()
    if expected_key_id is not None:
        verify_public_key_document_key_id(publicKeyDocument, expected_key_id)
    return SenderDataLock(publicKeyDocument)


def makeUserDataLock(keyring: Keyring | dict[str, Any], options: dict[str, Any]) -> UserDataLock:
    if isinstance(keyring, dict):
        keyring = Keyring(keyring)
    if not isinstance(keyring, Keyring):
        raise DataLockError(DataLockErrorCode.INVALID_KEYRING, "User DataLock requires a full Keyring")
    if not isinstance(options, dict) or not isinstance(options.get("masterPassword"), str):
        raise DataLockError(
            DataLockErrorCode.WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING,
            "User DataLock requires a Master Password",
        )

    read_key = keyring.unwrap_read_key(options["masterPassword"])
    return UserDataLock(keyring, read_key)


def encrypt_message(keyring: Keyring, plaintext: bytes) -> DataEnvelope:
    keyring.verify()
    return DataEnvelope(lock_bytes_with_public_key_raw(keyring.key_id, keyring.public_write_key, plaintext))


def encrypt_message_for_sender(public_key_document: PublicKeyDocument, plaintext: bytes) -> DataEnvelope:
    sender = makeSenderDataLock(public_key_document)
    return sender.lockBytes(plaintext)


def decrypt_message(keyring: Keyring, master_password: str, envelope: DataEnvelope) -> bytes:
    user = makeUserDataLock(keyring, {"masterPassword": master_password})
    return user.openBytes(envelope)


def send_file_with_public_doc(
    public_key_document_path: str | Path,
    input_path: str | Path,
    output_path: str | Path,
    *,
    expected_key_id: str | None = None,
) -> DataEnvelope:
    public_key_document = PublicKeyDocument.read(public_key_document_path)
    envelope = makeSenderDataLock(public_key_document, expected_key_id=expected_key_id).lockBytes(
        Path(input_path).read_bytes()
    )
    envelope.write(output_path)
    return envelope


def send_file(keyring_path: str | Path, input_path: str | Path, output_path: str | Path) -> DataEnvelope:
    """Legacy local helper that encrypts with the Write Key from a full Keyring.

    New sender environments should use send_file_with_public_doc(...) so they never
    receive full Keyring material. This helper is kept for v1 API compatibility.
    """
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
