from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any, Callable

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
    MAX_V1_FILE_BYTES,
    MIN_CREATE_SCRYPT_N,
    MIN_SCRYPT_N,
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
from .json import is_stable_json_document, read_json_document, write_private_bytes
from .password_strength import PasswordStrengthReport, check_password_strength


def create_keyring(
    master_password: str,
    *,
    scrypt_n: int = DEFAULT_SCRYPT_N,
    on_password_report: Callable[[PasswordStrengthReport], None] | None = None,
    allow_weak_password: bool = False,
    allow_low_scrypt_n: bool = False,
) -> Keyring:
    # ADR 0012 requires the Password Strength Report to reach the caller before
    # any key material is derived. ADR 0025 then refuses a weak report unless
    # the caller opts in. Opening an existing Keyring does not consult this check.
    report = check_password_strength(master_password)
    if on_password_report is not None:
        on_password_report(report)
    if report["allowed"] is False and not allow_weak_password:
        raise DataLockError(
            DataLockErrorCode.WEAK_MASTER_PASSWORD,
            "Master Password is too weak to create a Keyring. "
            "Pass allow_weak_password=True to create one anyway. "
            "Existing Keyrings can still be opened.",
        )
    validate_scrypt_n(scrypt_n)
    if scrypt_n < MIN_CREATE_SCRYPT_N and not allow_low_scrypt_n:
        raise DataLockError(
            DataLockErrorCode.INSECURE_SCRYPT_PARAMETERS,
            f"scrypt N {scrypt_n} is below the create-time minimum {MIN_CREATE_SCRYPT_N}. "
            f"Readers still accept Keyrings down to {MIN_SCRYPT_N}. "
            "Pass allow_low_scrypt_n=True to create one anyway.",
        )

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


def init_keyring(
    path: str | Path,
    master_password: str,
    *,
    scrypt_n: int = DEFAULT_SCRYPT_N,
    on_password_report: Callable[[PasswordStrengthReport], None] | None = None,
    allow_weak_password: bool = False,
    allow_low_scrypt_n: bool = False,
) -> Keyring:
    keyring = create_keyring(
        master_password,
        scrypt_n=scrypt_n,
        on_password_report=on_password_report,
        allow_weak_password=allow_weak_password,
        allow_low_scrypt_n=allow_low_scrypt_n,
    )
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
    allow_unpinned_public_key: bool = False,
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
    if expected_key_id is not None and not isinstance(expected_key_id, str):
        raise DataLockError(
            DataLockErrorCode.INVALID_PUBLIC_KEY_DOCUMENT,
            "expected_key_id must be a string",
        )
    if expected_key_id:
        verify_public_key_document_key_id(publicKeyDocument, expected_key_id)
    elif not allow_unpinned_public_key:
        raise DataLockError(
            DataLockErrorCode.UNPINNED_PUBLIC_KEY,
            "Sender DataLock requires expected_key_id so a replaced Public Key Document "
            "cannot be used by accident. Pass allow_unpinned_public_key=True only when "
            "the document is already authenticated.",
        )
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


def encrypt_message_for_sender(
    public_key_document: PublicKeyDocument,
    plaintext: bytes,
    *,
    expected_key_id: str | None = None,
    allow_unpinned_public_key: bool = False,
) -> DataEnvelope:
    sender = makeSenderDataLock(
        public_key_document,
        expected_key_id=expected_key_id,
        allow_unpinned_public_key=allow_unpinned_public_key,
    )
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
    allow_unpinned_public_key: bool = False,
) -> DataEnvelope:
    public_key_document = PublicKeyDocument.read(public_key_document_path)
    # lockBytes enforces the v1 limit, so the file helper inherits it here rather
    # than reading an oversized file into memory first.
    envelope = makeSenderDataLock(
        public_key_document,
        expected_key_id=expected_key_id,
        allow_unpinned_public_key=allow_unpinned_public_key,
    ).lockBytes(read_within_v1_limit(input_path))
    envelope.write(output_path)
    return envelope


def send_file(keyring_path: str | Path, input_path: str | Path, output_path: str | Path) -> DataEnvelope:
    """Legacy local helper that encrypts with the Write Key from a full Keyring.

    New sender environments should use send_file_with_public_doc(...) so they never
    receive full Keyring material. This helper is kept for v1 API compatibility.
    """
    keyring = load_keyring(keyring_path)
    envelope = encrypt_message(keyring, read_within_v1_limit(input_path))
    envelope.write(output_path)
    return envelope


def read_within_v1_limit(input_path: str | Path) -> bytes:
    """Read a local file, refusing anything a v1 Full Data Envelope cannot hold."""
    input_file = Path(input_path)
    if input_file.stat().st_size > MAX_V1_FILE_BYTES:
        raise DataLockError(
            DataLockErrorCode.OVERSIZED_FILE,
            "V1 Full Data Envelopes support local files up to 25 MB",
        )
    return input_file.read_bytes()


def open_file(
    keyring_path: str | Path,
    envelope_path: str | Path,
    output_path: str | Path,
    master_password: str,
) -> bytes:
    keyring = load_keyring(keyring_path)
    plaintext = decrypt_message(keyring, master_password, DataEnvelope.read(envelope_path))
    write_private_bytes(output_path, plaintext)
    return plaintext
