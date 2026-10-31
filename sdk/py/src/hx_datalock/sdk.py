from __future__ import annotations

import secrets
import warnings
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
    allow_weak: bool = False,
    public_keyring: bool = False,
) -> Keyring:
    """Create a private Keyring unless ``public_keyring`` is set.

    A weak Master Password is rejected. ``allow_weak`` is an explicit override
    for tests and migration; it does not bypass the 80-bit floor required when
    ``public_keyring`` is true. The Password Strength Report is always delivered
    to ``on_password_report`` before that decision.
    """
    if not isinstance(master_password, str):
        raise DataLockError(DataLockErrorCode.INVALID_ARGUMENT, "Master Password must be a string")
    report = check_password_strength(master_password)
    if on_password_report is not None:
        on_password_report(report)
    if public_keyring:
        warnings.warn(
            "Creating a Keyring for public storage. Anyone who can read it can guess the "
            "Master Password offline. Publish a Public Key Document instead unless this is deliberate.",
            UserWarning,
            stacklevel=2,
        )
        if not report.get("allowedForPublicKeyring"):
            raise DataLockError(
                DataLockErrorCode.WEAK_MASTER_PASSWORD,
                "A public Keyring requires a Master Password of at least 80 estimated bits",
            )
    elif not report["allowed"] and not allow_weak:
        raise DataLockError(
            DataLockErrorCode.WEAK_MASTER_PASSWORD,
            "Master Password is too weak to create a Keyring; pass allow_weak to override",
        )
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


def init_keyring(
    path: str | Path,
    master_password: str,
    *,
    scrypt_n: int = DEFAULT_SCRYPT_N,
    on_password_report: Callable[[PasswordStrengthReport], None] | None = None,
    allow_weak: bool = False,
    public_keyring: bool = False,
) -> Keyring:
    keyring = create_keyring(
        master_password,
        scrypt_n=scrypt_n,
        on_password_report=on_password_report,
        allow_weak=allow_weak,
        public_keyring=public_keyring,
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
    require_expected_key_id: bool = False,
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
    elif require_expected_key_id:
        raise DataLockError(
            DataLockErrorCode.UNPINNED_PUBLIC_KEY,
            "Sender DataLock requires expected_key_id so a replaced Public Key Document is rejected",
        )
    else:
        warnings.warn(
            "Sender DataLock has no expected_key_id. A replaced Public Key Document encrypts new data "
            "to the replacement key. Pass expected_key_id, or require_expected_key_id=True.",
            UserWarning,
            stacklevel=2,
        )
    return SenderDataLock(publicKeyDocument)


def make_user_data_lock(keyring: Keyring | dict[str, Any], master_password: str) -> UserDataLock:
    """Unlock a User DataLock from a Master Password string."""
    return makeUserDataLock(keyring, master_password)


def makeUserDataLock(keyring: Keyring | dict[str, Any], options: dict[str, Any] | str) -> UserDataLock:
    if isinstance(keyring, dict):
        keyring = Keyring(keyring)
    if not isinstance(keyring, Keyring):
        raise DataLockError(DataLockErrorCode.INVALID_KEYRING, "User DataLock requires a full Keyring")
    master_password = _master_password_from_options(options)
    read_key = keyring.unwrap_read_key(master_password)
    return UserDataLock(keyring, read_key)


def _master_password_from_options(options: dict[str, Any] | str) -> str:
    if isinstance(options, str):
        return options
    if not isinstance(options, dict):
        raise DataLockError(
            DataLockErrorCode.INVALID_ARGUMENT,
            "User DataLock requires a Master Password string or {masterPassword: string}",
        )
    if "masterPassword" not in options:
        raise DataLockError(
            DataLockErrorCode.INVALID_ARGUMENT,
            "User DataLock options require masterPassword; other key names are not accepted",
        )
    unknown = sorted(key for key in options if key != "masterPassword")
    if unknown:
        raise DataLockError(
            DataLockErrorCode.INVALID_ARGUMENT,
            f"Unknown User DataLock option: {', '.join(unknown)}",
        )
    master_password = options["masterPassword"]
    if not isinstance(master_password, str):
        raise DataLockError(DataLockErrorCode.INVALID_ARGUMENT, "masterPassword must be a string")
    return master_password


def encrypt_message(keyring: Keyring, plaintext: bytes) -> DataEnvelope:
    warnings.warn(
        "encrypt_message is deprecated; use UserDataLock.lockBytes or SenderDataLock.lockBytes",
        DeprecationWarning,
        stacklevel=2,
    )
    keyring.verify()
    return DataEnvelope(lock_bytes_with_public_key_raw(keyring.key_id, keyring.public_write_key, plaintext))


def encrypt_message_for_sender(public_key_document: PublicKeyDocument, plaintext: bytes) -> DataEnvelope:
    warnings.warn(
        "encrypt_message_for_sender is deprecated; use makeSenderDataLock(...).lockBytes",
        DeprecationWarning,
        stacklevel=2,
    )
    sender = makeSenderDataLock(public_key_document)
    return sender.lockBytes(plaintext)


def decrypt_message(keyring: Keyring, master_password: str, envelope: DataEnvelope) -> bytes:
    warnings.warn(
        "decrypt_message runs scrypt on every call. Unlock once with make_user_data_lock and reuse openBytes.",
        DeprecationWarning,
        stacklevel=2,
    )
    user = makeUserDataLock(keyring, master_password)
    return user.openBytes(envelope)


def rewrap_keyring(
    keyring: Keyring | dict[str, Any],
    current_password: str,
    new_password: str,
    *,
    on_password_report: Callable[[PasswordStrengthReport], None] | None = None,
    allow_weak: bool = False,
    public_keyring: bool = False,
) -> Keyring:
    """Wrap the same Read Key under a new Master Password.

    The Recipient Key ID does not change, so existing v1 Data Envelopes still open.
    This is not key rotation: a leaked copy of the old Keyring remains guessable.
    """
    if isinstance(keyring, dict):
        keyring = Keyring(keyring)
    if not isinstance(keyring, Keyring):
        raise DataLockError(DataLockErrorCode.INVALID_KEYRING, "rewrap_keyring requires a full Keyring")
    if not isinstance(new_password, str) or not isinstance(current_password, str):
        raise DataLockError(DataLockErrorCode.INVALID_ARGUMENT, "Passwords must be strings")
    report = check_password_strength(new_password)
    if on_password_report is not None:
        on_password_report(report)
    if public_keyring and not report.get("allowedForPublicKeyring"):
        raise DataLockError(
            DataLockErrorCode.WEAK_MASTER_PASSWORD,
            "A public Keyring requires a Master Password of at least 80 estimated bits",
        )
    if not report["allowed"] and not allow_weak:
        raise DataLockError(
            DataLockErrorCode.WEAK_MASTER_PASSWORD,
            "Master Password is too weak to rewrap a Keyring; pass allow_weak to override",
        )
    private_key = keyring.unwrap_read_key(current_password)
    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    previous_kdf = keyring.raw["encryptedReadKey"]["kdf"]
    kdf = {
        "name": "scrypt",
        "salt": b64(secrets.token_bytes(32)),
        "N": previous_kdf["N"],
        "r": previous_kdf["r"],
        "p": previous_kdf["p"],
        "keyLength": KEY_LENGTH,
    }
    rewrapped = Keyring(
        {
            "schema": KEYRING_SCHEMA,
            "createdAt": keyring.raw["createdAt"],
            "publicWriteKey": dict(keyring.raw["publicWriteKey"]),
            "encryptedReadKey": seal_read_key(keyring.key_id, new_password, kdf, private_der),
        }
    )
    rewrapped.verify()
    return rewrapped


def send_file_with_public_doc(
    public_key_document_path: str | Path,
    input_path: str | Path,
    output_path: str | Path,
    *,
    expected_key_id: str | None = None,
) -> DataEnvelope:
    public_key_document = PublicKeyDocument.read(public_key_document_path)
    # lockBytes enforces the v1 limit, so the file helper inherits it here rather
    # than reading an oversized file into memory first.
    envelope = makeSenderDataLock(public_key_document, expected_key_id=expected_key_id).lockBytes(
        read_within_v1_limit(input_path)
    )
    envelope.write(output_path)
    return envelope


def send_file(keyring_path: str | Path, input_path: str | Path, output_path: str | Path) -> DataEnvelope:
    """Legacy local helper that encrypts with the Write Key from a full Keyring.

    New sender environments should use send_file_with_public_doc(...) so they never
    receive full Keyring material. This helper is kept for v1 API compatibility.
    """
    warnings.warn(
        "send_file is deprecated; use send_file_with_public_doc so senders never receive a Keyring",
        DeprecationWarning,
        stacklevel=2,
    )
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
