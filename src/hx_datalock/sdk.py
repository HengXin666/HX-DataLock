from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _from_b64(value: str, field: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"Missing or invalid base64 field: {field}")
    return base64.b64decode(value, validate=True)


def _sha256_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _keyring_aad(key_id: str) -> bytes:
    return f"{KEYRING_SCHEMA}:{key_id}".encode("utf-8")


def _envelope_aad(key_id: str) -> bytes:
    return f"{ENVELOPE_SCHEMA}:{key_id}".encode("utf-8")


def _derive_password_key(master_password: str, kdf: dict[str, Any]) -> bytes:
    if kdf.get("name") != "scrypt":
        raise ValueError(f"Unsupported password KDF: {kdf.get('name')}")
    return Scrypt(
        salt=_from_b64(kdf["salt"], "encryptedReadKey.kdf.salt"),
        length=int(kdf.get("keyLength", KEY_LENGTH)),
        n=int(kdf["N"]),
        r=int(kdf["r"]),
        p=int(kdf["p"]),
    ).derive(master_password.encode("utf-8"))


def _validate_scrypt_n(value: int) -> None:
    if value < 2**14 or value & (value - 1):
        raise ValueError("scrypt_n must be a power of two and at least 16384")


@dataclass(frozen=True)
class Keyring:
    raw: dict[str, Any]

    @property
    def key_id(self) -> str:
        return self.raw["publicWriteKey"]["keyId"]

    @property
    def public_write_key(self) -> x25519.X25519PublicKey:
        public_der = _from_b64(self.raw["publicWriteKey"]["spki"], "publicWriteKey.spki")
        loaded = serialization.load_der_public_key(public_der)
        if not isinstance(loaded, x25519.X25519PublicKey):
            raise ValueError("publicWriteKey.spki is not an X25519 public key")
        return loaded

    def verify(self) -> None:
        if self.raw.get("schema") != KEYRING_SCHEMA:
            raise ValueError(f"Unsupported Keyring schema: {self.raw.get('schema')}")
        if self.raw.get("publicWriteKey", {}).get("alg") != "X25519":
            raise ValueError("Keyring must contain an X25519 Write Key")
        if self.raw.get("encryptedReadKey", {}).get("aead", {}).get("name") != "AES-256-GCM":
            raise ValueError("encryptedReadKey must use AES-256-GCM")

        public_der = _from_b64(self.raw["publicWriteKey"]["spki"], "publicWriteKey.spki")
        expected_key_id = f"x25519:{_sha256_base64url(public_der)[:22]}"
        if not secrets.compare_digest(self.key_id, expected_key_id):
            raise ValueError("keyId does not match the Write Key")
        self.public_write_key

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
            raise ValueError("Wrong master password or tampered Keyring") from exc

        loaded = serialization.load_der_private_key(private_der, password=None)
        if not isinstance(loaded, x25519.X25519PrivateKey):
            raise ValueError("Unwrapped Read Key is not an X25519 private key")
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


def create_keyring(master_password: str, *, scrypt_n: int = DEFAULT_SCRYPT_N) -> Keyring:
    if len(master_password) < 16:
        raise ValueError("Master password must be at least 16 characters")
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
            "alg": {
                "kem": "X25519",
                "kdf": "HKDF-SHA256",
                "aead": "AES-256-GCM",
            },
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
    if raw.get("schema") != ENVELOPE_SCHEMA:
        raise ValueError(f"Unsupported Data Envelope schema: {raw.get('schema')}")
    if raw.get("recipientKeyId") != keyring.key_id:
        raise ValueError("Data Envelope recipient does not match the Keyring")

    read_key = keyring.unwrap_read_key(master_password)
    loaded_public = serialization.load_der_public_key(
        _from_b64(raw["ephemeralPublicKey"], "ephemeralPublicKey")
    )
    if not isinstance(loaded_public, x25519.X25519PublicKey):
        raise ValueError("ephemeralPublicKey is not an X25519 public key")

    shared_secret = read_key.exchange(loaded_public)
    content_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=_from_b64(raw["hkdfSalt"], "hkdfSalt"),
        info=f"{ENVELOPE_SCHEMA}:{keyring.key_id}".encode("utf-8"),
    ).derive(shared_secret)
    try:
        return AESGCM(content_key).decrypt(
            _from_b64(raw["nonce"], "nonce"),
            _from_b64(raw["ciphertext"], "ciphertext") + _from_b64(raw["tag"], "tag"),
            _envelope_aad(keyring.key_id),
        )
    except InvalidTag as exc:
        raise ValueError("Ciphertext authentication failed") from exc


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
