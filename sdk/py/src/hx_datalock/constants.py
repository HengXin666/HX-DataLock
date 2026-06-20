from __future__ import annotations

KEYRING_SCHEMA = "hxdl.keyring.v1"
ENVELOPE_SCHEMA = "hxdl.envelope.v1"
PUBLIC_KEY_SCHEMA = "hxdl.publicKey.v1"

DEFAULT_SCRYPT_N = 2**18
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
KEY_LENGTH = 32

ENVELOPE_ALG = {
    "kem": "X25519",
    "kdf": "HKDF-SHA256",
    "aead": "AES-256-GCM",
}

MAX_V1_FILE_BYTES = 25 * 1024 * 1024
