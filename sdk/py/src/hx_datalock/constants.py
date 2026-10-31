from __future__ import annotations

KEYRING_SCHEMA = "hxdl.keyring.v1"
ENVELOPE_SCHEMA = "hxdl.envelope.v1"
PUBLIC_KEY_SCHEMA = "hxdl.publicKey.v1"
STREAM_SCHEMA = "hxdl.stream.v1"
MANIFEST_SCHEMA = "hxdl.manifest.v1"
ATTESTATION_SCHEMA = "hxdl.attestation.v1"
SIGNED_MANIFEST_V2_SCHEMA = "hxdl.signedManifest.v2"

STREAM_MAGIC = b"HXDL"
STREAM_VERSION = 1
DEFAULT_STREAM_CHUNK_SIZE = 1024 * 1024
MIN_STREAM_CHUNK_SIZE = 1
MAX_STREAM_CHUNK_SIZE = 8 * 1024 * 1024
MAX_STREAM_HEADER_BYTES = 64 * 1024

DEFAULT_SCRYPT_N = 2**18
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
KEY_LENGTH = 32

MIN_SCRYPT_N = 2**14
# New Keyrings should use at least 2^17. 2^14 remains readable so existing
# test and historical Keyrings still open. See ADR 0026.
RECOMMENDED_MIN_SCRYPT_N = 2**17
MAX_SCRYPT_N = 2**20
MAX_SCRYPT_R = 16
MAX_SCRYPT_P = 4

# Private Keyring creation rejects zxcvbn scores below 3 and estimates below this.
PRIVATE_MIN_GUESSES_LOG10 = 14.0
# Opt-in public Keyring creation requires about 80 bits (log10(2^80)).
PUBLIC_MIN_GUESSES_LOG10 = 24.082399653118497

MAX_V1_FILE_BYTES = 25 * 1024 * 1024
MAX_KEYRING_JSON_BYTES = 1024 * 1024
MAX_PUBLIC_KEY_JSON_BYTES = 64 * 1024
MAX_ENVELOPE_JSON_BYTES = 40 * 1024 * 1024

ENVELOPE_ALG = {
    "kem": "X25519",
    "kdf": "HKDF-SHA256",
    "aead": "AES-256-GCM",
}
