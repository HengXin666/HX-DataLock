package com.hxdatalock

internal const val KEYRING_SCHEMA = "hxdl.keyring.v1"
internal const val PUBLIC_KEY_SCHEMA = "hxdl.publicKey.v1"
internal const val ENVELOPE_SCHEMA = "hxdl.envelope.v1"
internal const val DEFAULT_SCRYPT_N = 262144
internal const val DEFAULT_SCRYPT_R = 8
internal const val DEFAULT_SCRYPT_P = 1
internal const val KEY_LENGTH = 32
internal const val MIN_SCRYPT_N = 16384
internal const val MAX_SCRYPT_N = 1048576
internal const val MAX_SCRYPT_R = 16
internal const val MAX_SCRYPT_P = 4
internal const val MAX_V1_FILE_BYTES = 25 * 1024 * 1024
internal const val MAX_KEYRING_JSON_BYTES = 1024 * 1024
internal const val MAX_PUBLIC_KEY_JSON_BYTES = 64 * 1024
internal const val MAX_ENVELOPE_JSON_BYTES = 40 * 1024 * 1024

internal val ENVELOPE_ALG = linkedMapOf(
    "kem" to "X25519",
    "kdf" to "HKDF-SHA256",
    "aead" to "AES-256-GCM",
)
