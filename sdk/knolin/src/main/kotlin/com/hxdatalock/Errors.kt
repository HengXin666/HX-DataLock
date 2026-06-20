package com.hxdatalock

enum class DataLockErrorCode {
    INVALID_KEYRING,
    INVALID_PUBLIC_KEY_DOCUMENT,
    WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING,
    ENVELOPE_RECIPIENT_MISMATCH,
    TAMPERED_ENVELOPE,
    UNSUPPORTED_SCHEMA,
    OVERSIZED_FILE,
    INVALID_UTF8,
    UNSUPPORTED_ALGORITHM,
}

class DataLockException(
    val code: DataLockErrorCode,
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)
