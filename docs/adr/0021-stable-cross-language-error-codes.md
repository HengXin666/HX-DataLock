# Stable Cross-language Error Codes

V1 SDKs expose stable DataLock Error Codes for expected failures instead of requiring applications to parse exception text. Each language may use idiomatic exceptions or result types, but the code values are part of the public contract across TypeScript, Python, and Android Kotlin.

The initial v1 codes are `INVALID_KEYRING`, `INVALID_PUBLIC_KEY_DOCUMENT`, `WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING`, `ENVELOPE_RECIPIENT_MISMATCH`, `TAMPERED_ENVELOPE`, `UNSUPPORTED_SCHEMA`, `OVERSIZED_FILE`, `INVALID_UTF8`, and `UNSUPPORTED_ALGORITHM`.

ADR 0025 adds `WEAK_MASTER_PASSWORD`, `INSECURE_SCRYPT_PARAMETERS`, and `UNPINNED_PUBLIC_KEY`. A weak Master Password is still described by the Password Strength Report, and Keyring creation now fails with `WEAK_MASTER_PASSWORD` unless the caller opts in. Opening an existing Keyring does not use that code.
