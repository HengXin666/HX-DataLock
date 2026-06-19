# Stable Cross-language Error Codes

V1 SDKs expose stable DataLock Error Codes for expected failures instead of requiring applications to parse exception text. Each language may use idiomatic exceptions or result types, but the code values are part of the public contract across TypeScript, Python, and Android Kotlin.

The initial v1 codes are `INVALID_KEYRING`, `INVALID_PUBLIC_KEY_DOCUMENT`, `WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING`, `ENVELOPE_RECIPIENT_MISMATCH`, `TAMPERED_ENVELOPE`, `UNSUPPORTED_SCHEMA`, `OVERSIZED_FILE`, `INVALID_UTF8`, and `UNSUPPORTED_ALGORITHM`. Weak Master Passwords are reported through Password Strength Reports, not error codes, because v1 allows users to continue.
