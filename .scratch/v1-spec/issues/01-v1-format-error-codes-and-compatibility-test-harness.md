Status: 已完成

# Establish v1 document formats, DataLock Error Codes, and compatibility test harness

## What to build

Create the shared v1 foundation that all language SDKs use to read, write, validate, and test Keyrings, Public Key Documents, and Data Envelopes. The slice should make stable JSON output, field-based JSON input, algorithm validation, and stable DataLock Error Codes observable through tests before feature-specific SDK work builds on it.

## Acceptance criteria

- [x] Keyring, Public Key Document, and Data Envelope writers produce UTF-8 JSON with two-space indentation, documented field order, base64 binary fields, and a trailing newline.
- [x] Readers parse JSON by field and do not require writer field order.
- [x] Stable DataLock Error Codes exist for the v1 expected failures: `INVALID_KEYRING`, `INVALID_PUBLIC_KEY_DOCUMENT`, `WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING`, `ENVELOPE_RECIPIENT_MISMATCH`, `TAMPERED_ENVELOPE`, `UNSUPPORTED_SCHEMA`, `OVERSIZED_FILE`, `INVALID_UTF8`, and `UNSUPPORTED_ALGORITHM`.
- [x] Algorithm identifiers are validated and unsupported schemas or algorithms fail with the corresponding DataLock Error Code.
- [x] Compatibility test fixtures or harness structure can express cross-language Keyring, Public Key Document, Data Envelope, and failure-mode cases without depending on one implementation's private APIs.

## Blocked by

None - can start immediately

## Comments

- Implemented in Python SDK foundation with public `DataLockError` / `DataLockErrorCode`, Public Key Document export/read support, schema and algorithm validation, algorithm-bound AAD, and v1 compatibility fixture manifest structure. Verified with `uv run pytest -q`.
