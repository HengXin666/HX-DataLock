Status: 交给代理

# Align Python Keyring creation and Public Key Document export with v1

## What to build

Implement the Python v1 setup path for local users: produce a password-wrapped X25519 Keyring from a Master Password, expose a Password Strength Report before creation, normalize the Master Password with NFC for key derivation, and export a Public Key Document that contains only the Write Key and non-secret metadata.

## Acceptance criteria

- [x] Python Keyring creation records the v1 schema, Creation Time, X25519 Write Key, encrypted Read Key, scrypt parameters actually used, AES-256-GCM wrapping metadata, and stable Write Key-derived key ID.
- [x] Master Password input is normalized with Unicode NFC and encoded as UTF-8 before scrypt derivation.
- [x] Keyring wrapping AAD binds the Keyring schema, Write Key ID, and wrapping algorithm identifiers; Creation Time is not part of AAD.
- [x] Python exposes a Password Strength Report with `level`, `allowed: true`, `warnings`, `suggestions`, and optional `estimatedEntropyBits`; weak passwords warn but do not block creation.
- [x] Python exports a Public Key Document with schema `hxdl.publicKey.v1`, Creation Time, and `publicWriteKey`, with no encrypted Read Key or Master Password-related material.
- [x] Tests cover obvious weak-password warnings, strong passphrases not treated as weak, NFC-equivalent Master Password unlock, malformed Keyrings, malformed Public Key Documents, and stable JSON output.

## Blocked by

- 01-v1-format-error-codes-and-compatibility-test-harness

## Comments

- Implemented in the Python SDK with public `check_password_strength`, NFC-normalized scrypt derivation, non-blocking weak-password Keyring creation, document-specific malformed input error codes, and coverage for the issue's setup-path behaviors. Verified with `uv run pytest -q`.
