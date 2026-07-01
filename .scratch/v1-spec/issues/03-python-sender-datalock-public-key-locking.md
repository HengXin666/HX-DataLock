Status: 已完成

# Implement Python Sender DataLock using only Public Key Documents

## What to build

Implement the Python Write-only Sender path end to end. A Sender DataLock must be constructed only from a Public Key Document and must lock Payload Bytes, strict UTF-8 text, and local files into Full Data Envelopes without accepting or retaining a Keyring, Master Password, encrypted Read Key, or Read Key.

## Acceptance criteria

- [x] Python exposes `makeSenderDataLock(publicKeyDocument)` with `lockBytes`, `lockText`, and `lockFile`.
- [x] Sender DataLock rejects full Keyrings and invalid Public Key Documents with stable DataLock Error Codes.
- [x] `lockBytes` creates a v1 Full Data Envelope using X25519 ephemeral sender key agreement, HKDF-SHA256, AES-256-GCM, and a single Recipient Key ID.
- [x] Data Envelope AAD binds the envelope schema, Recipient Key ID, and declared algorithm identifiers; Creation Time is not part of AAD.
- [x] `lockText` uses strict UTF-8 and fails invalid text input with `INVALID_UTF8` where applicable.
- [x] `lockFile` reads and writes local files as convenience only, enforces the 25 MB v1 limit, and fails oversized inputs with `OVERSIZED_FILE`.
- [x] Sender DataLock exposes no open operations, Read Key unwrapping, or Master Password input.

## Blocked by

- 02-python-keyring-and-public-key-document

## Comments

- Implemented in the Python SDK via `makeSenderDataLock(...)` and `SenderDataLock` with `lockBytes`, `lockText`, and `lockFile`.
- Full Keyrings are rejected as `INVALID_PUBLIC_KEY_DOCUMENT`; oversized file inputs report `OVERSIZED_FILE`.
- Verified by Python SDK/CLI tests and cross-language compatibility tests.
