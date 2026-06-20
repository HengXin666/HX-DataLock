Status: 交给代理

# Implement Python Sender DataLock using only Public Key Documents

## What to build

Implement the Python Write-only Sender path end to end. A Sender DataLock must be constructed only from a Public Key Document and must lock Payload Bytes, strict UTF-8 text, and local files into Full Data Envelopes without accepting or retaining a Keyring, Master Password, encrypted Read Key, or Read Key.

## Acceptance criteria

- [ ] Python exposes `makeSenderDataLock(publicKeyDocument)` with `lockBytes`, `lockText`, and `lockFile`.
- [ ] Sender DataLock rejects full Keyrings and invalid Public Key Documents with stable DataLock Error Codes.
- [ ] `lockBytes` creates a v1 Full Data Envelope using X25519 ephemeral sender key agreement, HKDF-SHA256, AES-256-GCM, and a single Recipient Key ID.
- [ ] Data Envelope AAD binds the envelope schema, Recipient Key ID, and declared algorithm identifiers; Creation Time is not part of AAD.
- [ ] `lockText` uses strict UTF-8 and fails invalid text input with `INVALID_UTF8` where applicable.
- [ ] `lockFile` reads and writes local files as convenience only, enforces the 25 MB v1 limit, and fails oversized inputs with `OVERSIZED_FILE`.
- [ ] Sender DataLock exposes no open operations, Read Key unwrapping, or Master Password input.

## Blocked by

- 02-python-keyring-and-public-key-document
