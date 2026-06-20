Status: 交给代理

# Implement Python User DataLock open and local lock operations

## What to build

Implement the Python local user path end to end. A User DataLock must be constructed from a full Keyring and Master Password, unwrap and cache the Read Key for the object lifetime, open Data Envelopes back to Payload Bytes, and locally lock new Payload Bytes using the Write Key already present in the Keyring.

## Acceptance criteria

- [ ] Python exposes `makeUserDataLock(keyring, { masterPassword })` with `openBytes`, `openText`, `openFile`, `lockBytes`, `lockText`, `lockFile`, and `close`.
- [ ] The Master Password is used immediately for derivation, is not stored on SDK object fields, is not logged, and is not included in errors or generated documents.
- [ ] Wrong Master Password or tampered encrypted Read Key fails with `WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING`.
- [ ] Recipient Key ID mismatches fail with `ENVELOPE_RECIPIENT_MISMATCH`.
- [ ] Tampered Data Envelopes fail with `TAMPERED_ENVELOPE`.
- [ ] `openText` decodes strict UTF-8 and invalid UTF-8 fails with `INVALID_UTF8`.
- [ ] Local file helpers enforce the 25 MB Full Data Envelope limit and do not implement chunked or streaming APIs.
- [ ] `close()` drops references to cached key material on a best-effort managed-runtime basis, and subsequent operations fail clearly.

## Blocked by

- 02-python-keyring-and-public-key-document
- 03-python-sender-datalock-public-key-locking
