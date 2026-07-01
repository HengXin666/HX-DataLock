Status: 已完成

# Add Public Key Document keyId pinning and fingerprint confirmation

## Risk

`Public Key Document` is public but still needs authenticity. Today the SDK validates that `publicWriteKey.keyId` matches `publicWriteKey.spki`, but it cannot tell whether that Write Key is the one the user intended to trust.

If a Write-only Sender reads a replaced Public Key Document from untrusted storage, future Data Envelopes can be encrypted to an attacker's Write Key.

## What to build

Add a v1 authenticity guard that applications and CLIs can use before locking data with a Public Key Document.

## Acceptance criteria

- [x] Python CLI `lock` accepts an expected Recipient Key ID or fingerprint option and fails if the Public Key Document does not match.
- [x] Node CLI `lock` supports the same check with the same stable error behavior.
- [x] Python and Node SDKs expose a small helper or option for checking an expected Public Key Document key ID before constructing Sender DataLock.
- [x] README and SDK docs show the recommended pinning workflow for Write-only Sender environments.
- [x] Tests cover a replaced Public Key Document being rejected before encryption.

## Notes

This is not a replacement for a later signed manifest. It is the minimum v1 operational protection against key-substitution when a sender is configured with a known expected key.

## Comments

- Added Python CLI `lock --expect-key-id ...` and Node CLI `lock --expect-key-id ...`; both fail before encryption with `INVALID_PUBLIC_KEY_DOCUMENT` when the Public Key Document keyId does not match.
- Added Python `verify_public_key_document_key_id(...)` and `makeSenderDataLock(..., expected_key_id=...)`.
- Added Node `verifyPublicKeyDocumentKeyId(...)` and `makeSenderDataLock(..., { expectedKeyId })`.
- Documented the pinning workflow in the root README and Python/Node SDK READMEs.
- Added Python and Node tests proving replaced Public Key Documents are rejected before writing an envelope.
