Status: 已完成

# Implement Android Kotlin User DataLock v1 SDK

## What to build

Implement the Android Kotlin v1 client SDK for local user environments only. Kotlin must open TypeScript and Python Data Envelopes with a full Keyring plus Master Password and must locally lock Payload Bytes using the Write Key already present in the Keyring. It must not provide Sender DataLock in v1.

## Acceptance criteria

- [x] Android Kotlin minimum target is API 26+ and the SDK avoids Sender DataLock APIs.
- [x] Kotlin exposes User DataLock creation from full Keyring plus Master Password, `openBytes`, local `lockBytes`, and `close`.
- [x] Kotlin normalizes Master Passwords with NFC before UTF-8 encoding and does not cache Master Password values.
- [x] Kotlin reads Python and TypeScript v1 Keyrings and Data Envelopes by field, independent of JSON field order.
- [x] Kotlin-created Data Envelopes can be opened by Python and TypeScript.
- [x] Kotlin returns stable DataLock Error Codes for wrong Master Password or tampered Keyring, tampered Data Envelope, Recipient Key ID mismatch, unsupported schema, and unsupported algorithm.
- [x] Tests document that Kotlin does not provide Sender DataLock, Public Key Document locking, CLI, chunked files, streaming APIs, or platform Keystore integration in v1.

## Blocked by

- 01-v1-format-error-codes-and-compatibility-test-harness
- 02-python-keyring-and-public-key-document
- 03-python-sender-datalock-public-key-locking
- 04-python-user-datalock-open-and-local-lock
- 06-typescript-full-sdk-v1
