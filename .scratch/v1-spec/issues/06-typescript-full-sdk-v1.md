Status: 已完成

# Implement TypeScript full SDK aligned with Python v1 behavior

## What to build

Build the TypeScript full SDK surface for v1 using the same domain boundaries as Python. It must create Keyrings, export Public Key Documents, expose Sender DataLock and User DataLock APIs, enforce stable DataLock Error Codes, and interoperate with Python document formats.

## Acceptance criteria

- [x] TypeScript exposes Keyring creation, Public Key Document export, Password Strength Report, `makeSenderDataLock`, and `makeUserDataLock`.
- [x] TypeScript normalizes Master Passwords with NFC before UTF-8 encoding and does not cache Master Password values.
- [x] Sender DataLock accepts only Public Key Documents and exposes only `lockBytes`, `lockText`, and `lockFile`.
- [x] User DataLock accepts full Keyring plus Master Password and exposes `openBytes`, `openText`, `openFile`, `lockBytes`, `lockText`, `lockFile`, and `close`.
- [x] TypeScript produces the same stable JSON document shapes, key IDs, AAD inputs, and algorithm identifiers as Python.
- [x] TypeScript enforces the 25 MB local file helper limit and returns stable DataLock Error Codes for v1 expected failures.
- [x] Tests prove TypeScript-created Keyrings and Data Envelopes can be verified and opened by Python, and Python-created Public Key Documents and Data Envelopes can be consumed by TypeScript.

## Blocked by

- 01-v1-format-error-codes-and-compatibility-test-harness
- 02-python-keyring-and-public-key-document
- 03-python-sender-datalock-public-key-locking
- 04-python-user-datalock-open-and-local-lock
