Status: 已完成

# Complete the v1 cross-language compatibility matrix

## What to build

Turn the v1 compatibility contract into automated tests across Python, TypeScript, and Android Kotlin. The matrix should cover successful interoperation and the expected security failure modes, using stable DataLock Error Codes rather than implementation-specific exception messages.

## Acceptance criteria

- [x] TypeScript-created Keyrings can be verified and used by Python to open Data Envelopes.
- [x] Python-created Keyrings can be verified and used by TypeScript to open Data Envelopes.
- [x] TypeScript-locked Data Envelopes can be opened by Python.
- [x] Python-locked Data Envelopes can be opened by TypeScript.
- [x] Android Kotlin opens TypeScript and Python Data Envelopes.
- [x] Android Kotlin locally locked Data Envelopes can be opened by TypeScript and Python.
- [x] Public Key Documents exported by one full SDK are accepted by the other full SDK's Sender DataLock.
- [x] Wrong Master Password fails with `WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING`.
- [x] Tampered Data Envelopes fail with `TAMPERED_ENVELOPE`.
- [x] Recipient Key ID mismatch fails with `ENVELOPE_RECIPIENT_MISMATCH`.
- [x] The matrix runs in CI or has a documented local command that exercises all available language implementations.

## Blocked by

- 06-typescript-full-sdk-v1
- 07-typescript-cli-python-interoperability
- 08-android-kotlin-user-datalock-v1
