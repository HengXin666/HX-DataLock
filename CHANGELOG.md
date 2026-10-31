# Changelog

## Unreleased

### Security and policy

- A Keyring is documented and created as a private local file. Publishing one is opt-in, warned, and requires about 80 estimated bits. `allow-weak` cannot bypass that floor.
- Master Password checks use zxcvbn-style estimators. Weak passwords are rejected on create and rewrap unless `allow_weak` / `allowWeak` is set. Both CLIs print the score and entropy and confirm an interactive password twice.
- `lock` requires `--expect-key-id` unless `--allow-unpinned-key` is set.
- `hxdl.attestation.v1` and `hxdl.signedManifest.v2` are Ed25519 signatures. v1 envelopes are not modified. The HMAC manifest script is unchanged.

### API

- New error codes: `DATALOCK_CLOSED`, `INVALID_ARGUMENT`, `WEAK_MASTER_PASSWORD`, `INVALID_SCRYPT_PARAMS`, `UNPINNED_PUBLIC_KEY`, `TAMPERED_STREAM`, `INVALID_MANIFEST`, `INVALID_ATTESTATION`.
- A closed DataLock and a mistyped Master Password option no longer report `WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING`.
- `lockBytes` accepts `bytes`, `bytearray`, and `memoryview` in Python, and rejects strings in Node and the browser with `INVALID_ARGUMENT`.
- Node `toJSON()` returns the document object. `serialize()` returns stable JSON text. `JSON.stringify(envelope)` encodes once.
- `DataEnvelope.parse` / `inspect` read metadata without decrypting. Kotlin can parse an envelope from a string.
- Opening a v1 envelope decodes its base64 fields once. Node base64 checks use a decode-and-reencode comparison instead of a per-character loop.
- `rewrap_keyring` / `rewrapKeyring` wraps the same Read Key with a new Master Password. Existing v1 envelopes still open.
- Kotlin Sender DataLock is part of the JVM SDK. `lockText` rejects unpaired surrogates.

### Large payloads and browsers

- `hxdl.stream.v1` and `hxdl.manifest.v1` are implemented in Python and TypeScript, including a browser `ReadableStream` writer. v1 envelopes stay capped at 25 MB.
- The npm package is public. `exports` selects the browser build or the Node build. `npm run build` also writes `dist/browser.bundle.js`.
- `bench/bench_py.py` and `bench/bench_node.mjs` time small payloads with a warmup and a median.

### After merging main

- New Keyrings with scrypt `N < 2^17` fail with `INSECURE_SCRYPT_PARAMETERS` unless `allow_low_scrypt_n` / `allowLowScryptN` / `--allow-low-scrypt-n` is set. Readers still open older Keyrings down to `2^14`. Out-of-window parameters stay `INVALID_SCRYPT_PARAMS`.
- Sender creation requires a pinned key id unless `allow_unpinned_public_key` is set. CLI accepts that flag and the older `--allow-unpinned-key` alias.
- Kotlin `checkPasswordStrength` uses zxcvbn with the same score and entropy floors as Python and TypeScript.
- Kotlin `lockStream` / `openStream` speak `hxdl.stream.v1`.
- `sdk/kotlin/android` builds an API-26 AAR (`:android:assembleRelease`) from the same sources.
- TypeScript `noImplicitAny` is on. Public error and `createKeyring` passwords are typed as `string`; many internal Node crypto parameters are explicit `any`.
- No Swift SDK. This environment has no Swift toolchain, so none was stubbed in.
