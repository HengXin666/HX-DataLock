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

### Not in this change

- Kotlin does not implement the stream format yet.
- There is no Android AAR and no Swift SDK.
- New Keyrings may still use scrypt `N` as low as `2^14`. The CLI warns below `2^17`. Raising the floor for newly created Keyrings is a follow-up so existing test and historical Keyrings keep opening.
