# Signed Security and Compatibility Manifests

HX-DataLock v1 keeps Data Envelopes self-contained and does not change their cryptographic format for distribution metadata. Published metadata such as compatibility manifests and release security statements can be authenticated separately as signed manifest objects.

The signed object shape is:

```json
{
  "schema": "hxdl.signedManifest.v1",
  "signedAt": "2026-07-02T00:00:00.000Z",
  "issuer": "hx-datalock",
  "keyId": "manifest:<identifier>",
  "alg": "HMAC-SHA256",
  "payload": {
    "schema": "hxdl.compatibilityManifest.v1"
  },
  "signature": "<base64url signature over stable JSON payload>"
}
```

The v1 prototype signs the stable JSON serialization of `payload` with HMAC-SHA256. This is useful for CI and release rehearsal because it fixes the object shape, canonical payload bytes, and verification flow without committing the SDK API to a final public-key trust model. HMAC keys must remain release secrets and must not be stored in the repository.

The intended long-term release model is an offline signing key with a published verification key and explicit key IDs. Verification should happen in release automation, downstream packaging, and any automation that consumes a manifest from public storage. Automatic trust discovery is out of scope for v1: callers must already know which manifest `keyId` or verification key they trust.

Signed manifests complement Public Key Document pinning. Pinning protects a sender that already knows the expected recipient `keyId`; signed manifests authenticate published metadata about supported schemas, SDK compatibility, and future trusted key lists. A later key rotation design can publish old and new manifest signing key IDs in a signed transition manifest, but v1 does not rotate Keyrings, Write Keys, Read Keys, or manifest trust roots automatically.

Out of scope for v1:

- Changing Keyring, Public Key Document, or Data Envelope formats.
- Automatic trust discovery from public storage.
- Embedding manifest signatures inside Data Envelopes.
- Making manifest signing a stable SDK API.
- Secure deletion, hardware-backed keys, or platform keychain integration.

The prototype command is `scripts/hxdl-manifest-sign.py`. It signs and verifies JSON manifests using a secret supplied through an environment variable. It is intentionally a script rather than a package export until the public-key trust model is settled.
