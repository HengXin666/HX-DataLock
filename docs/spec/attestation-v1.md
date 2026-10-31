# Attestation and signed manifest v2

v1 envelope additional data binds schema, recipient key id, and the algorithm names. It does not bind a storage path, a version, or a sender identity. On storage that anyone can write, a reader who only decrypts cannot tell an injected or swapped envelope from a real one.

## What the application must do

- Pin `expected_key_id` anywhere a Public Key Document is loaded from storage. The CLI requires `--expect-key-id` unless `--allow-unpinned-key` is passed.
- Keep the Keyring off that storage. See ADR 0025.
- Treat `createdAt` as unauthenticated display data.
- For objects that must be attributed, require an `hxdl.attestation.v1` whose signer key the reader already trusts, and check the context (path, version, or other location string).

## hxdl.attestation.v1

The signed message is UTF-8:

```text
hxdl.attestation.v1
{envelopeSha256}
{recipientKeyId}
{context}
```

`envelopeSha256` is unpadded base64url of SHA-256 over the stable JSON of the envelope, including its trailing newline. The signature is Ed25519 over that message. The signer public key is SPKI, and `signer.keyId` is `ed25519:` plus the first 22 characters of unpadded base64url SHA-256 of that SPKI.

## hxdl.signedManifest.v2

Ed25519 over the stable JSON of `payload`, including the trailing newline. The HMAC prototype `hxdl.signedManifest.v1` is unchanged and is not publicly verifiable.

Static-site decryption that runs in page JavaScript trusts that JavaScript with the Master Password. A browser extension or a local tool is the safer place to type the password. The browser module exists so a page or a Worker can implement the codec; it does not make the page's JavaScript a trust root.
