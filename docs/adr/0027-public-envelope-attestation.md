# Public Envelope Attestation

Status: accepted. Extends ADR 0022 without changing v1 Data Envelopes.

AES-GCM on a v1 Data Envelope proves the ciphertext was not edited. It does not prove who wrote it, or that it belongs at a particular path or version. The Write Key is public, so anyone can produce a decryptable envelope for a recipient.

Two additions stay outside the v1 envelope schema:

- `hxdl.attestation.v1` is an Ed25519 signature over the stable-JSON digest of an envelope, the recipient key id, and an application context string.
- `hxdl.signedManifest.v2` is an Ed25519 signature over the stable JSON of an arbitrary payload. The HMAC `hxdl.signedManifest.v1` script remains for the old prototype.

Callers must already know the signer key they trust. There is no automatic trust discovery.

The CLI `lock` command requires `--expect-key-id` unless `--allow-unpinned-key` is set. SDK sender construction still accepts a missing pin so existing callers keep working, and it warns. `require_expected_key_id` turns that warning into `UNPINNED_PUBLIC_KEY`.
