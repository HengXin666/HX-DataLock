# hxdl.stream.v1 and hxdl.manifest.v1

These schemas are additive. A v1 Data Envelope (`hxdl.envelope.v1`) is unchanged and is still limited to 25 MB.

## Stream container

Layout, big-endian:

1. Magic `HXDL` (4 bytes) and version `0x01` (1 byte).
2. Header length as `uint32`, then that many UTF-8 bytes of compact JSON.
3. Repeated chunks: `uint8` flag (`0` or `1` for last), `uint32` body length, then the AES-256-GCM body (ciphertext concatenated with the 16-byte tag).

Header fields, in this order: `schema` (`hxdl.stream.v1`), `recipientKeyId`, `alg` (the v1 triple), `ephemeralPublicKey` (base64 SPKI), `hkdfSalt` (base64, 32 bytes), `chunkSize`. Optional `fileId` and `chunkIndex` follow when the chunk is part of a manifest.

The content key is HKDF-SHA256 over the X25519 shared secret. HKDF info is `hxdl.stream.v1:` + recipient key id + `:` + SHA-256 of the recipient SPKI. The 12-byte nonce is the chunk index as 8 big-endian bytes, three zero bytes, and `0x01` when the chunk is last. AAD is:

```text
hxdl.stream.v1:{keyId}:X25519:HKDF-SHA256:AES-256-GCM:{chunkSize}:{index}:{0|1}:{headerSha256}
```

`headerSha256` is unpadded base64url of SHA-256 over the exact header bytes. A non-final chunk's plaintext length must equal `chunkSize`. The final chunk may be shorter, including empty. The container must end on a final chunk and must not continue after it.

`chunkSize` is an integer from 1 to 8 MiB. 1 MiB is the default. Callers that need a multi-gigabyte file should stream it; the SDK does not load the whole plaintext to seal a stream.

## Manifest

`hxdl.manifest.v1` is JSON:

- `fileId`, `version` (positive integer), `chunkSize`, `totalPlaintextLength`
- `chunks`: contiguous indexes from 0, each with `plaintextLength`, `plaintextSha256`, and `sealedSha256` (unpadded base64url)

Each sealed chunk is its own stream whose header carries the same `fileId` and `chunkIndex`. Incremental update compares plaintext hashes. Only indexes whose plaintext hash changed need a new sealed blob. The new manifest still points at the old sealed hash for unchanged chunks. Sign the manifest if a reader must reject an older version.

## Application transition

Until every reader speaks this format, an application can keep using v1 envelopes for pieces at or under 25 MB and record their hashes in its own list. New writers should prefer `hxdl.stream.v1` for anything that may grow, and `hxdl.manifest.v1` when unchanged pieces should not be uploaded again.
