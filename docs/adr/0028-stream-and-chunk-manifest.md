# Stream Container and Chunk Manifest

Status: accepted. v1 Full Data Envelopes stay the format from ADR 0003. This adds new schemas instead of stretching that format past 25 MB.

`hxdl.stream.v1` is a binary container: a header, then AEAD chunks. The nonce and additional data bind the chunk index and a last-chunk flag, so reordering, truncation, and appending fail authentication. The content key is unique per container. Chunk plaintext is bounded by the declared chunk size. v1 envelopes are not this format and still open as before.

`hxdl.manifest.v1` lists independent one-chunk streams for one file id. Unchanged plaintext can keep its previous sealed bytes; a new manifest version is not inside the chunk AEAD, so republishing a version does not force every chunk to be resealed. Moving a chunk to another file fails because file id and chunk index are inside that chunk's header. Manifest rollback is visible when the manifest is covered by an Ed25519 attestation or signed manifest.

Python and TypeScript expose `lockStream` / `openStream`. The browser entry exposes an async `lockStream` over `ReadableStream`. Kotlin stream helpers are not in this change.
