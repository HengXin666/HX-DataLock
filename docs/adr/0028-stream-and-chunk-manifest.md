# Stream Container and Chunk Manifest

Status: accepted. v1 Full Data Envelopes stay the format from ADR 0003. This adds new schemas instead of stretching that format past 25 MB.

`hxdl.stream.v1` is a binary container: a header, then AEAD chunks. The nonce and additional data bind the chunk index and a last-chunk flag, so reordering, truncation, and appending fail authentication. The content key is unique per container. Chunk plaintext is bounded by the declared chunk size. v1 envelopes are not this format and still open as before.

`hxdl.manifest.v1` lists independent one-chunk streams for one file id. `seal_chunked` reuses the previous sealed bytes when the plaintext hash is unchanged. The manifest version, chunk list, and total length are outside chunk AEAD, so deleting a tail chunk and shrinking the manifest is not detected by chunk authentication. Sign the manifest to detect truncation and rollback. Moving a chunk to another file fails because file id and chunk index are inside that chunk's header.

Python, TypeScript, and Kotlin expose `lockStream` / `openStream` and chunk sealing. The browser entry exposes an async `lockStream` over `ReadableStream`.
