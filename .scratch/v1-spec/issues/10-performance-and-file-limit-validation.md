Status: 已完成

# Validate v1 performance scope and file-size limits

## What to build

Add v1 performance and limit validation for Full Data Envelopes. The goal is to document measured behavior for supported payload sizes and to enforce that oversized single files fail instead of accidentally becoming an unstable chunked or streaming design.

## Acceptance criteria

- [x] Benchmarks measure Keyring unlock time.
- [x] Benchmarks measure `lockBytes` and `openBytes` for 1 MB, 10 MB, and 25 MB Payload Bytes.
- [x] Benchmarks measure `lockFile` and `openFile` for 1 MB, 10 MB, and 25 MB local files.
- [x] Local File Helpers reject files larger than 25 MB with `OVERSIZED_FILE` in Python and TypeScript.
- [x] Tests or docs explicitly confirm that v1 does not support Chunked File Envelopes, streaming APIs, 100 MB, 1 GB, or 10 GB performance claims.
- [x] Benchmark output is documented enough for users to reproduce locally without implying hard performance guarantees.

## Blocked by

- 05-v1-cli-commands-and-password-rules
- 07-typescript-cli-python-interoperability
- 09-cross-language-compatibility-matrix
