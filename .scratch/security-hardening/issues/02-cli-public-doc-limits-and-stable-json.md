Status: 已完成

# Align CLI Public Key Document limits and stable JSON verification

## Risk

The SDK document readers now enforce document-specific size limits, but CLI entry points are not fully aligned:

- Python CLI `lock` manually reads the public document with `Path(...).read_text()` before constructing `PublicKeyDocument`, bypassing the 64 KB Public Key Document read limit.
- Node CLI `lock` uses `readJson(...)`, but does not use the Public Key Document-specific 64 KB limit.
- Node `verify-keyring` and `verify-public` validate structure but do not enforce stable JSON in the same way as Python CLI verify commands.

This creates inconsistent behavior between SDK and CLI surfaces and leaves avoidable DoS and verification ambiguity.

## What to build

Make Python and Node CLI document handling use the same bounded readers and stable JSON policy as the SDK verification path.

## Acceptance criteria

- [x] Python CLI `lock` reads Public Key Documents through `PublicKeyDocument.read(...)` or an equivalent 64 KB-limited path.
- [x] Node CLI `lock` reads Public Key Documents through `PublicKeyDocument.read(...)` or an equivalent 64 KB-limited path.
- [x] Node CLI `verify-keyring` and `verify-public` enforce stable JSON or expose an explicit documented flag matching Python behavior.
- [x] Tests cover oversized Public Key Documents for Python CLI and Node CLI.
- [x] Tests cover non-stable Public Key Documents for Node verify behavior.

## Notes

Keep error codes stable: oversized JSON should report `OVERSIZED_FILE`; structurally invalid Public Key Documents should report `INVALID_PUBLIC_KEY_DOCUMENT` or `UNSUPPORTED_SCHEMA` as appropriate.

## Comments

- Python CLI `lock` now loads Public Key Documents with `PublicKeyDocument.read(...)`, so it uses the 64 KB Public Key Document limit.
- Node CLI `lock` now loads Public Key Documents with `PublicKeyDocument.read(...)`; Node SDK also gained stable JSON verification helpers used by `verify-keyring` and `verify-public`.
- Public Key Document verification now reports a full Keyring input as `INVALID_PUBLIC_KEY_DOCUMENT`, preserving the stable CLI error expectation while moving lock commands onto bounded readers.
- Added Python and Node CLI tests for oversized Public Key Documents, plus a Node CLI test for non-stable Public Key Document verification.
- Verification: `npm run build` passed, targeted CLI tests passed, and `uv run pytest -q` passed with 49 passed and 3 skipped.
