Status: 已完成

# Return stable DataLock Error Codes for malformed v1 documents

## What was found

Malformed Data Envelopes with missing fields can leak implementation exceptions instead of stable DataLock Error Codes. Node SDK `openText` can also leak a native UTF-8 decoding error instead of `INVALID_UTF8`.

## Acceptance criteria

- [x] Python `UserDataLock.openBytes` returns `TAMPERED_ENVELOPE` for missing envelope binary fields.
- [x] Node `UserDataLock.openText` returns `INVALID_UTF8` for non-UTF-8 payload bytes.
- [x] Tests cover these failures through public SDK interfaces.
- [x] CLI failures continue to surface stable `HXDL_ERROR code=...` output.

## Evidence

- Python missing `hkdfSalt`, `nonce`, `tag`, or `ciphertext` raised `KeyError`.
- Node `openText` on payload `0xff` raised `TypeError ERR_ENCODING_INVALID_ENCODED_DATA`.

## Comments

- Fixed through TDD with public-interface tests in `tests/test_v1_foundation.py` and `tests/test_cross_language.py`. Verified with `uv run pytest -q`.
