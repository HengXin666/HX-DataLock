Status: 已完成

# Align CLI commands and Master Password input rules with v1

## What to build

Implement the v1 CLI as the user-facing path over the Python SDK. The CLI should support local Keyring creation, Public Key Document export, Write-only Sender locking, local user opening, document verification, and performance measurement while respecting the Master Password boundary.

## Acceptance criteria

- [x] CLI supports `hxdl init --keyring keyring.hxdl.json` and interactive init asks for the Master Password twice before creating a Keyring.
- [x] CLI supports explicit environment-variable password input for local automation, and SDK APIs do not read environment variables themselves.
- [x] CLI supports `export-public`, `lock`, `open`, `verify-keyring`, `verify-public`, and `bench` commands with v1 naming and arguments.
- [x] `lock` accepts only a Public Key Document and never a full Keyring.
- [x] `open` accepts a full Keyring and Master Password input and writes the opened Payload Bytes to a local file.
- [x] Verification commands validate document schema, algorithms, key IDs, and stable JSON expectations without requiring the Master Password unless unwrapping is explicitly needed.
- [x] CLI failures surface stable DataLock Error Codes in a machine-readable or consistently parseable way.
- [x] `bench` measures Keyring unlock time plus `lockBytes`, `openBytes`, `lockFile`, and `openFile` for 1 MB, 10 MB, and 25 MB Full Data Envelopes.

## Blocked by

- 02-python-keyring-and-public-key-document
- 03-python-sender-datalock-public-key-locking
- 04-python-user-datalock-open-and-local-lock

## Comments

- Implemented in the Python CLI with `init`, `export-public`, `lock`, `open`, `verify-keyring`, `verify-public`, and `bench`.
- Current CLI option names are documented in `docs/spec/v1.md` and SDK READMEs: `lock --public ...` and `verify-public --public ...`.
- Verification commands enforce stable JSON expectations without requiring the Master Password.
- Verified by `tests/py/test_cli_v1.py` and cross-language CLI compatibility tests.
