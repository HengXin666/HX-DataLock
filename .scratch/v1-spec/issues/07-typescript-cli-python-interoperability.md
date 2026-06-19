Status: 已完成

# Add TypeScript CLI and Python interoperability coverage

## What to build

Provide a TypeScript CLI path over the TypeScript SDK and prove it interoperates with the Python CLI and SDK. This slice turns the existing Node script behavior into v1 command semantics rather than a parallel legacy interface.

## Acceptance criteria

- [x] TypeScript CLI supports the v1 command set: `init`, `export-public`, `lock`, `open`, `verify-keyring`, `verify-public`, and `bench`.
- [x] TypeScript CLI `lock` accepts Public Key Documents only and refuses full Keyrings.
- [x] TypeScript CLI `open` accepts full Keyrings and explicit Master Password input for local use.
- [x] Python-created Keyrings and Public Key Documents work with TypeScript CLI lock/open flows.
- [x] TypeScript-created Keyrings and Public Key Documents work with Python CLI lock/open flows.
- [x] CLI-level tests cover wrong Master Password, tampered Data Envelope, Recipient Key ID mismatch, oversized files, invalid UTF-8, unsupported schema, and unsupported algorithm failures.
- [x] Legacy command names or README examples are either removed, redirected, or documented as non-v1 compatibility shims.

## Blocked by

- 05-v1-cli-commands-and-password-rules
- 06-typescript-full-sdk-v1
